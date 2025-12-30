// Copyright 2025 Tiktok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::cache::MemBasedCache;
use crate::cache_redis::RedisCache;

use super::cache::Cache;
use super::rag::Document;
use chrono::Utc;
use handlebars::Handlebars;
use openai_api_rs::v1::api::OpenAIClient as LlmClient;
use openai_api_rs::v1::chat_completion;
use openai_api_rs::v1::chat_completion::chat_completion::ChatCompletionRequest;
use rocket::fairing::AdHoc;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_json::json;
use tokio::sync::Mutex;
use types::utils::get_env_or_default_value;
use uuid::Uuid;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChatCompletitionError {
    #[error("Redis failed: {0}")]
    Redis(#[from] redis::RedisError),
    #[error("JSON serialization/deserialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("Model response parsing failed")]
    ModelResponse(String),
    #[error("rendering template")]
    Render,
    #[error("connection")]
    Connection,
    #[error("internal")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, ChatCompletitionError>;

const CHAT_TEMPLATE_DOCUMENTS: &str = r#"
# Documents
{{#each documents}}
{{content}}
{{/each}}
"#;

const CHAT_TEMPLATE_HISTORY: &str = r#"
# History
{{#each history}}
<message role="user">
{{user_content}}
</message>
<message role="assistant">
{{assistant_content}}
</message>
{{/each}}
"#;

const CHAT_TEMPLATE: &str = r#"
# User inputs
{{input}}
"#;

const SUMMARY_PROMPT: &str = r#"
You are a professional chat summarizer with expertise in technical and business communication. Please summarize the following LLM chat history based on the requirements below:

### Core Requirements:
1. **Structure Clarity**: Organize the summary into 4 mandatory sections + 1 optional section (if applicable):
   - **Core Topics**: List 2-5 key discussion themes (e.g., "LLM prompt engineering for risk scoring", "database optimization for URL risk analysis").
   - **Key Conclusions/Decisions**: Highlight confirmed agreements, technical solutions, or business decisions (e.g., "Adopt few-shot learning for risky URL classification", "Use Redis cache to reduce DB query latency").
   - **Action Items**: Include assignees (if mentioned), deadlines (if specified), and specific tasks (e.g., "Developer A: Test prompt variants for risk scoring by 2024-XX-XX", "Research team: Validate LLM output accuracy with 10k URL samples").
   - **Unresolved Issues**: Note open questions or pending discussions (e.g., "Need to confirm LLM model selection (GPT-4 vs. Claude 3) for real-time processing", "Unclear how to handle false positives in risk scoring").
   - **Optional (Technical Scenarios)**: Add technical details if relevant (e.g., "API latency target: <200ms", "Data sources: Public URL blacklists + internal threat intelligence").

2. **Precision**:
   - Use technical terms consistently (e.g., "risk scoring", "cache invalidation", "LLM fine-tuning") as used in the chat.
   - Avoid adding irrelevant information or assumptions not mentioned in the conversation.
   - Preserve numerical values, deadlines, and key metrics (e.g., "85% accuracy target", "3-day implementation window").

3. **Conciseness**:
   - Keep each section concise (1-3 bullet points per item where possible).
   - Total summary length: 150-300 words (adjust based on chat length; longer chats can be up to 500 words).

4. **Readability**:
   - Use bullet points and emojis (as above) for scannability.
   - Use active voice (e.g., "Team agreed to..." instead of "It was agreed that...").

Please generate the summary strictly following the above structure and requirements.

### Chat History to Summarize:
"#;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub msg_id: String,
    pub user_content: String,
    pub assistant_content: String,
    pub timestamp: i64,
}

pub struct ChatCompletionManager {
    llm_client: LlmClient,
    max_chats: usize,

    cache: Box<dyn Cache>,
    endpoint_model: String,
    max_tokens: usize,
    system_prompt: String,
}

pub fn stage(
    redis_endpoint: &str,
    system_prompt_file: &str,
    max_token: Option<usize>,
    llm_model: Option<&str>,
    llm_endpoint: Option<&str>,
) -> AdHoc {
    let redis = RedisCache::new(redis_endpoint, /*ttl_seconds*/ 60 * 10);
    let cache: Box<dyn Cache> = match redis {
        Ok(redis_cache) => {
            log::info!("create redis cache");
            Box::new(redis_cache)
        }
        Err(_) => {
            log::info!("create in-mem cache");
            Box::new(MemBasedCache::new())
        }
    };

    let system_prompt_str = std::fs::read_to_string(system_prompt_file)
        .or_else(|e| {
            error!("failed to read system prompt from file {}", e);
            Ok::<String, ()>(String::new())
        })
        .unwrap();

    let m = Mutex::new(
        ChatCompletionManager::new_with_config(
            cache,
            &system_prompt_str,
            max_token,
            llm_model,
            llm_endpoint,
        )
        .unwrap(),
    );
    AdHoc::on_ignite("Init Cache", |rocket| async { rocket.manage(m) })
}

#[allow(dead_code)]
impl ChatCompletionManager {
    pub fn new_with_config(
        cache: Box<dyn Cache>,
        system_prompt: &str,
        max_tokens: Option<usize>,
        model: Option<&str>,
        llm_endpoint: Option<&str>,
    ) -> Result<Self> {
        let default_mt = max_tokens.unwrap_or_default();
        let max_tokens = get_env_or_default_value("LLM_MAX_TOKEN", default_mt);
        let default_model = model.map(|s| s.to_string()).unwrap_or_default();
        let model = get_env_or_default_value("LLM_MODEL", default_model);
        let default_endpoint = llm_endpoint.map(|s| s.to_string()).unwrap_or_default();
        let endpoint = get_env_or_default_value("LLM_ENDPOINT", default_endpoint);

        let llm_client = LlmClient::builder()
            .with_endpoint(endpoint)
            .build()
            .map_err(|_| ChatCompletitionError::Connection)?;

        Ok(Self {
            cache,
            max_chats: 20,
            llm_client,
            endpoint_model: model,
            max_tokens,
            system_prompt: system_prompt.to_string(),
        })
    }

    pub fn new(cache: Box<dyn Cache>, max_tokens: usize, system_prompt: &str) -> Result<Self> {
        ChatCompletionManager::new_with_config(cache, system_prompt, Some(max_tokens), None, None)
    }

    fn get_from_cache(&self, key: &str) -> Result<Vec<Message>> {
        let msg_val: Option<Vec<String>> = self.cache.lrange(key);
        if let Some(_msg_val) = msg_val {
            let messages: Vec<Message> = _msg_val
                .iter()
                .map(|s| serde_json::from_str(s).unwrap())
                .collect();
            return Ok(messages);
        }

        Ok(Vec::new())
    }

    fn add_to_cache(&self, key: &str, value: &str) -> Result<()> {
        self.cache.rpush(key, value);
        Ok(())
    }

    fn reset_cache(&self, key: &str, value: &str) -> Result<()> {
        self.cache.reset_key(key, value);
        Ok(())
    }

    fn get_cache_size(&self, key: &str) -> Option<usize> {
        Some(self.cache.llen(key))
    }

    pub fn get_context(&self, session_id: &str) -> Result<Vec<Message>> {
        let msg_key = format!("session:{}:messages", session_id);
        self.get_from_cache(&msg_key)
    }

    async fn append_one_chat(
        &mut self,
        session_id: &str,
        user: &str,
        assistant: &str,
    ) -> Result<()> {
        let key = format!("session:{}:messages", session_id);

        if let Some(chat_size) = self.get_cache_size(&key)
            && chat_size >= self.max_chats
        {
            // call LLM to summeraize
            if let Ok(response) = self.summeraize_history(session_id).await {
                let message = Message {
                    msg_id: Uuid::new_v4().to_string(),
                    user_content: "the summeraized history".to_string(),
                    assistant_content: response,
                    timestamp: Utc::now().timestamp_millis(),
                };
                let value = serde_json::to_string(&message)?;
                let _: () = self.reset_cache(&key, &value)?;
            }
        }

        let message = Message {
            msg_id: Uuid::new_v4().to_string(),
            user_content: user.to_string(),
            assistant_content: assistant.to_string(),
            timestamp: Utc::now().timestamp_millis(),
        };

        let value = serde_json::to_string(&message)?;

        self.add_to_cache(&key, &value)
    }

    fn configure_request(&self) -> ChatCompletionRequest {
        let mut req = ChatCompletionRequest::new(self.endpoint_model.clone(), vec![]);
        req = req.temperature(0.8);
        req = req.top_p(0.7);
        req = req.max_tokens(self.max_tokens as i64);
        req = req.n(1);
        req
    }

    pub async fn chat_with_context(
        &mut self,
        sid: &str,
        prompt: &str,
        documents: Option<&[Document]>,
    ) -> Result<String> {
        let mut req = self.configure_request();
        let messages = &mut req.messages;

        messages.push(chat_completion::ChatCompletionMessage {
            role: chat_completion::MessageRole::system,
            content: chat_completion::Content::Text(self.system_prompt.clone()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        });

        let h = self.get_context(sid)?;
        let history: Vec<JsonValue> = h
                    .iter()
                    .map(|m| json!({"user_content": m.user_content, "assistant_content": m.assistant_content}))
                    .collect();

        let mut chat_prompt = String::new();
        let handlebars = Handlebars::new();

        if let Some(documents) = documents {
            let h = handlebars
                .render_template(CHAT_TEMPLATE_DOCUMENTS, &json!({"documents": documents}))
                .map_err(|_| ChatCompletitionError::Render)?;
            log::debug!("Documents rendered {}", h);
            chat_prompt = chat_prompt + &h;
        }

        chat_prompt = chat_prompt
            + &handlebars
                .render_template(CHAT_TEMPLATE, &json!({"input": prompt}))
                .map_err(|_| ChatCompletitionError::Render)?;

        if !history.is_empty() {
            let h = handlebars
                .render_template(CHAT_TEMPLATE_HISTORY, &json!({"history": history}))
                .map_err(|_| ChatCompletitionError::Render)?;
            chat_prompt = chat_prompt + &h;
        }

        messages.push(chat_completion::ChatCompletionMessage {
            role: chat_completion::MessageRole::user,
            content: chat_completion::Content::Text(chat_prompt),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        });

        let result = self
            .llm_client
            .chat_completion(req)
            .await
            .map_err(|_e| ChatCompletitionError::ModelResponse(_e.to_string()))?;

        let response = result
            .choices
            .first()
            .and_then(|choice| choice.message.content.clone())
            .ok_or(ChatCompletitionError::Internal(
                "get chat result".to_string(),
            ))?;

        let response = self.trim_think(&response);
        self.append_one_chat(sid, prompt, &response).await?;
        Ok(response)
    }

    pub async fn chat(&mut self, sid: &str, prompt: &str) -> Result<String> {
        self.chat_with_context(sid, prompt, None).await
    }

    async fn summeraize_history(&mut self, sid: &str) -> Result<String> {
        let h = self.get_context(sid)?;
        if h.is_empty() {
            return Err(ChatCompletitionError::Internal(
                "history is empty".to_string(),
            ));
        }

        let history: Vec<JsonValue> = h
                .iter()
                .map(|m| json!({"user_content": m.user_content, "assistant_content": m.assistant_content}))
                .collect();

        let handlebars = Handlebars::new();
        let chat_prompt = handlebars
            .render_template(CHAT_TEMPLATE_HISTORY, &json!({"history": history}))
            .map_err(|_| ChatCompletitionError::Render)?;

        let mut req = self.configure_request();
        let messages = &mut req.messages;

        messages.push(chat_completion::ChatCompletionMessage {
            role: chat_completion::MessageRole::system,
            content: chat_completion::Content::Text(SUMMARY_PROMPT.to_string()),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        });

        messages.push(chat_completion::ChatCompletionMessage {
            role: chat_completion::MessageRole::user,
            content: chat_completion::Content::Text(chat_prompt),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        });

        let result = self
            .llm_client
            .chat_completion(req)
            .await
            .map_err(|_e| ChatCompletitionError::ModelResponse(_e.to_string()))?;

        let response = result
            .choices
            .first()
            .and_then(|choice| choice.message.content.clone())
            .ok_or(ChatCompletitionError::Internal(
                "get chat result".to_string(),
            ))?;

        let response = self.trim_think(&response);
        Ok(response)
    }

    fn trim_think(&self, s: &str) -> String {
        match s.find("</think>") {
            Some(end_pos) => match s[..end_pos].find("<think>") {
                Some(start_pos) => {
                    let before_think = &s[..start_pos];
                    let after_think = &s[end_pos + "</think>".len()..];

                    let mut result = String::with_capacity(before_think.len() + after_think.len());
                    result.push_str(before_think);
                    result.push_str(after_think);
                    result
                }
                _ => s[(end_pos + "</think>".len())..].to_string(),
            },
            None => s.to_string(),
        }
    }
}
