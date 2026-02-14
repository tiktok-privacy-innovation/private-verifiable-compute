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

use crate::rag::Document;
use anyhow::Result;
use bytes::Bytes;
use futures::StreamExt;
use futures::stream::BoxStream;
use handlebars::Handlebars;
use openai_api_rs::v1::chat_completion;
use openai_api_rs::v1::chat_completion::chat_completion_stream::ChatCompletionStreamRequest;
use reqwest;
use rocket::fairing::AdHoc;
use serde_json;
use tracing::error;

const CHAT_TEMPLATE_DOCUMENTS: &str = r#"
# Reference Documents for the users.
{{#each documents}}
{{content}}
{{/each}}
"#;

pub struct ChatCompletionHelper {
    http_client: reqwest::Client,
    max_tokens: usize,
    system_prompt: String,
    chat_completion_path: String,
    default_model: String,
}

pub fn stage(
    system_prompt_file: &str,
    max_token: usize,
    llm_endpoint: &str,
    llm_model: &str,
) -> AdHoc {
    let system_prompt_str = std::fs::read_to_string(system_prompt_file)
        .or_else(|e| {
            error!("failed to read system prompt from file {}", e);
            Ok::<String, ()>(String::new())
        })
        .unwrap();

    let m =
        ChatCompletionHelper::new(&system_prompt_str, max_token, llm_endpoint, llm_model).unwrap();
    AdHoc::on_ignite("Init Cache", |rocket| async { rocket.manage(m) })
}

#[allow(dead_code)]
impl ChatCompletionHelper {
    pub fn new(
        system_prompt: &str,
        max_tokens: usize,
        llm_endpoint: &str,
        llm_model: &str,
    ) -> Result<Self> {
        let http_client = reqwest::Client::builder().build()?;

        Ok(Self {
            http_client: http_client,
            max_tokens,
            system_prompt: system_prompt.to_string(),
            chat_completion_path: format!("{}/chat/completions", llm_endpoint),
            default_model: llm_model.to_string(),
        })
    }

    pub async fn stream_completion(
        &self,
        req: ChatCompletionStreamRequest,
        rag: Option<Vec<Document>>,
    ) -> Result<BoxStream<'static, Bytes>> {
        let chat_completion_path = self.chat_completion_path.clone();
        let llm_model = self.default_model.clone();
        let system_prompt = self.system_prompt.clone();
        let max_tokens = self.max_tokens;
        let http_client = self.http_client.clone();

        let mut req = req;
        req = req.max_tokens(max_tokens as i64);
        req = req.n(1);
        if req.model.is_empty() {
            req.model = llm_model;
        }

        req.messages.push(chat_completion::ChatCompletionMessage {
            role: chat_completion::MessageRole::system,
            content: chat_completion::Content::Text(system_prompt),
            name: None,
            tool_calls: None,
            tool_call_id: None,
        });

        if let Some(rag) = rag {
            let handlebars = Handlebars::new();
            let h = handlebars.render_template(
                CHAT_TEMPLATE_DOCUMENTS,
                &serde_json::json!({"documents": rag}),
            )?;
            warn!("rag doc {}", h);
            req.messages.push(chat_completion::ChatCompletionMessage {
                role: chat_completion::MessageRole::system,
                content: chat_completion::Content::Text(h),
                name: None,
                tool_calls: None,
                tool_call_id: None,
            });
        };

        let mut payload = serde_json::to_value(req)?;
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("stream".into(), serde_json::Value::Bool(true));
        }

        let request = http_client.post(chat_completion_path).json(&payload);

        let response = request.send().await?;

        let stream = response.bytes_stream().filter_map(|result| async move {
            match result {
                Ok(bytes) => Some(bytes),
                Err(_) => None, // Filter out connection errors from stream
            }
        });
        Ok(stream.boxed())
    }
}
