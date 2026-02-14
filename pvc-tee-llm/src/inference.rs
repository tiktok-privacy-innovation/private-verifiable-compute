// Copyright 2025 TikTok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use super::ServiceConfig;
use crate::chat::ChatCompletionHelper;
use crate::rag::VectorStores;
use crate::request::CleartextPayload;
use crate::session::Session;
use crate::session::{Sessions, Sid};
use anyhow::Result;
use bytes::Bytes;
use futures::stream::{BoxStream, StreamExt};
use openai_api_rs::v1::chat_completion::chat_completion_stream::ChatCompletionStreamRequest;
use openai_api_rs::v1::chat_completion::{Content, MessageRole};

use rocket::State;
use rocket::response::stream::ByteStream;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tracing::error;
use types::ApiCode;

fn ensure_field(obj: &mut Value, key: &str, default: String) {
    let map = obj.as_object_mut();
    if map.is_some() {
        map.unwrap()
            .entry(key.to_string())
            .or_insert(Value::String(default));
    }
}

#[post("/chat/completions", data = "<payload>")]
pub async fn chat_completions(
    sessions: &State<Sessions>,
    payload: CleartextPayload,
    sid: Sid,
    chat_completion_helper: &State<ChatCompletionHelper>,
    vector_stores: &State<VectorStores>,
    config: &State<ServiceConfig>,
) -> Result<ByteStream![Bytes], ApiCode> {
    let session = sessions
        .get(&sid)
        .await
        .map_err(|_| ApiCode::InvalidSessionId)?;
    let mut json_payload: serde_json::Value =
        serde_json::from_slice(payload.as_bytes()).map_err(|e| {
            error!("invalid json payload: {}", e);
            ApiCode::InvalidRequestBody
        })?;
    // ensure model field
    ensure_field(&mut json_payload, "model", config.llm_model.clone());

    let req: ChatCompletionStreamRequest = serde_json::from_value(json_payload).map_err(|e| {
        error!("invalid json payload for req messages: {}", e);
        ApiCode::InvalidRequestBody
    })?;

    let documents = {
        if let Some(user_prompt) = req.messages.last()
            && user_prompt.role == MessageRole::user
            && let Content::Text(txt) = user_prompt.content.clone()
        {
            let mut vector_stores = vector_stores.write().await;
            if let Some(vector_store) = vector_stores.get(&sid) {
                Some(vector_store.query_top_n(1, txt).await.unwrap_or(Vec::new()))
            } else {
                None
            }
        } else {
            None
        }
    };

    let stream = chat_completion_helper
        .stream_completion(req, documents)
        .await
        .map_err(|e| {
            error!("ERROR forwarding request to backend LLM: {}", e);
            ApiCode::TeeLlmError
        })?;

    encrypt_stream(session, stream)
        .await
        .map_err(|_| ApiCode::NoiseEncryptedFailed)
}

/// Creates an encrypted stream by encrypting each chunk of the input stream
async fn encrypt_stream(
    session: Arc<Mutex<Session>>,
    input_stream: BoxStream<'static, Bytes>,
) -> Result<ByteStream![Bytes]> {
    // Create a channel for encrypted results
    let (result_tx, result_rx) = mpsc::channel::<Bytes>(128);

    // Clone the session for the encryption task
    let enc_session = session.clone();

    // Spawn a dedicated task for encryption processing
    tokio::spawn(async move {
        let mut stream = input_stream;
        while let Some(chunk) = stream.next().await {
            let mut session_guard = enc_session.lock().await;
            match session_guard.encrypt_with_prefix_len(&chunk) {
                Ok(ct) => {
                    if result_tx.send(Bytes::from(ct)).await.is_err() {
                        error!("encrypt_stream: failed to send via pipe");
                        break;
                    }
                }
                Err(e) => {
                    error!("encrypt_stream: encryption failed {}", e);
                    break;
                }
            }
        }
    });

    // Convert the receiver into a stream
    let encrypted_stream = ReceiverStream::new(result_rx).boxed();

    Ok(ByteStream::from(encrypted_stream))
}
