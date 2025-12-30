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

use crate::chat::ChatCompletionManager;
use crate::noise::{Sessions, decrypt_with_noise, encrypt_with_noise};
use crate::rag::VectorStores;
use crate::session::Sid;
use anyhow::Result;
use base64::{Engine, prelude::BASE64_STANDARD};
use rocket::State;
use rocket::http::Status;
use rocket::serde::json::Json;
use tokio::sync::Mutex;
use types::{ApiCode, ApiResponse, InferenceResp};

#[post("/", data = "<payload>")]
pub async fn inference(
    sessions: &State<Sessions>,
    payload: Vec<u8>,
    sid: Sid,
    chat_completion_mgr: &State<Mutex<ChatCompletionManager>>,
    vector_stores: &State<VectorStores>,
) -> Result<Json<ApiResponse<InferenceResp>>, Status> {
    let decoded = BASE64_STANDARD
        .decode(&payload)
        .map_err(|_| Status::BadRequest)?;

    let user_prompt: Vec<u8> = decrypt_with_noise(sessions, &sid, &decoded)
        .await
        .map_err(|_| Status::BadRequest)?;
    let user_prompt = String::from_utf8(user_prompt).map_err(|_| Status::BadRequest)?;

    let documents = {
        let mut vector_stores = vector_stores.write().await;
        if let Some(vector_store) = vector_stores.get(&sid) {
            vector_store
                .query_top_n(1, user_prompt.clone())
                .await
                .unwrap()
        } else {
            Vec::new()
        }
    };

    let mut mgr = chat_completion_mgr.lock().await;
    let llm_response = match documents.len() {
        0 => mgr.chat(&sid.to_string(), &user_prompt).await,
        _ => {
            mgr.chat_with_context(&sid.to_string(), &user_prompt, Some(&documents))
                .await
        }
    }
    .map_err(|e| {
        error!("ERROR forwarding request to OpenAI: {}", e);
        Status::InternalServerError
    })?;

    let encrypted_content = encrypt_with_noise(sessions, &sid, llm_response.as_bytes())
        .await
        .map_err(|e| {
            error!("ERROR noise protocol failed encryption: {}", e);
            Status::InternalServerError
        })?;

    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: String::new(),
        data: Some(InferenceResp {
            content: encrypted_content,
        }),
    }))
}
