// Copyright 2025 TikTok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use crate::client::PvcClient;
use rocket::State;
use rocket::fs::NamedFile;
use rocket::http::Status;
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use types::{ApiCode, ApiResponse, keys::ContextKey};

#[derive(Debug, Serialize, Deserialize)]
pub struct AuthConfig {
    pub enabled: bool,
    #[serde(rename = "clientID")]
    pub client_id: String,
    pub loggedin: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct OauthLoginRequest {
    #[serde(rename = "idToken")]
    pub id_token: String,
}

#[get("/auth/google/callback")]
pub async fn google_oauth_callback() -> Option<NamedFile> {
    info!("google oauth callback");
    NamedFile::open(Path::new("static/index.html")).await.ok()
}

#[get("/auth/config")]
pub async fn auth_config(
    oauth_token: &State<Arc<RwLock<Option<String>>>>,
) -> Result<Json<ApiResponse<AuthConfig>>, Status> {
    match oauth::get_oauth_type() {
        oauth::OauthType::Google => Ok(Json(ApiResponse {
            code: ApiCode::Success as i32,
            message: String::new(),
            data: Some(AuthConfig {
                enabled: true,
                client_id: std::env::var("GOOGLE_OAUTH_CLIENT_ID").map_err(|_| {
                    error!("google oauth enabled but client id is not set");
                    Status::InternalServerError
                })?,
                loggedin: oauth_token.read().await.is_some(),
            }),
        })),
        oauth::OauthType::Disable => Ok(Json(ApiResponse {
            code: ApiCode::Success as i32,
            message: String::new(),
            data: Some(AuthConfig {
                enabled: false,
                client_id: String::new(),
                loggedin: true,
            }),
        })),
    }
}

#[post("/auth/login", data = "<payload>")]
pub async fn login_with_oauth_token(
    oauth_token: &State<Arc<RwLock<Option<String>>>>,
    client: &State<Arc<RwLock<PvcClient>>>,
    payload: String,
    key: &State<ContextKey>,
) -> Result<Json<ApiResponse<()>>, Status> {
    let req: OauthLoginRequest = serde_json::from_str(&payload).map_err(|_| Status::BadRequest)?;

    let mut token = oauth_token.write().await;
    *token = Some(req.id_token.clone());

    // start noise handshake and tee attestation
    let mut pvc_client = client.write().await;

    pvc_client
        .handshake_with_attestation(Some(req.id_token))
        .await
        .map_err(|e| {
            error!("failed to handshake with backend tee {e}");
            Status::InternalServerError
        })?;

    pvc_client.upload_encryption_key(key).await.map_err(|e| {
        error!("failed to upload encryption key {e}");
        Status::InternalServerError
    })?;

    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: String::new(),
        data: None,
    }))
}
