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

use crate::session::{Session, Sid};
use anyhow::Result;
use base64::{Engine, prelude::BASE64_STANDARD};
use p256::ecdsa::signature::SignerMut;
use p256::ecdsa::{Signature, SigningKey};
use rocket::async_trait;
use rocket::fairing::AdHoc;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{
    Request, State,
    outcome::Outcome,
    request::{self, FromRequest},
};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tracing::{error, info};
use types::keys::EncryptionKey;
use types::{ApiCode, ApiResponse, EmptyResp, HandShakeResp, new_err};
use uuid::Uuid;

pub type Sessions = Arc<RwLock<HashMap<Sid, Session>>>;
#[allow(dead_code)]
pub struct IdentityToken(String);

#[derive(Debug)]
#[allow(dead_code)]
pub enum HeaderError {
    MissingIdentityToken,
    MissingSessionId,
    InvalidSessionId,
}

impl IdentityToken {
    pub fn verify(&self) -> Result<()> {
        Ok(())
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for IdentityToken {
    type Error = HeaderError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let token = request.headers().get_one("X-Identity-Token");
        match token {
            Some(token) => {
                info!("identity token {}", token);
                Outcome::Success(IdentityToken(token.to_string()))
            }
            None => Outcome::Error((Status::Unauthorized, Self::Error::MissingIdentityToken)),
        }
    }
}

#[async_trait]
impl<'r> FromRequest<'r> for Sid {
    type Error = HeaderError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let sid = request.headers().get_one("X-Session-Id");
        match sid {
            Some(s) => Uuid::parse_str(s).map_or_else(
                |_e| Outcome::Error((Status::BadRequest, Self::Error::MissingSessionId)),
                |uuid| Outcome::Success(Sid::new(uuid)),
            ),
            None => Outcome::Error((Status::BadRequest, Self::Error::MissingSessionId)),
        }
    }
}

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Noise Server", |rocket| async {
        rocket.manage(Sessions::default())
    })
}

#[post("/noise", data = "<payload>")]
pub async fn handshake(
    sessions: &State<Sessions>,
    signing_key: &State<Mutex<SigningKey>>,
    payload: Vec<u8>,
    token: IdentityToken,
    sid: Sid,
) -> Result<Json<ApiResponse<HandShakeResp>>, Status> {
    // verify identity token
    token.verify().map_err(|e| {
        error!(error=%e);
        Status::Unauthorized
    })?;

    let decoded_payload = BASE64_STANDARD.decode(&payload).map_err(|e| {
        error!(error=%e);
        Status::BadRequest
    })?;

    let mut session_lock = sessions.write().await;

    match session_lock.remove(&sid) {
        Some(s) => {
            let (session, resp_data) = s.handshake(&decoded_payload).map_err(|e| {
                error!(error=%e, "failed to noise handshake init");
                Status::InternalServerError
            })?;
            session_lock.insert(sid.clone(), session);

            // sign the noise payload
            let mut signing_key = signing_key.lock().await;
            let signature: Vec<u8> =
                sign_noise_script(&mut signing_key, &decoded_payload, &resp_data);
            Ok(Json(ApiResponse {
                code: ApiCode::Success as i32,
                message: String::new(),
                data: Some(HandShakeResp {
                    data: resp_data,
                    signature,
                }),
            }))
        }
        None => {
            error!("failed to found session, sid = {}", sid.to_string());
            Err(Status::BadRequest)
        }
    }
}

#[post("/key/upload", data = "<payload>")]
pub async fn upload_key(
    sessions: &State<Sessions>,
    payload: Vec<u8>,
    sid: Sid,
) -> Result<Json<ApiResponse<EmptyResp>>, Json<ApiResponse<()>>> {
    let decoded_payload = BASE64_STANDARD
        .decode(&payload)
        .map_err(|_| Json(new_err(ApiCode::BadRequest, "data is not base64 encoded")))?;

    let encryption_key = decrypt_with_noise(sessions, &sid, &decoded_payload)
        .await
        .map_err(|_| {
            Json(new_err(
                ApiCode::BadRequest,
                "failed to decrypt encryption key",
            ))
        })?;

    let mut sessions = sessions.write().await;
    if let Some(s) = sessions.get_mut(&sid) {
        s.set_encryption_key(EncryptionKey::new(&encryption_key));
    }

    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: String::new(),
        data: Some(EmptyResp {}),
    }))
}

pub fn sign_noise_script(signing_key: &mut SigningKey, e: &[u8], ee: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(e);
    message.extend_from_slice(ee);

    let signature: Signature = signing_key.sign(&message);
    signature.to_vec()
}

pub async fn decrypt_with_noise(
    sessions: &State<Sessions>,
    sid: &Sid,
    ciphertext: &[u8],
) -> Result<Vec<u8>, Status> {
    match sessions.write().await.get_mut(sid) {
        Some(s) => s.decrypt(ciphertext).map_err(|_| {
            error!("failed to decrypt ciphertext, sid = {}", sid.to_string());
            Status::InternalServerError
        }),
        None => {
            error!("failed to found session, sid = {}", sid.to_string());
            Err(Status::BadRequest)
        }
    }
}

pub async fn encrypt_with_noise(
    sessions: &State<Sessions>,
    sid: &Sid,
    plaintext: &[u8],
) -> Result<Vec<u8>, Status> {
    match sessions.write().await.get_mut(sid) {
        Some(s) => s.encrypt(plaintext).map_err(|_| {
            error!("failed to encrypt, sid = {}", sid.to_string());
            Status::InternalServerError
        }),
        None => {
            error!("failed to found session, sid = {}", sid.to_string());
            Err(Status::BadRequest)
        }
    }
}
