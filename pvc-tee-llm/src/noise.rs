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

use crate::request::{CleartextPayload, IdentityToken};
use crate::session::{Sessions, Sid};
use anyhow::Result;
use base64::Engine;
use blind_rsa_signatures::reexports::rsa::RsaPublicKey;
use num_bigint_dig::BigUint;
use p256::ecdsa::signature::SignerMut;
use p256::ecdsa::{Signature, SigningKey};
use rocket::State;
use rocket::fairing::AdHoc;
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use tracing::{error, info};
use types::ApiResponse;
use types::keys::PublicKeyFields;
use types::{ApiCode, ApiResult, HandShakeResp, keys::ContextKey};

/// Identity server RSA public key, shared and periodically refreshed.
pub type IdPubkey = Arc<RwLock<RsaPublicKey>>;

#[post("/establish", data = "<payload>")]
pub async fn establish(
    sessions: &State<Sessions>,
    signing_key: &State<Mutex<SigningKey>>,
    id_pubkey: &State<IdPubkey>,
    payload: Vec<u8>,
    token: IdentityToken,
    sid: Sid,
) -> ApiResult<HandShakeResp> {
    let logic = async || -> Result<HandShakeResp, ApiCode> {
        let pk = id_pubkey.read().await;
        token.verify(&*pk).map_err(|e| {
            error!(error=%e, "failed to verify identity token");
            ApiCode::InvalidIdentityToken
        })?;

        match sessions.get(&sid).await {
            Ok(s) => {
                let mut s = s.lock().await;
                let resp_data = s.establish(&payload).map_err(|e| {
                    error!(error=%e, "failed to noise handshake init");
                    ApiCode::NoiseHandShakeFailed
                })?;

                // sign the noise payload
                let mut signing_key = signing_key.lock().await;
                let signature: Vec<u8> = sign_noise_script(&mut signing_key, &payload, &resp_data);
                Ok(HandShakeResp {
                    data: resp_data,
                    signature,
                })
            }
            Err(_) => Err(ApiCode::InvalidSessionId),
        }
    };

    logic().await.into()
}

#[post("/keys", data = "<context_key>")]
pub async fn upload_key(
    sessions: &State<Sessions>,
    context_key: CleartextPayload,
    sid: Sid,
) -> ApiResult<()> {
    let logic = async || -> Result<(), ApiCode> {
        let session = sessions
            .get(&sid)
            .await
            .map_err(|_| ApiCode::InvalidSessionId)?;
        let mut session = session.lock().await;
        session.set_context_key(ContextKey::new(context_key.as_bytes()));
        Ok(())
    };
    logic().await.into()
}

pub fn sign_noise_script(signing_key: &mut SigningKey, e: &[u8], ee: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(e);
    message.extend_from_slice(ee);

    let signature: Signature = signing_key.sign(&message);
    signature.to_vec()
}

/// Interval in seconds between identity server pubkey refreshes.
const PUBKEY_REFRESH_INTERVAL_SECS: u64 = 300;

async fn fetch_identity_pubkey(url: &str) -> Result<RsaPublicKey, String> {
    let client = reqwest::Client::new();
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("request failed: {}", e))?;
    let body = resp
        .bytes()
        .await
        .map_err(|e| format!("read body failed: {}", e))?;
    let api_resp: ApiResponse<PublicKeyFields> =
        serde_json::from_slice(&body).map_err(|e| format!("parse response failed: {}", e))?;
    let pubkey_fields = api_resp
        .data()
        .map_err(|e| format!("pubkey parse error: {:?}", e))?
        .ok_or("identity server pubkey data missing")?;
    let n_bytes = base64::engine::general_purpose::STANDARD
        .decode(&pubkey_fields.n)
        .map_err(|e| format!("invalid pubkey n base64: {}", e))?;
    let e_bytes = base64::engine::general_purpose::STANDARD
        .decode(&pubkey_fields.e)
        .map_err(|e| format!("invalid pubkey e base64: {}", e))?;
    let n = BigUint::from_bytes_le(&n_bytes);
    let e = BigUint::from_bytes_le(&e_bytes);
    RsaPublicKey::new(n, e).map_err(|e| format!("invalid RSA pubkey components: {}", e))
}

pub fn stage(identity_server_url: String) -> AdHoc {
    AdHoc::on_ignite("Fetch identity server RSA pubkey", |rocket| async move {
        let url = format!("{}/pubkey", identity_server_url.trim_end_matches('/'));
        let rsa_public_key = fetch_identity_pubkey(&url)
            .await
            .expect("failed to fetch identity server pubkey at startup");
        let id_pubkey: IdPubkey = Arc::new(RwLock::new(rsa_public_key));
        let id_pubkey_clone = Arc::clone(&id_pubkey);

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(std::time::Duration::from_secs(PUBKEY_REFRESH_INTERVAL_SECS));
            interval.tick().await;
            loop {
                interval.tick().await;
                match fetch_identity_pubkey(&url).await {
                    Ok(new_key) => {
                        *id_pubkey_clone.write().await = new_key;
                        info!("identity server pubkey refreshed");
                    }
                    Err(e) => {
                        error!(error=%e, "failed to refresh identity server pubkey");
                    }
                }
            }
        });

        rocket.manage(id_pubkey)
    })
}
