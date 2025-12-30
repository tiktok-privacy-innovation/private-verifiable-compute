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

use crate::noise::{IdentityToken, Sessions};
use crate::session::Session;
use anyhow::Result;
#[cfg(feature = "attestation")]
use attester::{BoxedAttester, detect_tee_type};
use base64::{Engine, prelude::BASE64_STANDARD};
use kbs_types::Tee;
use p256::ecdsa::SigningKey;
use rocket::State;
use rocket::serde::json::Json;
use serde_json::Value;
#[cfg(not(feature = "attestation"))]
use serde_json::json;
use tokio::sync::Mutex;
use tracing::error;
use types::keys::encode_verifying_key;
use types::{ApiCode, ApiResponse, new_err};
use types::{AttestationResponse, ReportData};

const REPORT_DATA_SIZE: usize = 64;

pub async fn get_tee_evidence(report_data: ReportData) -> Result<(Tee, Value)> {
    #[cfg(feature = "attestation")]
    let (tee_type, evidence) = {
        let tee_type = detect_tee_type();
        info!("Tee type {:?}", tee_type);
        (
            tee_type,
            TryInto::<BoxedAttester>::try_into(tee_type)?
                .get_evidence(report_data.to_vec())
                .await?,
        )
    };

    #[cfg(not(feature = "attestation"))]
    let (tee_type, evidence) = (
        Tee::Sample,
        json!({"report_data": hex::encode(report_data)}),
    );

    Ok((tee_type, evidence))
}

#[post("/nonce", data = "<payload>")]
pub async fn attestation_with_nonce(
    payload: Vec<u8>,
) -> Result<Json<ApiResponse<AttestationResponse>>, ApiResponse<()>> {
    info!("received body {}", String::from_utf8_lossy(&payload));
    let decoded_nonce = BASE64_STANDARD.decode(&payload).map_err(|e| {
        new_err(
            ApiCode::BadRequest,
            format!("Invalid Base64 payload: {}", e),
        )
    })?;

    if decoded_nonce.len() != REPORT_DATA_SIZE {
        return Err(new_err(
            ApiCode::BadRequest,
            format!(
                "Invalid nonce length: expected {}, got {}",
                REPORT_DATA_SIZE,
                decoded_nonce.len()
            ),
        ));
    }

    let report_data = decoded_nonce.try_into().unwrap();
    let evidence = get_tee_evidence(report_data).await.map_err(|e| {
        error!(error = %e, "failed to get tee evidence");
        new_err(
            ApiCode::InternalServerError,
            format!("failed to generate tee evidence: {}", e),
        )
    })?;

    let device_evidences = {
        #[cfg(feature = "attestation")]
        let res = crate::gpu_attester::get_nvidia_evidence(report_data)
            .await
            .map_err(|e| {
                error!(error = %e, "failed to get device evidence");
                new_err(
                    ApiCode::InternalServerError,
                    format!("failed to generate device evidence: {}", e),
                )
            })?;

        #[cfg(not(feature = "attestation"))]
        let res = None;

        res
    };

    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: String::new(),
        data: Some(AttestationResponse {
            tee_type: evidence.0,
            evidence: evidence.1,
            device_evidences: device_evidences,
            sid: None,
        }),
    }))
}

#[post("/")]
pub async fn attestation(
    sessions: &State<Sessions>,
    signing_key: &State<Mutex<SigningKey>>,
    _token: IdentityToken,
) -> Result<Json<ApiResponse<AttestationResponse>>, ApiResponse<()>> {
    let session = Session::new().map_err(|e| {
        error!(error=%e, "failed to new a noise session");
        new_err(
            ApiCode::BadRequest,
            format!("failed to new a noise session: {}", e),
        )
    })?;
    let sid = session.get_sid();
    {
        let mut sessions_lock = sessions.write().await;
        sessions_lock.insert(sid.clone(), session);
    }

    // generate a signing key pair
    let signing_key = signing_key.lock().await;
    let pk: [u8; 64] = encode_verifying_key(&signing_key);

    let evidence = get_tee_evidence(pk).await.map_err(|e| {
        error!(error=%e, "failed to get tee evidence");
        new_err(
            ApiCode::InternalServerError,
            format!("failed to generate tee evidence: {}", e),
        )
    })?;

    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: String::new(),
        data: Some(AttestationResponse {
            tee_type: evidence.0,
            evidence: evidence.1,
            device_evidences: None,
            sid: Some(sid.to_string()),
        }),
    }))
}
