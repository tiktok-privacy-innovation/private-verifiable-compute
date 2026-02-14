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

use crate::noise::IdPubkey;
use crate::request::IdentityToken;
use crate::session::{Session, Sessions};
use anyhow::Result;
use attester::{BoxedAttester, detect_tee_type};
use kbs_types::Tee;
use p256::ecdsa::SigningKey;
use rocket::State;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::error;
use types::keys::encode_verifying_key;
use types::{ApiCode, ApiResult};
use types::{AttestationResponse, ReportData};

const REPORT_DATA_SIZE: usize = 64;

pub async fn get_tee_evidence(report_data: ReportData) -> Result<(Tee, Value)> {
    let tee_type = detect_tee_type();
    info!("Tee type {:?}", tee_type);
    Ok((
        tee_type,
        TryInto::<BoxedAttester>::try_into(tee_type)?
            .get_evidence(report_data.to_vec())
            .await?,
    ))
}

#[post("/attestation", data = "<nonce>")]
pub async fn attestation(nonce: Vec<u8>) -> ApiResult<AttestationResponse> {
    let logic = async || -> Result<AttestationResponse, ApiCode> {
        if nonce.len() != REPORT_DATA_SIZE {
            return Err(ApiCode::NonceLengthMismatch);
        }
        let report_data = nonce.try_into().unwrap();
        let evidence = get_tee_evidence(report_data).await.map_err(|e| {
            error!(error = %e, "failed to get tee evidence");
            ApiCode::TeeEvidenceFetchFailed
        })?;

        let device_evidences = {
            let res = crate::gpu_attester::get_nvidia_evidence(report_data)
                .await
                .map_err(|e| {
                    error!(error = %e, "failed to get device evidence");
                    ApiCode::DeviceEvidenceFetchFailed
                })?;
            res
        };

        Ok(AttestationResponse {
            tee_type: evidence.0,
            evidence: evidence.1,
            device_evidences: device_evidences,
            sid: None,
        })
    };

    logic().await.into()
}

#[post("/handshake")]
pub async fn handshake_with_attestation(
    sessions: &State<Sessions>,
    signing_key: &State<Mutex<SigningKey>>,
    token: IdentityToken,
    id_pubkey: &State<IdPubkey>,
) -> ApiResult<AttestationResponse> {
    let logic = async || -> Result<AttestationResponse, ApiCode> {
        let pk = id_pubkey.read().await;
        token.verify(&*pk).map_err(|e| {
            error!(error=%e, "failed to verify identity token");
            ApiCode::InvalidIdentityToken
        })?;

        let session = Session::new().map_err(|e| {
            error!(error=%e, "failed to new a noise session");
            ApiCode::CreateNewSessionFailed
        })?;
        let sid = session.get_sid();
        sessions
            .insert(sid.clone(), Arc::new(Mutex::new(session)))
            .await;
        let signing_key = signing_key.lock().await;
        let pk: [u8; 64] = encode_verifying_key(&signing_key);

        let evidence = get_tee_evidence(pk).await.map_err(|e| {
            error!(error=%e, "failed to get tee evidence");
            ApiCode::TeeEvidenceFetchFailed
        })?;
        Ok(AttestationResponse {
            tee_type: evidence.0,
            evidence: evidence.1,
            device_evidences: None,
            sid: Some(sid.to_string()),
        })
    };
    logic().await.into()
}
