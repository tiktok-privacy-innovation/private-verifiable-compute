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
use anyhow::{Context, Result};
use attester::{BoxedAttester, detect_attestable_devices, detect_tee_type};
use base64::prelude::*;
use kbs_types::Tee;
use nvml_wrapper::Nvml;
use p256::ecdsa::SigningKey;
use rocket::State;
use rocket::serde::json::Json;
use std::sync::{Arc, Once};
use tokio::sync::Mutex;
use tracing::{error, info, warn};
use types::keys::encode_verifying_key;
use types::{
    ApiCode, ApiResult, AttestationEnvelope, AttestationEvidence, AttestationRequest,
    AttestationResponse, BindingMaterial, ReportData, SessionInfo,
};

const REPORT_DATA_SIZE: usize = 64;

/// Emit operator-visible diagnostics when the NVIDIA attester is silently
/// skipped. The upstream `attester::nvidia::detect_platform()` swallows NVML
/// errors (e.g. `libnvidia-ml.so` not loadable, driver missing, or the GPU
/// not being in CC mode) and just returns `false`, which makes the "empty
/// devices" failure mode invisible in pod logs. This helper probes NVML once
/// per process so the underlying reason shows up in the logs.
///
/// In sample-device mode (e.g. minikube without NVIDIA hardware) this is
/// expected; we only warn when neither a real Hopper NOR the upstream
/// `Tee::SampleDevice` fallback was picked up, since that means the request
/// will return an empty `devices` list and the demo flow will degrade.
fn warn_if_nvidia_attester_skipped(detected: &[Tee]) {
    if detected.contains(&Tee::Nvidia) || detected.contains(&Tee::SampleDevice) {
        return;
    }
    static NVIDIA_DETECT_WARNED: Once = Once::new();
    NVIDIA_DETECT_WARNED.call_once(|| match Nvml::init() {
        Ok(_) => warn!(
            "NVIDIA attester skipped: NVML initialized but no CC-enabled GPU was detected; \
             confirm the device is in CC mode and /dev/nvidia* is exposed to the pod, \
             or set ENABLE_SAMPLE_DEVICE=1 to opt into the upstream sample-device fallback"
        ),
        Err(e) => warn!(
            error = %e,
            "NVIDIA attester skipped: failed to initialize NVML; \
             ensure libnvidia-ml.so is loadable (e.g. LD_LIBRARY_PATH=/usr/local/nvidia/lib64) \
             and the NVIDIA driver is present on the host, \
             or set ENABLE_SAMPLE_DEVICE=1 to opt into the upstream sample-device fallback"
        ),
    });
}

/// Emit a one-shot operator warning whenever sample TEE attestation is in
/// effect, so the demo nature of the response is obvious in pod logs.
fn warn_if_sample_in_use(cpu_tee: Tee, device_tees: &[Tee]) {
    static SAMPLE_WARNED: Once = Once::new();
    if cpu_tee != Tee::Sample && !device_tees.contains(&Tee::SampleDevice) {
        return;
    }
    SAMPLE_WARNED.call_once(|| {
        warn!(
            cpu = ?cpu_tee,
            devices = ?device_tees,
            "Returning SAMPLE attestation evidence — not real hardware; \
             do not use in production. Disable by removing ENABLE_SAMPLE_DEVICE=1 \
             and running on real TDX/CC hardware."
        );
    });
}

async fn get_evidence(tee_type: Tee, report_data: ReportData) -> Result<AttestationEvidence> {
    Ok(AttestationEvidence {
        tee_type,
        evidence: TryInto::<BoxedAttester>::try_into(tee_type)?
            .get_evidence(report_data.to_vec())
            .await?,
    })
}

pub async fn get_tee_evidence(report_data: ReportData) -> Result<AttestationEvidence> {
    let tee_type = detect_tee_type();
    info!("Tee type {:?}", tee_type);
    get_evidence(tee_type, report_data).await
}

fn decode_report_data(nonce: &str) -> Result<ReportData, ApiCode> {
    let decoded = BASE64_STANDARD
        .decode(nonce)
        .map_err(|_| ApiCode::InvalidRequestBody)?;
    if decoded.len() != REPORT_DATA_SIZE {
        return Err(ApiCode::NonceLengthMismatch);
    }
    decoded.try_into().map_err(|_| ApiCode::NonceLengthMismatch)
}

async fn get_device_evidences(
    report_data: ReportData,
) -> Result<Vec<AttestationEvidence>, ApiCode> {
    let mut device_evidences = Vec::new();

    let detected = detect_attestable_devices();
    warn_if_nvidia_attester_skipped(&detected);

    for tee_type in &detected {
        let evidence = get_evidence(*tee_type, report_data)
            .await
            .with_context(|| format!("failed to get evidence for {tee_type:?}"))
            .map_err(|e| {
                error!(error = ?e, tee = ?tee_type, "failed to get device evidence");
                ApiCode::DeviceEvidenceFetchFailed
            })?;
        device_evidences.push(evidence);
    }

    Ok(device_evidences)
}

async fn get_attestation(report_data: ReportData) -> Result<AttestationEnvelope, ApiCode> {
    let cpu_evidence = get_tee_evidence(report_data).await.map_err(|e| {
        error!(error = %e, "failed to get tee evidence");
        ApiCode::TeeEvidenceFetchFailed
    })?;
    let device_evidences = get_device_evidences(report_data).await?;

    let device_tees: Vec<Tee> = device_evidences.iter().map(|d| d.tee_type).collect();
    warn_if_sample_in_use(cpu_evidence.tee_type, &device_tees);

    Ok(AttestationEnvelope {
        cpu: cpu_evidence,
        devices: device_evidences,
    })
}

async fn attestation_response(report_data: ReportData) -> Result<AttestationResponse, ApiCode> {
    Ok(AttestationResponse {
        attestation: get_attestation(report_data).await?,
        binding: None,
        session: None,
    })
}

async fn handshake_response(
    sessions: &Sessions,
    signing_key: &Mutex<SigningKey>,
    token: IdentityToken,
    id_pubkey: &IdPubkey,
) -> Result<AttestationResponse, ApiCode> {
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
    let handshake_verifying_key = encode_verifying_key(&signing_key);

    Ok(AttestationResponse {
        attestation: get_attestation(handshake_verifying_key).await?,
        binding: Some(BindingMaterial {
            handshake_verifying_key: BASE64_STANDARD.encode(handshake_verifying_key),
        }),
        session: Some(SessionInfo {
            id: sid.to_string(),
        }),
    })
}

#[post("/attestation", format = "json", data = "<request>")]
pub async fn attestation(request: Json<AttestationRequest>) -> ApiResult<AttestationResponse> {
    let report_data = decode_report_data(&request.nonce);
    match report_data {
        Ok(report_data) => attestation_response(report_data).await.into(),
        Err(code) => Result::<AttestationResponse, ApiCode>::Err(code).into(),
    }
}

#[post("/handshake")]
pub async fn handshake_with_attestation(
    sessions: &State<Sessions>,
    signing_key: &State<Mutex<SigningKey>>,
    token: IdentityToken,
    id_pubkey: &State<IdPubkey>,
) -> ApiResult<AttestationResponse> {
    handshake_response(
        sessions.inner(),
        signing_key.inner(),
        token,
        id_pubkey.inner(),
    )
    .await
    .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kbs_types::Tee;
    use serde_json::json;

    #[test]
    fn decode_report_data_accepts_base64_encoded_64_bytes() {
        let report_data = [7u8; REPORT_DATA_SIZE];
        let encoded = BASE64_STANDARD.encode(report_data);

        assert_eq!(decode_report_data(&encoded).unwrap(), report_data);
    }

    #[test]
    fn decode_report_data_rejects_invalid_base64() {
        assert_eq!(
            decode_report_data("not-base64").unwrap_err() as i32,
            ApiCode::InvalidRequestBody as i32
        );
    }

    #[test]
    fn decode_report_data_rejects_invalid_length() {
        let encoded = BASE64_STANDARD.encode([1u8; REPORT_DATA_SIZE - 1]);

        assert_eq!(
            decode_report_data(&encoded).unwrap_err() as i32,
            ApiCode::NonceLengthMismatch as i32
        );
    }

    #[tokio::test]
    async fn sample_attester_produces_report_data_bound_evidence() {
        // The CPU sample path in `detect_tee_type()` is the same one minikube
        // exercises when no TDX is available. Pin its behavior here so a
        // change in the upstream attester crate that breaks the demo flow
        // (e.g. changing the evidence shape) is caught by Bazel tests.
        let report_data = [11u8; REPORT_DATA_SIZE];
        let evidence = get_evidence(Tee::Sample, report_data).await.unwrap();
        assert!(matches!(evidence.tee_type, Tee::Sample));
        let report_data_field = evidence
            .evidence
            .get("report_data")
            .and_then(|v| v.as_str())
            .expect("sample attester must serialize a report_data field");
        let decoded = BASE64_STANDARD.decode(report_data_field).unwrap();
        assert_eq!(decoded, report_data.to_vec());
    }

    #[tokio::test]
    async fn sample_device_attester_is_invoked_when_env_set() {
        // SAFETY: tests run in a single shared process; clear the env at the
        // end of the test to avoid leaking state to siblings. The env var is
        // the same one upstream `attester::sample_device::detect_platform()`
        // checks for, so this asserts the contract the minikube overlay
        // relies on.
        // SAFETY: Tests in this module run sequentially via the default
        // test harness; no other test reads/writes ENABLE_SAMPLE_DEVICE.
        unsafe {
            std::env::set_var("ENABLE_SAMPLE_DEVICE", "1");
        }
        let detected = attester::detect_attestable_devices();
        // SAFETY: see above.
        unsafe {
            std::env::remove_var("ENABLE_SAMPLE_DEVICE");
        }
        assert!(
            detected.contains(&Tee::SampleDevice),
            "expected sample device fallback to be picked up via ENABLE_SAMPLE_DEVICE"
        );
    }

    #[test]
    fn attestation_envelope_keeps_cpu_and_device_evidence() {
        let response = AttestationEnvelope {
            cpu: AttestationEvidence {
                tee_type: Tee::Tdx,
                evidence: json!({"report_data": "abc"}),
            },
            devices: vec![AttestationEvidence {
                tee_type: Tee::Nvidia,
                evidence: json!({"nonce": "gpu"}),
            }],
        };

        assert_eq!(response.cpu.evidence["report_data"], "abc");
        assert_eq!(response.devices.len(), 1);
        assert_eq!(response.devices[0].evidence["nonce"], "gpu");
    }
}
