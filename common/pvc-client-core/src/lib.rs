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

use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use base64::prelude::*;
use blind_rsa::BlindPublicKey;
use blind_rsa::blinder::RsaBlinder;
use bytes::Bytes;
use futures::TryStreamExt;
use futures::stream::Stream;
use futures::stream::StreamExt;
use identity::IdentityClient;
#[cfg(feature = "attestation")]
use kbs_types::Tee;
use noise::{NoiseNnInitiator, NoiseNnTransport};
use ohttp_wrap::{ClientRequest, KeyConfig, Message, Mode, OhttpClient};
use p256::ecdsa::{Signature, signature::Verifier};
use rand_core::{OsRng, RngCore};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs;
use std::io::ErrorKind;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio_util::codec::LengthDelimitedCodec;
use tokio_util::io::StreamReader;
use tracing::{error, info, warn};
use types::{
    ApiCode, ApiError, ApiResponse, AttestationResponse, HandShakeResp, ReportData,
    UploadDocumentReq,
    async_rw::{self},
    http::{
        HttpClient,
        reqwest::{
            IntoUrl, Url,
            header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue},
        },
    },
    keys::{
        BlindMessageRequest, BlindMessageResponse, ContextKey, PublicKeyFields,
        decode_verifying_key,
    },
};

#[cfg(feature = "attestation")]
use verifier::{InitDataHash, ReportData as TeeReportData, VerifierConfig, to_verifier};

use futures::{AsyncReadExt, AsyncWriteExt};

struct VerifiedHandshake {
    handshake_verifying_key: [u8; 64],
    session_id: Option<String>,
    claims: Claim,
}

const ESTABLISH_PATH: &str = "/v1/establish";
const CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
const HANDSHAKE_WITH_ATTESTATION_PATH: &str = "/v1/handshake";
const ATTESTATION_PATH: &str = "/v1/attestation";
const UPLOAD_KEY_PATH: &str = "/v1/keys";
const UPLOAD_DOCUMENT_PATH: &str = "/v1/documents";
#[cfg(feature = "attestation")]
const NVIDIA_NONCE_SIZE: usize = 32;

const SESSION_ID_HEADER: &str = "X-Session-ID";
const IDENTITY_TOKEN_HEADER: &str = "X-Identity-Token";
const IDENTITY_MESSAGE_HEADER: &str = "X-Identity-Message";
const PVC_ROOT_DIR: &str = ".pvc";
const KEY_FILE: &str = "secret";
#[cfg(feature = "attestation")]
const NVIDIA_REMOTE_VERIFIER_CONFIG: &str = r#"{
    "nvidia_verifier": {
        "type": "Remote",
        "verifier_url": "https://nras.attestation.nvidia.com/v4/attest"
    }
}"#;

pub type Claim = Vec<(Value, String)>;
pub type ChatCompletionStream = Pin<Box<dyn Stream<Item = Result<String>> + Send>>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PvcClientConfig {
    pub identity_server_url: String,
    pub ohttp_gateway_url: String,
    pub relay_url: String,
    pub target_url: String,
}

/// Source of the identity token used for the next handshake.
///
/// Implementations are consulted lazily by [`PvcClient::recover_session`]
/// each time the backend forgets our `sid` (e.g. after a pvc-tee-server
/// restart). Returning `None` is equivalent to the OAuth-disabled path —
/// the handshake will run unauthenticated.
///
/// We use a trait instead of caching the token in [`PvcClient`] so the
/// recovery path can pick up a freshly logged-in token when the operator
/// re-authenticates without having to call back into [`PvcClient`].
#[async_trait]
pub trait IdTokenProvider: Send + Sync {
    async fn id_token(&self) -> Option<String>;
}

/// Adapter so callers that already keep the live token in a Rocket-style
/// `Arc<RwLock<Option<String>>>` can pass it straight through to
/// [`PvcClient::set_id_token_provider`] without an extra wrapper.
#[async_trait]
impl IdTokenProvider for tokio::sync::RwLock<Option<String>> {
    async fn id_token(&self) -> Option<String> {
        self.read().await.clone()
    }
}

/// Convenience provider for callers that load the token once at startup
/// and never refresh it (e.g. `pvc-cli`, where each invocation reloads
/// the value from `session.json`).
#[derive(Debug, Clone, Default)]
pub struct StaticIdToken(pub Option<String>);

#[async_trait]
impl IdTokenProvider for StaticIdToken {
    async fn id_token(&self) -> Option<String> {
        self.0.clone()
    }
}

pub struct PvcClient {
    identity_server_url: Url,
    relay_url: Url,
    target_url: String,
    http_client: HttpClient,
    ohttp_key_config: KeyConfig,
    session_id: Option<String>,
    noise_transport: Option<Arc<Mutex<NoiseNnTransport>>>,
    /// Live source for the identity token used during session recovery.
    /// When unset, [`PvcClient::recover_session`] re-handshakes
    /// unauthenticated, which matches the OAuth-disabled deployment.
    id_token_provider: Option<Arc<dyn IdTokenProvider>>,
    /// Context key uploaded after the most recent handshake. Cached so the
    /// session recovery path can re-attach it to the freshly created Noise
    /// session without requiring the caller to redo the upload.
    cached_context_key: Option<ContextKey>,
}

#[cfg(feature = "attestation")]
fn nvidia_verifier_config() -> VerifierConfig {
    serde_json::from_str(NVIDIA_REMOTE_VERIFIER_CONFIG).unwrap()
}

#[cfg(feature = "attestation")]
async fn verify_evidence(
    evidence: &types::AttestationEvidence,
    report_data: &TeeReportData<'_>,
) -> Result<Claim> {
    let config = match evidence.tee_type {
        Tee::Nvidia => Some(nvidia_verifier_config()),
        _ => None,
    };
    let verifier = to_verifier(&evidence.tee_type, config)
        .await
        .context("failed to build attestation verifier")?;
    verifier
        .evaluate(
            evidence.evidence.clone(),
            report_data,
            &InitDataHash::NotProvided,
        )
        .await
        .map_err(Into::into)
}

#[cfg(feature = "attestation")]
fn device_report_data_for_tee<'a>(tee_type: Tee, report_data: &'a [u8]) -> TeeReportData<'a> {
    match tee_type {
        Tee::Nvidia => {
            assert!(report_data.len() >= NVIDIA_NONCE_SIZE);
            TeeReportData::Value(&report_data[0..NVIDIA_NONCE_SIZE])
        }
        Tee::SampleDevice => TeeReportData::Value(report_data),
        _ => TeeReportData::Value(report_data),
    }
}

#[cfg(feature = "attestation")]
async fn verify_attestation(
    cpu_evidence: &types::AttestationEvidence,
    device_evidences: &[types::AttestationEvidence],
    report_data: &[u8],
) -> Result<Claim> {
    let cpu_report_data = TeeReportData::Value(report_data);
    let mut claim = verify_evidence(cpu_evidence, &cpu_report_data).await?;
    info!("device tee num: {:?}", device_evidences.len());
    for device_evidence in device_evidences {
        let device_report_data = device_report_data_for_tee(device_evidence.tee_type, report_data);
        match verify_evidence(device_evidence, &device_report_data).await {
            Ok(mut device_claim) => claim.append(&mut device_claim),
            Err(e) => error!("failed to verify device evidence {:?}", e),
        }
    }
    Ok(claim)
}

impl PvcClient {
    pub async fn new<U: IntoUrl + Send>(
        identity_server_url: U,
        ohttp_gateway_url: U,
        relay_url: U,
        target_url: String,
    ) -> Result<Self> {
        let key_config = PvcClient::ohttp_initialize(ohttp_gateway_url).await?;
        Ok(Self {
            identity_server_url: identity_server_url.into_url()?,
            relay_url: relay_url.into_url()?,
            target_url,
            http_client: HttpClient::new(),
            ohttp_key_config: key_config,
            session_id: None,
            noise_transport: None,
            id_token_provider: None,
            cached_context_key: None,
        })
    }

    /// Registers a provider consulted by [`Self::recover_session`] to
    /// fetch the identity token at recovery time. Long-lived hosts should
    /// pass an adapter over their live token state (e.g.
    /// `Arc<RwLock<Option<String>>>` for Rocket); short-lived CLIs can use
    /// [`StaticIdToken`] to inject a one-shot value loaded from disk.
    pub fn set_id_token_provider(&mut self, provider: Arc<dyn IdTokenProvider>) {
        self.id_token_provider = Some(provider);
    }

    pub async fn from_config(config: &PvcClientConfig) -> Result<Self> {
        Self::new(
            config.identity_server_url.clone(),
            config.ohttp_gateway_url.clone(),
            config.relay_url.clone(),
            config.target_url.clone(),
        )
        .await
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub async fn handshake_with_attestation(&mut self, id_token: Option<String>) -> Result<()> {
        let identity = self.get_identity_token(id_token).await?;
        let verified = self.handshake_attestation_with_identity(&identity).await?;
        self.session_id = verified.session_id;
        self.establish_with_identity(verified.handshake_verifying_key, &identity)
            .await?;
        Ok(())
    }

    /// Performs a one-shot attestation against the target server.
    ///
    /// When a `nonce` is supplied, the request hits `/v1/attestation` with
    /// the explicit nonce contract and does **not** carry an identity
    /// header — the server-side route is unauthenticated and the client
    /// flow only needs to bind the returned evidence to the supplied
    /// nonce. When no nonce is supplied, we run the authenticated
    /// `/v1/handshake` path and reuse its verified claim set, which also
    /// updates [`PvcClient::session_id`] for any follow-up request.
    pub async fn attest(
        &mut self,
        nonce: Option<String>,
        id_token: Option<String>,
    ) -> Result<Claim> {
        match nonce {
            Some(nonce) => self.attest_with_nonce(nonce).await,
            None => {
                let identity = self.get_identity_token(id_token).await?;
                let verified = self.handshake_attestation_with_identity(&identity).await?;
                self.session_id = verified.session_id;
                Ok(verified.claims)
            }
        }
    }

    async fn attest_with_nonce(&self, nonce: String) -> Result<Claim> {
        self.attest_with_nonce_and_headers(nonce, None).await
    }

    async fn attest_with_nonce_and_headers(
        &self,
        nonce: String,
        headers: Option<HeaderMap>,
    ) -> Result<Claim> {
        let mut attestation_headers = headers.unwrap_or_default();
        attestation_headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        let body = serde_json::to_vec(&types::AttestationRequest {
            nonce: nonce.clone(),
        })?;
        let resp: AttestationResponse = self
            .ohttp_post(
                &self.target_url,
                ATTESTATION_PATH,
                Some(attestation_headers),
                Some(body),
            )
            .await?
            .ok_or(ApiError::MissingData)?;

        let claim = {
            #[cfg(feature = "attestation")]
            {
                let decoded_nonce = BASE64_STANDARD.decode(&nonce)?;
                if decoded_nonce.len() != 64 {
                    return Err(anyhow!("attestation nonce must decode to 64 bytes"));
                }
                verify_attestation(
                    &resp.attestation.cpu,
                    &resp.attestation.devices,
                    &decoded_nonce,
                )
                .await?
            }

            #[cfg(not(feature = "attestation"))]
            {
                let mut claim = Vec::new();
                claim.push((resp.attestation.cpu.evidence.clone(), "cpu".to_string()));
                claim
            }
        };

        Ok(claim)
    }

    async fn handshake_attestation_with_identity(
        &mut self,
        identity: &(String, String),
    ) -> Result<VerifiedHandshake> {
        let handshake_header = self.generate_identity_header(identity)?;
        let resp: AttestationResponse = self
            .ohttp_post(
                &self.target_url,
                HANDSHAKE_WITH_ATTESTATION_PATH,
                Some(handshake_header),
                None,
            )
            .await?
            .ok_or(ApiError::MissingData)?;

        let handshake_verifying_key: [u8; 64] = resp
            .binding
            .as_ref()
            .ok_or_else(|| anyhow!("missing attestation binding material"))
            .and_then(|binding| {
                BASE64_STANDARD
                    .decode(&binding.handshake_verifying_key)
                    .map_err(|e| anyhow!(e))?
                    .try_into()
                    .map_err(|_| anyhow!("invalid handshake verifying key length"))
            })?;

        let claims = {
            #[cfg(feature = "attestation")]
            {
                // The server uses `handshake_verifying_key` (64 bytes) as
                // report_data for CPU evidence and for sample-device evidence,
                // while NVIDIA verification only consumes the first 32 bytes.
                // Choose the device report-data shape per tee type so minikube
                // sample attestation and real NVIDIA attestation both verify.
                verify_attestation(
                    &resp.attestation.cpu,
                    &resp.attestation.devices,
                    &handshake_verifying_key,
                )
                .await?
            }

            #[cfg(not(feature = "attestation"))]
            {
                let mut claim = Vec::new();
                claim.push((resp.attestation.cpu.evidence.clone(), "cpu".to_string()));
                claim.extend(
                    resp.attestation
                        .devices
                        .iter()
                        .map(|device| (device.evidence.clone(), "gpu".to_string())),
                );
                claim
            }
        };

        Ok(VerifiedHandshake {
            handshake_verifying_key,
            session_id: resp.session.map(|session| session.id),
            claims,
        })
    }

    pub async fn establish(
        &mut self,
        verifying_key: [u8; 64],
        id_token: Option<String>,
    ) -> Result<()> {
        let identity = self.get_identity_token(id_token).await?;
        self.establish_with_identity(verifying_key, &identity).await
    }

    async fn establish_with_identity(
        &mut self,
        verifying_key: [u8; 64],
        identity: &(String, String),
    ) -> Result<()> {
        let mut noise_initiator =
            NoiseNnInitiator::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap(), None)?;

        let handshake_header = self.generate_identity_header(identity)?;

        let ephemeral = noise_initiator.generate_ephemeral()?;
        let resp: HandShakeResp = self
            .ohttp_post(
                &self.target_url,
                ESTABLISH_PATH,
                Some(handshake_header),
                Some(ephemeral.clone()),
            )
            .await?
            .ok_or(ApiError::MissingData)?;

        verify_noise_script_signature(verifying_key, &ephemeral, &resp.data, &resp.signature)?;

        let tp = noise_initiator.recv_response(&resp.data)?;
        self.noise_transport = Some(Arc::new(Mutex::new(tp)));
        Ok(())
    }

    #[cfg(feature = "noise")]
    fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if let Some(t) = &self.noise_transport {
            let mut transport = t
                .try_lock()
                .map_err(|_| anyhow!("Failed to acquire lock on noise transport"))?;
            transport.encrypt(message)
        } else {
            Err(anyhow!("noise transport is none, internal error happens"))
        }
    }

    #[cfg(not(feature = "noise"))]
    fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        Ok(message.to_vec())
    }

    pub async fn upload_encryption_key(&mut self, session_key: &ContextKey) -> Result<()> {
        let encrypted_key = self.encrypt_message(&session_key.0)?;
        let headers = self.generate_header();

        let _: Option<()> = self
            .ohttp_post(
                &self.target_url,
                UPLOAD_KEY_PATH,
                Some(headers),
                Some(encrypted_key),
            )
            .await?;
        // Cache for the recovery path: after a forced re-handshake the new
        // session has no context key, and any subsequent RAG-flavoured chat
        // would silently lose the document store. Keeping the key here lets
        // `recover_session` re-attach it to the fresh session id.
        self.cached_context_key = Some(session_key.clone());
        Ok(())
    }

    pub async fn upload_knowledge_document(&mut self, filename: &str, content: &str) -> Result<()> {
        let req = UploadDocumentReq {
            filename: filename.to_string(),
            content: content.to_string(),
        };
        let req_str = serde_json::to_string(&req).unwrap();
        let encrypted = self.encrypt_message(req_str.as_bytes())?;
        let headers = self.generate_header();
        let _: Option<()> = self
            .ohttp_post(
                &self.target_url,
                UPLOAD_DOCUMENT_PATH,
                Some(headers),
                Some(encrypted),
            )
            .await?;
        Ok(())
    }

    /// Issues a chat completions request against pvc-tee-llm with transparent
    /// single-shot session recovery.
    ///
    /// The cached `sid` lives only as long as the pvc-tee-server pod that
    /// minted it. After a tee-server restart the sid is gone and the data
    /// guard on the server rejects the request with `InvalidSessionId`. With
    /// the catcher registered in pvc-tee-llm this surfaces here as an
    /// `ApiError::BackendError { code: ApiCode::InvalidSessionId, .. }`
    /// inside `chat_completions_once`. For backwards compatibility with
    /// older pods that still emit Rocket's default HTML 400 (which the
    /// OHTTP gateway translates to 502) we also recognise the 502 / fuzzy
    /// match via [`is_session_rejected`].
    ///
    /// The orchestration (send → on InvalidSessionId, recover → resend once)
    /// is delegated to [`execute_with_session_recovery`] so the retry
    /// invariants (max-1 retry, propagate non-session errors as-is, fail
    /// fast if recovery itself fails) can be unit-tested against a mock
    /// transport — see the `execute_with_session_recovery_*` tests below.
    ///
    /// Concurrency note: callers wrap `PvcClient` in an `Arc<RwLock<…>>`
    /// (see `pvc-client/src/server.rs`). The write-lock held for the entire
    /// duration of this method serialises concurrent recovery, so we don't
    /// need a separate per-session mutex / coalescing OnceCell. If concurrent
    /// throughput on the chat endpoint ever becomes a bottleneck the simplest
    /// upgrade is to acquire a finer-grained `tokio::sync::Mutex` around just
    /// the recovery step; today the coarse RwLock is sufficient.
    pub async fn chat_completions(
        &mut self,
        h: Option<&HeaderMap>,
        body: &[u8],
    ) -> Result<ChatCompletionStream> {
        let op = ChatCompletionsOp {
            client: self,
            headers: h.cloned(),
            body: body.to_vec(),
        };
        execute_with_session_recovery(op).await
    }

    /// Single attempt of `chat_completions`: encrypt with the current Noise
    /// transport, POST through the OHTTP relay, and either return the
    /// decrypted stream or propagate a structured `ApiError::BackendError`
    /// when the response body is a JSON envelope instead of a Noise
    /// ciphertext stream.
    async fn chat_completions_once(
        &mut self,
        h: Option<&HeaderMap>,
        body: &[u8],
    ) -> Result<ChatCompletionStream> {
        let mut headers = match h {
            Some(h) => h.clone(),
            None => HeaderMap::new(),
        };
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(sid) = &self.session_id {
            headers.insert(SESSION_ID_HEADER, HeaderValue::from_str(sid)?);
        }

        let encrypted_input = self
            .encrypt_message(body)
            .map_err(|e| anyhow!("Failed to encrypt message: {}", e))?;
        let raw_stream = self
            .ohttp_post_stream(
                &self.target_url,
                CHAT_COMPLETIONS_PATH,
                Some(headers),
                Some(encrypted_input),
            )
            .await?;

        let stream = intercept_error_envelope(raw_stream).await?;
        self.decrypt_cipher_stream(stream).await
    }

    /// Drops the cached session state and re-runs the handshake (and
    /// context-key upload, if one was cached). Pulls the identity token
    /// from the registered [`IdTokenProvider`] at call time instead of a
    /// stale cache so re-authentication on the host side (e.g. Rocket
    /// updating `oauth_token`) is picked up automatically. Idempotent in
    /// the sense that repeated calls just produce a fresh sid each time;
    /// safe to invoke from the recovery path even when the prior handshake
    /// never happened.
    async fn recover_session(&mut self) -> Result<()> {
        self.session_id = None;
        self.noise_transport = None;
        let token = match &self.id_token_provider {
            Some(provider) => provider.id_token().await,
            None => None,
        };
        self.handshake_with_attestation(token).await?;
        if let Some(key) = self.cached_context_key.clone() {
            self.upload_encryption_key(&key).await?;
        }
        Ok(())
    }

    async fn get_identity_token(&self, id_token: Option<String>) -> Result<(String, String)> {
        let pk: BlindPublicKey = self.fetch_public_key().await?;

        let msg = {
            let mut msg = vec![0; 20];
            OsRng.fill_bytes(&mut msg);
            msg
        };
        let blinder = RsaBlinder {};
        let state = blinder
            .blind(&msg, pk.clone())
            .context("Failed to blind message")?;
        let blinded_msg = state.blinded_message()?;

        let blind_sig_bytes = self
            .request_blind_signature(&blinded_msg, id_token)
            .await
            .context("Failed to request blind signature")?;

        let sig = blinder
            .verify(&blind_sig_bytes, &state, pk)
            .context("Failed to verify unblind signature")?;

        Ok((hex::encode(&msg), hex::encode(&sig)))
    }

    fn generate_header(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(sid) = &self.session_id {
            headers.insert(SESSION_ID_HEADER, HeaderValue::from_str(sid).unwrap());
        }
        headers
    }

    fn generate_identity_header(&self, identity: &(String, String)) -> Result<HeaderMap> {
        let (msg, token) = identity;
        let mut headers = self.generate_header();
        headers.insert(IDENTITY_TOKEN_HEADER, HeaderValue::from_str(token)?);
        headers.insert(IDENTITY_MESSAGE_HEADER, HeaderValue::from_str(msg)?);
        Ok(headers)
    }

    async fn decrypt_cipher_stream(
        &mut self,
        stream: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>,
    ) -> Result<ChatCompletionStream> {
        let noise_transport = self
            .noise_transport
            .clone()
            .ok_or_else(|| anyhow!("noise transport missing"))?;
        let reader = StreamReader::new(
            stream.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e)),
        );
        let codec = LengthDelimitedCodec::builder()
            .length_field_length(4)
            .max_frame_length(1024 * 1024)
            .new_read(reader);
        let decrypted_stream = codec
            .map_err(|e| anyhow!(format!("failed to read cipher stream {}", e)))
            .then(move |frame_res| {
                let noise_transport = noise_transport.clone();
                async move {
                    let frame = match frame_res {
                        Ok(f) => f,
                        Err(e) => return Err(e),
                    };
                    #[cfg(feature = "noise")]
                    {
                        let mut transport = noise_transport.lock().await;
                        transport
                            .decrypt(&frame)
                            .map_err(|e| anyhow!("Decryption failed: {}", e))
                            .and_then(|d| {
                                String::from_utf8(d).map_err(|e| anyhow!("UTF8 error: {}", e))
                            })
                            .map(Some)
                    }
                    #[cfg(not(feature = "noise"))]
                    {
                        let _ = &noise_transport;
                        Ok(Some(String::from_utf8_lossy(&frame).to_string()))
                    }
                }
            })
            .try_filter_map(|res| async move { Ok(res) });
        Ok(Box::pin(decrypted_stream))
    }
}

/// Abstracts a single session-using operation that can be transparently
/// retried after a session has been invalidated on the server.
///
/// Splitting [`PvcClient::chat_completions`] into "attempt the request" +
/// "recover the session" via this trait lets us unit-test the retry
/// orchestration (max-1 retry, correct error fall-through, no infinite
/// loops) without spinning up an OHTTP stack.
#[async_trait]
trait SessionedOperation: Send {
    type Output: Send;

    /// Performs one attempt of the underlying request. Errors that satisfy
    /// [`is_session_rejected`] trigger a single recovery + retry; all other
    /// errors are propagated unchanged.
    async fn attempt(&mut self) -> Result<Self::Output>;

    /// Re-establishes session state (typically: clear sid, run a fresh
    /// `handshake_with_attestation`, re-upload context key). Called at most
    /// once per [`execute_with_session_recovery`] invocation.
    async fn recover_session(&mut self) -> Result<()>;
}

/// Drives [`SessionedOperation`] with single-shot session recovery.
///
/// Semantics — exactly one retry, never more:
///
/// 1. Run `op.attempt()`. On success, return.
/// 2. On any other error, return it unchanged. We do not touch the cached
///    session for non-session-rejection failures (e.g. network timeouts,
///    decrypt errors) because those tend to be transient at a lower layer
///    and rehandshaking would make recovery flakier, not faster.
/// 3. On a session-rejection error (see [`is_session_rejected`]), log a
///    warning, call `op.recover_session()`. If recovery itself fails we
///    propagate that error with context — we do not loop, so a broken
///    handshake path cannot turn into an infinite retry storm.
/// 4. Run `op.attempt()` one more time and return whatever it produces,
///    even if it is another `InvalidSessionId`. The caller's retry budget
///    is intentionally bounded at "one extra try" to keep failure modes
///    predictable.
async fn execute_with_session_recovery<O>(mut op: O) -> Result<O::Output>
where
    O: SessionedOperation,
{
    match op.attempt().await {
        Ok(v) => Ok(v),
        Err(e) if is_session_rejected(&e) => {
            warn!(
                error = %e,
                "session rejected by tee-llm, re-handshaking and retrying once",
            );
            op.recover_session()
                .await
                .with_context(|| "failed to recover session after InvalidSessionId from tee-llm")?;
            info!("session re-established, retrying request once");
            match op.attempt().await {
                Ok(v) => Ok(v),
                Err(e) => {
                    error!(error = %e, "retry after session recovery also failed");
                    Err(e)
                }
            }
        }
        Err(e) => Err(e),
    }
}

/// Adapter that lets `PvcClient::chat_completions` go through
/// [`execute_with_session_recovery`] without exposing the trait publicly.
struct ChatCompletionsOp<'a> {
    client: &'a mut PvcClient,
    headers: Option<HeaderMap>,
    body: Vec<u8>,
}

#[async_trait]
impl<'a> SessionedOperation for ChatCompletionsOp<'a> {
    type Output = ChatCompletionStream;

    async fn attempt(&mut self) -> Result<ChatCompletionStream> {
        self.client
            .chat_completions_once(self.headers.as_ref(), &self.body)
            .await
    }

    async fn recover_session(&mut self) -> Result<()> {
        self.client.recover_session().await
    }
}

/// Returns `true` when an error from a session-using request looks like the
/// client should re-handshake before retrying once.
///
/// Detection order (most-specific first):
///
/// 1. A `BackendError` other than `InvalidSessionId`. We must short-circuit
///    here so that, for example, a `NoiseDecryptFailed` envelope is NOT
///    treated as a session-recovery signal even though the same envelope
///    family is involved.
/// 2. Structured `ApiError::BackendError { code: ApiCode::InvalidSessionId,
///    .. }` — produced by `intercept_error_envelope` after the tee-llm 400
///    catcher rewrites Rocket's default HTML 400 into a JSON envelope.
///    This is the canonical signal on post-rollout deployments.
/// 3. A 502 Bad Gateway from the OHTTP relay. The gateway maps any non-2xx
///    backend response to 502, so a tee-llm pod that predates the catcher
///    fix surfaces here as `reqwest::Error` whose `Display` contains the
///    canonical `"502 Bad Gateway"` token. We require BOTH substrings to
///    appear in the error message before re-handshaking, so unrelated
///    failures whose Display happens to contain "502" (e.g. a port number
///    or UUID) do not trigger spurious recovery.
///
///    This branch exists purely for backward compatibility with older
///    deployments that have not yet picked up the catchers. Once those are
///    drained, the branch can be deleted along with its dedicated test.
/// 4. Explicit local client state gaps such as a missing Noise transport.
///    This lets the first chat request lazily bootstrap session state in
///    OAuth-enabled deployments where startup warmup is skipped.
/// 5. A last-ditch fuzzy text match against `InvalidSessionId` / "Invalid
///    session ID" anywhere in the error chain, in case a future transport
///    surfaces the structured code via a different error shape.
pub fn is_session_rejected(err: &anyhow::Error) -> bool {
    if let Some(api_err) = err.downcast_ref::<ApiError>() {
        return matches!(
            api_err,
            ApiError::BackendError { code, .. } if *code == ApiCode::InvalidSessionId as i32,
        );
    }
    let msg = err.to_string();
    // Require BOTH tokens to avoid matching unrelated text. The canonical
    // reqwest format is `HTTP status server error (502 Bad Gateway) for
    // url (...)`, so this still catches the production-observed shape.
    if msg.contains("502") && msg.contains("Bad Gateway") {
        return true;
    }
    if msg.contains("noise transport is none") || msg.contains("noise transport missing") {
        return true;
    }
    if msg.contains("InvalidSessionId") || msg.contains("Invalid session ID") {
        return true;
    }
    false
}

/// Peeks at the first chunk(s) of a (likely) Noise-encrypted response stream
/// and short-circuits to a structured `ApiError::BackendError` when the body
/// is actually a plaintext `ApiResponse` envelope.
///
/// The tee-llm `chat_completions` handler returns one of two body shapes:
///
/// * Happy path: a length-prefixed Noise cipher stream where the first 4
///   bytes are a big-endian frame length. For any reasonably sized frame
///   (< 16 MiB) the first byte is `0x00`.
/// * Error path: the project-wide `ApiResponse` JSON envelope rendered by
///   `ApiCode::respond_to` (always a 200 OK on the wire so the OHTTP gateway
///   forwards the body intact). JSON envelopes always start with `{`.
///
/// We only buffer the response when the first byte is `{` — i.e. only in
/// the rare "session rejected" path. The bytes we buffered are re-emitted as
/// a single chunk when decoding fails or the envelope turns out to be a
/// success code, so the streaming behaviour of the success path is
/// preserved.
async fn intercept_error_envelope(
    mut stream: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>,
) -> Result<Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>> {
    const MAX_ENVELOPE_BYTES: usize = 64 * 1024;

    let first = match stream.next().await {
        Some(Ok(chunk)) => chunk,
        Some(Err(e)) => return Err(e),
        None => return Ok(Box::pin(futures::stream::empty())),
    };

    if first.first() != Some(&b'{') {
        let initial = futures::stream::iter(vec![Ok(first)]);
        return Ok(Box::pin(initial.chain(stream)));
    }

    let mut buf: Vec<u8> = first.to_vec();
    while buf.len() <= MAX_ENVELOPE_BYTES {
        match stream.next().await {
            Some(Ok(chunk)) => buf.extend_from_slice(&chunk),
            Some(Err(e)) => return Err(e),
            None => break,
        }
    }

    if buf.len() > MAX_ENVELOPE_BYTES {
        // Way too big to be an envelope; rejoin and treat as a Noise stream.
        let initial = futures::stream::iter(vec![Ok(Bytes::from(buf))]);
        return Ok(Box::pin(initial.chain(stream)));
    }

    match serde_json::from_slice::<ApiResponse<serde_json::Value>>(&buf) {
        Ok(envelope) if envelope.code != ApiCode::Success => Err(ApiError::BackendError {
            code: envelope.code,
            message: envelope.message,
        }
        .into()),
        _ => {
            // Either a 200 success envelope (unexpected on this path) or
            // arbitrary leading bytes that happened to start with `{`. Fall
            // through to the Noise codec by re-emitting what we buffered.
            let single = futures::stream::iter(vec![Ok(Bytes::from(buf))]);
            Ok(Box::pin(single))
        }
    }
}

pub fn create_or_get_encryption_key() -> Result<ContextKey> {
    let path = key_path_in_home()?;
    match fs::read(&path) {
        Ok(buf) => Ok(ContextKey(buf)),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if let Some(dir) = path.parent() {
                fs::create_dir_all(dir)?;
            }

            let mut key = vec![0u8; 32];
            OsRng.fill_bytes(&mut key);
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&path)?;
            file.write_all(&key)?;
            file.sync_all()?;

            Ok(ContextKey(key))
        }
        Err(err) => Err(err.into()),
    }
}

pub fn pvc_home_dir() -> Result<PathBuf> {
    let home = std::env::home_dir().ok_or_else(|| anyhow!("home directory is unavailable"))?;
    Ok(home.join(PVC_ROOT_DIR))
}

pub fn key_path_in_home() -> Result<PathBuf> {
    Ok(pvc_home_dir()?.join(KEY_FILE))
}

pub fn ensure_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    Ok(())
}

pub fn read_json_file<T: DeserializeOwned>(path: &Path) -> Result<Option<T>> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err.into()),
    }
}

pub fn write_private_json_file<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    ensure_parent_dir(path)?;
    let data = serde_json::to_vec_pretty(value)?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&data)?;
    file.write_all(b"\n")?;
    Ok(())
}

pub fn remove_file_if_exists(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

/// Extract the 64-byte CPU `report_data` from a verified claim set.
///
/// Kept `pub(crate)` because the canonical client flow now binds against
/// `binding.handshake_verifying_key` from the normalized handshake
/// response, not the in-quote report data. This helper is retained for
/// the unit tests and for any future internal caller that needs to
/// re-derive the report data from a parsed claim list.
#[allow(dead_code)]
pub(crate) fn extract_report_data(claims: &Claim) -> Result<ReportData> {
    let cpu = claims
        .iter()
        .find(|(_val, key)| key == "cpu")
        .map(|(val, _key)| val)
        .ok_or_else(|| anyhow!("missing cpu claim"))?;
    let report_data_str = cpu["report_data"]
        .as_str()
        .ok_or_else(|| anyhow!("missing cpu report_data claim"))?;
    match hex::decode(report_data_str) {
        Ok(report_data) => report_data
            .try_into()
            .map_err(|_| anyhow!("invalid cpu report_data length")),
        Err(_) => BASE64_STANDARD
            .decode(report_data_str)
            .map_err(|e| anyhow!(e))?
            .try_into()
            .map_err(|_| anyhow!("invalid cpu report_data length")),
    }
}

fn verify_noise_script_signature(
    verifying_key: [u8; 64],
    e: &[u8],
    ee: &[u8],
    signature: &[u8],
) -> Result<()> {
    let verifying_key = decode_verifying_key(verifying_key)?;
    let mut message = Vec::new();
    message.extend_from_slice(e);
    message.extend_from_slice(ee);
    verifying_key
        .verify(&message, &Signature::from_slice(signature)?)
        .map_err(|_| anyhow!("failed to verify noise script signature"))
}

#[async_trait]
impl IdentityClient for PvcClient {
    async fn fetch_public_key(&self) -> Result<BlindPublicKey> {
        let resp: PublicKeyFields = self
            .http_client
            .get(self.identity_server_url.join("pubkey")?, None)
            .await?
            .ok_or(ApiError::MissingData)?;
        let pk = BlindPublicKey {
            n: BASE64_STANDARD.decode(&resp.n)?,
            e: BASE64_STANDARD.decode(&resp.e)?,
        };
        Ok(pk)
    }

    async fn request_blind_signature(
        &self,
        blinded_message: &[u8],
        id_token: Option<String>,
    ) -> Result<Vec<u8>> {
        let body = BlindMessageRequest {
            blinded_message: blinded_message.to_vec(),
        };
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(id_token) = id_token {
            headers.insert(
                AUTHORIZATION,
                format!("Bearer {}", id_token).parse().unwrap(),
            );
        }
        let body_bytes = serde_json::to_string(&body)?;
        let resp: BlindMessageResponse = self
            .http_client
            .post(
                self.identity_server_url.join("sign")?,
                body_bytes.as_bytes(),
                Some(headers),
            )
            .await?
            .ok_or(ApiError::MissingData)?;
        let sig: Vec<u8> = BASE64_STANDARD.decode(resp.signature)?;
        Ok(sig)
    }
}

#[async_trait]
impl OhttpClient for PvcClient {
    async fn ohttp_initialize<U>(ohttp_gateway_url: U) -> Result<KeyConfig>
    where
        U: IntoUrl + Send,
    {
        let ohttp_gateway_url: Url = ohttp_gateway_url.into_url()?;
        let config_url = ohttp_gateway_url.join("ohttp-configs")?;
        let http_client = HttpClient::new();
        let resp = http_client.get_with_raw_response(config_url, None).await?;
        let cfg_bytes = resp.bytes().await?;
        if cfg_bytes.len() < 2 {
            return Err(anyhow!("Invalid ohttp-configs response"));
        }
        let length_prefix = u16::from_be_bytes([cfg_bytes[0], cfg_bytes[1]]);
        if length_prefix != (cfg_bytes.len() - 2) as u16 {
            return Err(anyhow!("Invalid length prefix for ohttp-configs"));
        }
        let key_config: KeyConfig = KeyConfig::decode(&cfg_bytes[2..])?;
        Ok(key_config)
    }

    async fn ohttp_post_stream(
        &self,
        target_server: &str,
        path: &str,
        headers: Option<HeaderMap>,
        body: Option<Vec<u8>>,
    ) -> Result<Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>> {
        let mut request = Message::request(
            b"POST".to_vec(),
            b"http".to_vec(),
            target_server.as_bytes().to_vec(),
            path.as_bytes().to_vec(),
        );
        if let Some(b) = body {
            request.write_content(&b);
        }
        if let Some(headers) = headers {
            for (name, value) in headers.iter() {
                request.put_header(name.as_str(), value.as_bytes());
            }
        }

        let mut request_buf = Vec::new();
        request.write_bhttp(Mode::KnownLength, &mut request_buf)?;
        let req: ClientRequest = ClientRequest::from_config(&mut self.ohttp_key_config.clone())?;

        let (encrypted_request, client_request) = {
            let (request_write, mut request_read) = async_rw::create_channel_pair();
            let mut enc_request_writer = req
                .encapsulate_stream(request_write)
                .map_err(|e| anyhow!("Failed to encapsulate request: {}", e))?;

            let reader_task: tokio::task::JoinHandle<Result<Vec<u8>, anyhow::Error>> =
                tokio::spawn(async move {
                    let mut encrypted_request = Vec::new();
                    request_read
                        .read_to_end(&mut encrypted_request)
                        .await
                        .map_err(|e| anyhow!("Failed to read from encrypt request: {}", e))?;
                    Ok(encrypted_request)
                });

            enc_request_writer
                .write_all(&request_buf)
                .await
                .map_err(|e| anyhow!("Failed to write request: {}", e))?;

            enc_request_writer
                .close()
                .await
                .map_err(|e| anyhow!("Failed to close writer: {}", e))?;

            let encrypted_request = reader_task
                .await
                .map_err(|e| anyhow!("Failed reader task: {}", e))??;

            (encrypted_request, enc_request_writer)
        };

        let relay_request_body = {
            #[cfg(feature = "base64")]
            {
                BASE64_STANDARD.encode(&encrypted_request).into_bytes()
            }
            #[cfg(not(feature = "base64"))]
            {
                encrypted_request
            }
        };

        let mut outer_headers: HeaderMap = HeaderMap::new();
        outer_headers.insert(CONTENT_TYPE, "message/ohttp-req".parse().unwrap());
        let response = self
            .http_client
            .post_with_raw_response(
                self.relay_url.clone(),
                &relay_request_body,
                Some(outer_headers),
            )
            .await?
            .error_for_status()?;

        let (mut channel_writer, channel_reader) = async_rw::create_channel_pair_with_size(1024);
        let response_read = client_request
            .response(channel_reader)
            .map_err(|_| anyhow!("Failed to set response".to_string()))?;

        let resp_stream = response.bytes_stream();
        tokio::spawn(async move {
            let mut resp_stream = Box::pin(resp_stream);
            while let Some(bytes_chunk) = resp_stream.next().await {
                match bytes_chunk {
                    Ok(chunk) => {
                        if let Err(e) = channel_writer.write_all(&chunk).await {
                            error!("Failed to write chunk: {}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Error from ohttp response stream: {}", e);
                        break;
                    }
                }
            }

            let _ = channel_writer.close().await;
        });

        Ok(Box::pin(futures::stream::unfold(
            response_read,
            |mut response_read| {
                Box::pin(async move {
                    let mut buffer = vec![0; 1024];
                    match response_read.read(&mut buffer).await {
                        Ok(0) => None,
                        Ok(n) => Some((Ok(Bytes::copy_from_slice(&buffer[..n])), response_read)),
                        Err(e) => {
                            error!("OHTTP decryption failed: {}", e);
                            Some((Err(anyhow::Error::from(e)), response_read))
                        }
                    }
                })
            },
        )))
    }

    async fn ohttp_post<V: DeserializeOwned>(
        &self,
        target_server: &str,
        path: &str,
        headers: Option<HeaderMap>,
        body: Option<Vec<u8>>,
    ) -> Result<Option<V>> {
        let mut bytes_stream = self
            .ohttp_post_stream(target_server, path, headers, body)
            .await?;
        let mut res = Vec::new();
        while let Some(result) = bytes_stream.next().await {
            match result {
                Ok(chunk) => res.extend_from_slice(&chunk),
                Err(e) => return Err(e),
            }
        }

        let api_resp: ApiResponse<V> = serde_json::from_slice(&res)?;
        api_resp.data().map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sign_noise_message() -> ([u8; 64], Vec<u8>, Vec<u8>, [u8; 64]) {
        use p256::ecdsa::{Signature, SigningKey, VerifyingKey, signature::Signer};
        use p256::elliptic_curve::rand_core::OsRng;

        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        let e = b"client_ephemeral_e".to_vec();
        let ee = b"server_ephemeral_ee".to_vec();
        let mut msg = Vec::new();
        msg.extend_from_slice(&e);
        msg.extend_from_slice(&ee);

        let sig: Signature = signing_key.sign(&msg);
        let raw64: [u8; 64] = sig.to_bytes().into();
        let vk_bytes = verifying_key.to_encoded_point(false);
        let vk_raw = &vk_bytes.as_bytes()[1..65];
        let verifying_key: [u8; 64] = vk_raw.try_into().unwrap();

        (verifying_key, e, ee, raw64)
    }

    #[test]
    fn test_verify_signature_with_raw_p1363_bytes() {
        let (verifying_key, e, ee, signature) = sign_noise_message();

        verify_noise_script_signature(verifying_key, &e, &ee, &signature).unwrap();
    }

    #[test]
    fn test_verify_signature_rejects_mismatched_binding_material() {
        use p256::ecdsa::{SigningKey, VerifyingKey};
        use p256::elliptic_curve::rand_core::OsRng;

        let (_verifying_key, e, ee, signature) = sign_noise_message();
        let other_signing_key = SigningKey::random(&mut OsRng);
        let other_verifying_key = VerifyingKey::from(&other_signing_key);
        let other_bytes = other_verifying_key.to_encoded_point(false);
        let mismatched_key: [u8; 64] = other_bytes.as_bytes()[1..65].try_into().unwrap();

        let error = verify_noise_script_signature(mismatched_key, &e, &ee, &signature).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("failed to verify noise script signature")
        );
    }

    #[test]
    fn extract_report_data_supports_cpu_only_claims() {
        let report_data = [7u8; 64];
        let claims = vec![(
            json!({"report_data": hex::encode(report_data)}),
            "cpu".to_string(),
        )];

        assert_eq!(extract_report_data(&claims).unwrap(), report_data);
    }

    #[test]
    fn extract_report_data_ignores_device_claims() {
        let report_data = [9u8; 64];
        let claims = vec![
            (
                json!({"nonce": BASE64_STANDARD.encode([3u8; 32])}),
                "gpu".to_string(),
            ),
            (
                json!({"report_data": BASE64_STANDARD.encode(report_data)}),
                "cpu".to_string(),
            ),
        ];

        assert_eq!(extract_report_data(&claims).unwrap(), report_data);
    }

    #[cfg(feature = "attestation")]
    #[test]
    fn device_report_data_for_nvidia_uses_32_byte_nonce() {
        let report_data = [7u8; 64];

        // `verifier::ReportData` has multiple variants (e.g. `NotProvided`),
        // so this `let`-binding is refutable. Use `let else` and panic
        // explicitly when the helper diverges from its documented contract
        // of always returning `Value(_)` — an `unreachable!()` would silently
        // swallow a regression in test mode.
        let TeeReportData::Value(value) = device_report_data_for_tee(Tee::Nvidia, &report_data)
        else {
            panic!("device_report_data_for_tee(Nvidia) must return Value(_)");
        };
        assert_eq!(value, &report_data[..NVIDIA_NONCE_SIZE]);
    }

    #[cfg(feature = "attestation")]
    #[test]
    fn device_report_data_for_sample_device_uses_full_report_data() {
        let report_data = [11u8; 64];

        let TeeReportData::Value(value) =
            device_report_data_for_tee(Tee::SampleDevice, &report_data)
        else {
            panic!("device_report_data_for_tee(SampleDevice) must return Value(_)");
        };
        assert_eq!(value, &report_data[..]);
    }

    #[test]
    fn is_session_rejected_detects_structured_invalid_session_id() {
        let err = anyhow::Error::new(ApiError::BackendError {
            code: ApiCode::InvalidSessionId as i32,
            message: "Invalid session ID".to_string(),
        });

        assert!(is_session_rejected(&err));
    }

    #[test]
    fn is_session_rejected_detects_502_bad_gateway_from_reqwest_text() {
        // Reproduces the exact `reqwest::Error::Display` shape we see in
        // production logs when pvc-tee-llm returns a default 400 page and the
        // OHTTP gateway translates it to 502 Bad Gateway.
        let err =
            anyhow!("HTTP status server error (502 Bad Gateway) for url (http://pvc-relay:8787/)");

        assert!(is_session_rejected(&err));
    }

    #[test]
    fn is_session_rejected_fuzzy_matches_session_id_string() {
        let err = anyhow!("upstream said: InvalidSessionId");
        assert!(is_session_rejected(&err));

        let pretty = anyhow!("backend reported Invalid session ID for sid=abc");
        assert!(is_session_rejected(&pretty));
    }

    #[test]
    fn is_session_rejected_detects_missing_local_noise_transport() {
        let err =
            anyhow!("Failed to encrypt message: noise transport is none, internal error happens");
        assert!(is_session_rejected(&err));

        let decrypt_path = anyhow!("noise transport missing");
        assert!(is_session_rejected(&decrypt_path));
    }

    #[test]
    fn is_session_rejected_ignores_unrelated_errors() {
        let err = anyhow!("connection refused");
        assert!(!is_session_rejected(&err));

        let api_err = anyhow::Error::new(ApiError::BackendError {
            code: ApiCode::NoiseDecryptFailed as i32,
            message: "decrypt failure".to_string(),
        });
        assert!(!is_session_rejected(&api_err));

        let local_crypto_err = anyhow!("Failed to encrypt message: invalid key material");
        assert!(!is_session_rejected(&local_crypto_err));
    }

    #[test]
    fn is_session_rejected_502_branch_requires_both_tokens() {
        // Pure "502" without "Bad Gateway" must NOT trigger recovery —
        // otherwise a URL containing the substring "502" (e.g. a port or
        // request id) would unnecessarily force a re-handshake.
        let port_in_url = anyhow!("connect failed for url (http://service:9502/health)");
        assert!(!is_session_rejected(&port_in_url));

        // Pure "Bad Gateway" without "502" is unlikely from reqwest but
        // still must not trigger — leaves the door open for a future
        // proxy that emits the phrase outside the 502 path.
        let bad_gateway_only = anyhow!("upstream returned: Bad Gateway placeholder body");
        assert!(!is_session_rejected(&bad_gateway_only));
    }

    #[tokio::test]
    async fn intercept_error_envelope_returns_structured_error_for_envelope_body() {
        let envelope = ApiResponse::<serde_json::Value> {
            code: ApiCode::InvalidSessionId as i32,
            message: "Invalid session ID".to_string(),
            data: None,
        };
        let body = serde_json::to_vec(&envelope).unwrap();
        let stream: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>> =
            Box::pin(futures::stream::iter(vec![Ok(Bytes::from(body))]));

        let err = match intercept_error_envelope(stream).await {
            Ok(_) => panic!("error envelope should short-circuit to Err"),
            Err(e) => e,
        };
        assert!(is_session_rejected(&err));
    }

    #[tokio::test]
    async fn intercept_error_envelope_passes_through_noise_like_bytes() {
        // Noise frames start with a 4-byte big-endian length prefix; the
        // first byte for any < 16 MiB frame is `0x00`, which is distinct
        // from the `{` that a JSON envelope would start with.
        let noise_bytes = vec![0x00, 0x00, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let stream: Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>> = Box::pin(
            futures::stream::iter(vec![Ok(Bytes::from(noise_bytes.clone()))]),
        );

        let mut out = intercept_error_envelope(stream).await.unwrap();
        let first = out
            .next()
            .await
            .expect("stream should emit at least one chunk")
            .unwrap();
        assert_eq!(first.as_ref(), noise_bytes.as_slice());
    }

    // --- session-recovery orchestration tests ----------------------------
    //
    // The tests below exercise `execute_with_session_recovery` directly via
    // a hand-rolled `SessionedOperation` mock. They cover the invariants
    // declared on `PvcClient::chat_completions`:
    //
    //   * a single `InvalidSessionId` triggers exactly one recovery + retry,
    //   * non-session errors pass straight through without touching the
    //     session,
    //   * a back-to-back `InvalidSessionId` does NOT loop (max 2 attempts,
    //     1 recovery),
    //   * a recovery failure short-circuits the retry.

    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Behaviour script driving the per-attempt outcome.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AttemptOutcome {
        Ok,
        InvalidSession,
        MissingLocalNoiseTransport,
        OtherError,
    }

    /// Mock `SessionedOperation` whose attempts return a scripted sequence
    /// of outcomes. We count both `attempt` and `recover_session` calls via
    /// `Arc<AtomicUsize>` so the assertions can inspect them after the
    /// helper consumes the op.
    struct ScriptedOp {
        outcomes: Vec<AttemptOutcome>,
        attempt_calls: Arc<AtomicUsize>,
        recover_calls: Arc<AtomicUsize>,
        recover_outcome: Result<(), &'static str>,
    }

    #[async_trait]
    impl SessionedOperation for ScriptedOp {
        type Output = &'static str;

        async fn attempt(&mut self) -> Result<Self::Output> {
            let idx = self.attempt_calls.fetch_add(1, Ordering::SeqCst);
            // Guard against the helper ever issuing a third attempt.
            assert!(
                idx < self.outcomes.len(),
                "execute_with_session_recovery issued attempt #{} but only {} scripted",
                idx + 1,
                self.outcomes.len()
            );
            match self.outcomes[idx] {
                AttemptOutcome::Ok => Ok("payload"),
                AttemptOutcome::InvalidSession => Err(anyhow::Error::new(ApiError::BackendError {
                    code: ApiCode::InvalidSessionId as i32,
                    message: "Invalid session ID".to_string(),
                })),
                AttemptOutcome::MissingLocalNoiseTransport => Err(anyhow!(
                    "Failed to encrypt message: noise transport is none, internal error happens"
                )),
                AttemptOutcome::OtherError => Err(anyhow!("transport timeout")),
            }
        }

        async fn recover_session(&mut self) -> Result<()> {
            self.recover_calls.fetch_add(1, Ordering::SeqCst);
            match self.recover_outcome {
                Ok(()) => Ok(()),
                Err(msg) => Err(anyhow!(msg)),
            }
        }
    }

    fn counters() -> (Arc<AtomicUsize>, Arc<AtomicUsize>) {
        (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)))
    }

    #[tokio::test]
    async fn execute_with_session_recovery_retries_after_invalid_session() {
        // First call fails with InvalidSessionId, recovery succeeds, second
        // call succeeds. This is the primary success path the task asks us
        // to verify: 2 attempts, 1 handshake, retry result is returned.
        let (attempts, recoveries) = counters();
        let op = ScriptedOp {
            outcomes: vec![AttemptOutcome::InvalidSession, AttemptOutcome::Ok],
            attempt_calls: attempts.clone(),
            recover_calls: recoveries.clone(),
            recover_outcome: Ok(()),
        };

        let result = execute_with_session_recovery(op).await;

        assert_eq!(result.unwrap(), "payload");
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            2,
            "expected exactly two attempts (original + retry)"
        );
        assert_eq!(
            recoveries.load(Ordering::SeqCst),
            1,
            "expected exactly one recovery handshake between the attempts"
        );
    }

    #[tokio::test]
    async fn execute_with_session_recovery_retries_after_missing_local_noise_transport() {
        let (attempts, recoveries) = counters();
        let op = ScriptedOp {
            outcomes: vec![
                AttemptOutcome::MissingLocalNoiseTransport,
                AttemptOutcome::Ok,
            ],
            attempt_calls: attempts.clone(),
            recover_calls: recoveries.clone(),
            recover_outcome: Ok(()),
        };

        let result = execute_with_session_recovery(op).await;

        assert_eq!(result.unwrap(), "payload");
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(recoveries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn execute_with_session_recovery_no_retry_on_first_success() {
        let (attempts, recoveries) = counters();
        let op = ScriptedOp {
            outcomes: vec![AttemptOutcome::Ok],
            attempt_calls: attempts.clone(),
            recover_calls: recoveries.clone(),
            recover_outcome: Ok(()),
        };

        let result = execute_with_session_recovery(op).await;

        assert_eq!(result.unwrap(), "payload");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            recoveries.load(Ordering::SeqCst),
            0,
            "recovery must not run on the happy path",
        );
    }

    #[tokio::test]
    async fn execute_with_session_recovery_passes_through_unrelated_errors() {
        // Non-session-rejection errors must be returned verbatim and must
        // NOT trigger a re-handshake. Triggering a handshake on every
        // network blip would be a denial-of-service waiting to happen.
        let (attempts, recoveries) = counters();
        let op = ScriptedOp {
            outcomes: vec![AttemptOutcome::OtherError],
            attempt_calls: attempts.clone(),
            recover_calls: recoveries.clone(),
            recover_outcome: Ok(()),
        };

        let err = execute_with_session_recovery(op).await.unwrap_err();

        assert!(err.to_string().contains("transport timeout"));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(recoveries.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn execute_with_session_recovery_caps_retries_at_one() {
        // Two consecutive InvalidSessionId errors must NOT loop. If the
        // helper ever issued a third attempt, `ScriptedOp::attempt` would
        // panic with the out-of-range assertion above.
        let (attempts, recoveries) = counters();
        let op = ScriptedOp {
            outcomes: vec![
                AttemptOutcome::InvalidSession,
                AttemptOutcome::InvalidSession,
            ],
            attempt_calls: attempts.clone(),
            recover_calls: recoveries.clone(),
            recover_outcome: Ok(()),
        };

        let err = execute_with_session_recovery(op).await.unwrap_err();

        assert!(is_session_rejected(&err));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(recoveries.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn execute_with_session_recovery_propagates_recovery_failure() {
        // If the handshake itself fails we must surface that error (with
        // context) instead of silently swallowing it or pretending the
        // original InvalidSessionId did not happen.
        let (attempts, recoveries) = counters();
        let op = ScriptedOp {
            outcomes: vec![AttemptOutcome::InvalidSession],
            attempt_calls: attempts.clone(),
            recover_calls: recoveries.clone(),
            recover_outcome: Err("handshake refused"),
        };

        let err = execute_with_session_recovery(op).await.unwrap_err();
        let display = format!("{:#}", err);

        assert!(
            display.contains("failed to recover session after InvalidSessionId"),
            "expected recovery context in error chain, got: {display}"
        );
        assert!(
            display.contains("handshake refused"),
            "expected underlying handshake error in chain, got: {display}"
        );
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            1,
            "no retry must run after recovery failure",
        );
        assert_eq!(recoveries.load(Ordering::SeqCst), 1);
    }
}
