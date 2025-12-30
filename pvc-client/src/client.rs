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
use identity::IdentityClient;
use noise::{NoiseNnInitiator, NoiseNnTransport};
use ohttp_wrap::{ClientRequest, ClientResponse, KeyConfig, Message, Mode, OhttpClient};
use p256::ecdsa::{Signature, signature::Verifier};
use serde::de::DeserializeOwned;
use serde_json::Value;
use types::http::{HttpClient, Response};
use types::keys::decode_verifying_key;
use types::keys::{BlindMessageRequest, BlindMessageResponse, EncryptionKey, PublicKeyFields};
use types::{
    ApiResponse, EmptyResp, HandShakeResp, InferenceResp, UploadDocumentReq, UploadDocumentResp,
};
use types::{
    AttestationResponse,
    http::reqwest::{
        IntoUrl, Url,
        header::{AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue},
    },
};
#[cfg(feature = "attestation")]
use verifier::{InitDataHash, ReportData as TeeReportData, to_verifier};

const HANDSHAKE_PATH: &str = "/handshake/noise";
const INFERENCE_PATH: &str = "/inference";
const ATTESTATION_PATH: &str = "/attestation";
const ATTESTATION_WITH_NONCE_PATH: &str = "/attestation/nonce";
const UPLOAD_KEY_PATH: &str = "/key/upload";
const UPLOAD_DOCUMENT_PATH: &str = "/document/upload";
const NVIDIA_NONCE_SIZE: usize = 32;
pub type Claim = Vec<(Value, String)>;

pub struct PvcClient {
    identity_server_url: Url,
    relay_url: Url,
    target_url: String,
    http_client: HttpClient,
    ohttp_key_config: KeyConfig,
    session_id: Option<String>,
    noise_transport: Option<NoiseNnTransport>,
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
        })
    }

    pub async fn handshake_with_attestation(&mut self, id_token: Option<String>) -> Result<()> {
        let claims = self.attest(None, id_token.clone()).await?;
        let verifying_key = crate::server::extract_report_data(&claims);
        self.noise_with_ohttp(verifying_key, id_token).await?;
        Ok(())
    }

    pub async fn attest(
        &mut self,
        nonce: Option<String>,
        id_token: Option<String>,
    ) -> Result<Claim> {
        let (_msg, token) = self.get_identity_token(id_token).await?;
        let mut handshake_header = HeaderMap::new();
        handshake_header.insert("X-Identity-Token", HeaderValue::from_str(&token)?);
        handshake_header.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );

        if let Some(sid) = &self.session_id {
            handshake_header.insert("X-Session-Id", HeaderValue::from_str(sid)?);
        }

        let resp: AttestationResponse = match &nonce {
            Some(nonce) => {
                self.ohttp_post(
                    &self.target_url,
                    ATTESTATION_WITH_NONCE_PATH,
                    Some(handshake_header),
                    Some(nonce.as_bytes().to_vec()),
                )
                .await?
            }
            None => {
                self.ohttp_post(
                    &self.target_url,
                    ATTESTATION_PATH,
                    Some(handshake_header),
                    None,
                )
                .await?
            }
        };

        let claim = {
            #[cfg(feature = "attestation")]
            {
                let (cpu_report_data, gpu_report_data) = match &nonce {
                    Some(n) => {
                        let decoded_nonce = BASE64_STANDARD.decode(n)?;
                        assert!(decoded_nonce.len() >= NVIDIA_NONCE_SIZE);
                        (
                            TeeReportData::Value(&decoded_nonce.clone()),
                            TeeReportData::Value(&decoded_nonce.clone()[0..NVIDIA_NONCE_SIZE]),
                        )
                    }
                    None => (TeeReportData::NotProvided, TeeReportData::NotProvided),
                };

                let verifier = to_verifier(&resp.tee_type, None).await.unwrap();
                let mut claim = verifier
                    .evaluate(resp.evidence, &cpu_report_data, &InitDataHash::NotProvided)
                    .await?;
                info!("device tee num: {:?}", resp.device_evidences);
                if let Some((key, evidence)) = resp.device_evidences {
                    let json_data = r#"{
                        "nvidia_verifier": {
                            "verifier": {
                                "Remote": {
                                    "verifier_url": "https://nras.attestation.nvidia.com/v4/attest"
                                }
                            }
                        }
                    }"#;
                    let config: verifier::VerifierConfig = serde_json::from_str(json_data).unwrap();
                    let device_verifier = to_verifier(&key, Some(config)).await.unwrap();
                    match device_verifier
                        .evaluate(
                            evidence.clone(),
                            &gpu_report_data,
                            &InitDataHash::NotProvided,
                        )
                        .await
                    {
                        Ok(mut device_claim) => {
                            claim.append(&mut device_claim);
                        }
                        Err(e) => {
                            error!("failed to verify device evidence {:?}", e)
                        }
                    };
                }
                claim
            }

            #[cfg(not(feature = "attestation"))]
            {
                let mut claim = Vec::new();
                claim.push((resp.evidence, "cpu".to_string()));
                claim
            }
        };

        if self.session_id.is_none() && resp.sid.is_some() {
            self.session_id = resp.sid;
        }
        Ok(claim)
    }

    pub async fn noise_with_ohttp(
        &mut self,
        verifying_key: [u8; 64],
        id_token: Option<String>,
    ) -> Result<()> {
        let (_msg, token) = self.get_identity_token(id_token).await?;
        // noise protocol over ohttp
        let mut noise_initiator =
            NoiseNnInitiator::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap(), None)?;

        let mut handshake_header = HeaderMap::new();
        handshake_header.insert("X-Identity-Token", HeaderValue::from_str(&token)?);
        handshake_header.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );

        if let Some(sid) = &self.session_id {
            handshake_header.insert("X-Session-Id", HeaderValue::from_str(sid)?);
        }

        let ephemeral = noise_initiator.generate_ephemeral()?;
        let encoded_noise_initiator = BASE64_STANDARD.encode(&ephemeral);
        let resp: HandShakeResp = self
            .ohttp_post(
                &self.target_url,
                HANDSHAKE_PATH,
                Some(handshake_header),
                Some(encoded_noise_initiator.as_bytes().to_vec()),
            )
            .await?;

        verify_noise_script_signature(verifying_key, &ephemeral, &resp.data, &resp.signature)?;

        let tp = noise_initiator.recv_response(&resp.data)?;
        self.noise_transport = Some(tp);
        Ok(())
    }

    fn encrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if let Some(t) = &mut self.noise_transport {
            t.encrypt(message)
        } else {
            Err(anyhow!("noise transport is none, internal error happens"))
        }
    }

    fn decrypt_message(&mut self, message: &[u8]) -> Result<Vec<u8>> {
        if let Some(t) = &mut self.noise_transport {
            t.decrypt(message)
        } else {
            Err(anyhow!("noise transport is none, internal error happens"))
        }
    }

    pub async fn request_inference(&mut self, input: &str) -> Result<String> {
        let encrypted = self.encrypt_message(input.as_bytes())?;
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(sid) = &self.session_id {
            headers.insert("X-Session-Id", HeaderValue::from_str(sid)?);
        }

        let encoded_encrypted_message = BASE64_STANDARD.encode(encrypted);

        let resp: InferenceResp = self
            .ohttp_post(
                &self.target_url,
                INFERENCE_PATH,
                Some(headers),
                Some(encoded_encrypted_message.as_bytes().to_vec()),
            )
            .await?;

        let decrypted_resp = self.decrypt_message(&resp.content)?;
        let res: String = String::from_utf8(decrypted_resp).unwrap();
        Ok(res)
    }

    pub async fn upload_encryption_key(&mut self, session_key: &EncryptionKey) -> Result<()> {
        let encrypted = self.encrypt_message(&session_key.0)?;
        let headers = self.generate_header();
        let encoded_encrypted_message = BASE64_STANDARD.encode(encrypted);

        let _: EmptyResp = self
            .ohttp_post(
                &self.target_url,
                UPLOAD_KEY_PATH,
                Some(headers),
                Some(encoded_encrypted_message.as_bytes().to_vec()),
            )
            .await?;
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
        let _: UploadDocumentResp = self
            .ohttp_post(
                &self.target_url,
                UPLOAD_DOCUMENT_PATH,
                Some(headers),
                Some(encrypted),
            )
            .await?;
        Ok(())
    }

    async fn get_identity_token(
        &self,
        id_token: Option<String>,
    ) -> anyhow::Result<(Vec<u8>, String)> {
        // Step 1: Fetch public key from identity server
        let pk: BlindPublicKey = self.fetch_public_key().await?;

        // Step 2: Generate full domain hashed message for blind signature
        let msg = vec![0; 20];

        let blinder = RsaBlinder {};
        // Step 3: Blind the message
        let state = blinder
            .blind(&msg, pk.clone())
            .context("Failed to blind message")?;
        let blinded_msg = state.blinded_message()?;

        // Step 4: Request blind signature
        let blind_sig_bytes = self
            .request_blind_signature(&blinded_msg, id_token)
            .await
            .context("Failed to request blind signature")?;

        // Step 5: Verify the signature
        let sig = blinder
            .verify(&blind_sig_bytes, &state, pk)
            .context("Failed to verify unblind signature")?;

        // Step 6: Encode signature to token
        let token = BASE64_STANDARD.encode(&sig);

        Ok((msg, token))
    }

    fn generate_header(&self) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/octet-stream"),
        );
        if let Some(sid) = &self.session_id {
            headers.insert("X-Session-Id", HeaderValue::from_str(sid).unwrap());
        }
        headers
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
            .await?;
        let pk = BlindPublicKey {
            n: BASE64_STANDARD.decode(&resp.n)?,
            e: BASE64_STANDARD.decode(&resp.e)?,
        };
        Ok(pk)
    }

    // todo: use self-defined struct
    async fn request_blind_signature(
        &self,
        blinded_message: &[u8],
        id_token: Option<String>,
    ) -> Result<Vec<u8>> {
        let body = BlindMessageRequest {
            blinded_message: BASE64_STANDARD.encode(blinded_message),
        };
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(id_token) = id_token {
            headers.insert(
                AUTHORIZATION,
                format!("Bearer {}", id_token).parse().unwrap(),
            );
        }
        let bode_bytes = serde_json::to_string(&body)?;
        let resp: BlindMessageResponse = self
            .http_client
            .post(
                self.identity_server_url.join("sign")?,
                bode_bytes.as_bytes(),
                Some(headers),
            )
            .await?;
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
        let key_config: KeyConfig = KeyConfig::decode(&cfg_bytes)?;
        Ok(key_config)
    }

    async fn ohttp_post<V: DeserializeOwned>(
        &self,
        target_server: &str,
        path: &str,
        headers: Option<HeaderMap>,
        body: Option<Vec<u8>>,
    ) -> Result<V> {
        // create http request
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

        let (enc_request, ohttp_response) = req.encapsulate(&request_buf)?;

        let mut outer_headers: HeaderMap = HeaderMap::new();
        outer_headers.insert(CONTENT_TYPE, "message/ohttp-req".parse().unwrap());
        let resp = self
            .http_client
            .post_with_raw_response(self.relay_url.clone(), &enc_request, Some(outer_headers))
            .await?
            .error_for_status()?;

        let res = decapsulate_response(resp, ohttp_response).await?;
        let api_resp: ApiResponse<V> = serde_json::from_slice(&res)?;
        api_resp
            .into_data_or()
            .map_err(|_| anyhow!("failed to parse api response"))
    }
}

/// Decapsulate the http response
async fn decapsulate_response(
    response: Response,
    client_response: ClientResponse,
) -> Result<Vec<u8>> {
    let enc_response = response.bytes().await?;
    let response_buf = client_response.decapsulate(&enc_response)?;
    let response = Message::read_bhttp(&mut std::io::Cursor::new(&response_buf[..]))?;
    let body = response.content();
    Ok(body.to_vec())
}

#[cfg(test)]
mod tests {}
