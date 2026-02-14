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

use crate::client::Claim;
use crate::client::PvcClient;
use types::ReportData;

use crate::resp::ServerResponse;
use anyhow::Result;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use futures::StreamExt;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rocket::data::{Data, ToByteUnit};
use rocket::form::Form;
use rocket::fs::TempFile;
use rocket::http::Status;
use rocket::response::stream::TextStream;
use rocket::serde::{Deserialize, Serialize};
use rocket::{Request, State, request::FromRequest};
use std::str::FromStr;
use tokio::io::AsyncReadExt;

use serde_json::{Value, json};
use std::sync::Arc;
use tracing::{error, info};

use tokio::sync::RwLock;
use types::ApiError;

#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationRequest {
    pub nonce: String,
}

#[derive(FromForm)]
pub struct Upload<'f> {
    file: TempFile<'f>,
}

#[get("/health")]
pub fn health() -> &'static str {
    "ok"
}

#[post("/attestation", data = "<payload>")]
pub async fn attestation(
    client: &State<Arc<RwLock<PvcClient>>>,
    payload: String,
    oauth_token: &State<Arc<RwLock<Option<String>>>>,
) -> ServerResponse<Value> {
    let logic = async || -> Result<Value, ApiError> {
        let req: AttestationRequest = serde_json::from_str(&payload)?;
        let mut pvc_client = client.write().await;
        let response = pvc_client
            .attest(Some(req.nonce), oauth_token.read().await.clone())
            .await?;
        info!("{:?}", response);
        Ok(extract_cpu(&response))
    };

    logic().await.into()
}

#[derive(Debug, Clone)]
pub struct RequestHeaders(pub HeaderMap);

#[async_trait]
impl<'r> FromRequest<'r> for RequestHeaders {
    type Error = ();

    async fn from_request(request: &'r Request<'_>) -> rocket::request::Outcome<Self, Self::Error> {
        let mut h = HeaderMap::new();
        let headers = request.headers();

        let header_pairs: Vec<(String, String)> = headers
            .iter()
            .map(|kv| (kv.name().as_str().to_string(), kv.value().to_string()))
            .collect();

        for (name, value) in header_pairs {
            if let Ok(header_name) = HeaderName::from_str(&name) {
                if header_name != "Authorization" {
                    continue;
                }
                if let Ok(header_value) = HeaderValue::from_str(&value) {
                    h.insert(header_name, header_value);
                }
            }
        }

        rocket::request::Outcome::Success(RequestHeaders(h))
    }
}

#[post("/chat/completions", format = "application/json", data = "<raw_body>")]
pub async fn chat_completions(
    client: &State<Arc<RwLock<PvcClient>>>,
    headers: RequestHeaders,
    raw_body: Data<'_>,
) -> Result<TextStream![String], Status> {
    let mut buffer = Vec::new();
    raw_body
        .open(50.mebibytes())
        .read_to_end(&mut buffer)
        .await
        .map_err(|e| {
            error!("Failed to read request body: {}", e);
            // Check if error is due to size limit
            if e.to_string().contains("limit")
                || e.to_string().contains("size")
                || e.to_string().contains("exceed")
            {
                Status::PayloadTooLarge
            } else {
                Status::BadRequest
            }
        })?;

    let mut pvc_client = client.write().await;
    let stream = pvc_client
        .chat_completions(Some(&headers.0), buffer.as_slice())
        .await
        .map_err(|e| {
            error!("Failed to chat: {}", e);
            Status::InternalServerError
        })?;

    let stream = stream.scan(false, |error_occurred, b| {
        if *error_occurred {
            return std::future::ready(None);
        }

        match b {
            Ok(text) => std::future::ready(Some(text)),
            Err(e) => {
                *error_occurred = true;
                error!("Error occurred during processing");
                let error_json = serde_json::json!({
                    "error": {
                        "message": e.to_string(),
                        "type": "api_error",
                        "param": Value::Null,
                        "code": Value::Null
                    }
                });
                std::future::ready(Some(error_json.to_string()))
            }
        }
    });

    Ok(TextStream::from(stream))
}

#[post("/upload", data = "<form>")]
pub async fn upload(
    form: Form<Upload<'_>>,
    client: &State<Arc<RwLock<PvcClient>>>,
) -> ServerResponse<()> {
    let logic = async || -> Result<(), ApiError> {
        let mut form = form.into_inner();
        let filename = match form.file.name() {
            Some(name) => name.to_string(),
            None => "unnamed_file".to_string(),
        };
        let tmp_path = std::env::temp_dir().join(&filename);
        form.file.persist_to(&tmp_path).await.unwrap();

        let content = std::fs::read_to_string(&tmp_path).unwrap();
        let mut client = client.write().await;

        client
            .upload_knowledge_document(&filename, &content)
            .await?;
        Ok(())
    };
    logic().await.into()
}

fn extract_cpu(claims: &Claim) -> Value {
    let cpu = claims
        .iter()
        .find(|(_val, key)| key == "cpu")
        .map(|(val, _key)| val)
        .unwrap()
        .clone();
    let gpu = claims
        .iter()
        .find(|(_val, key)| key == "gpu")
        .map(|(val, _key)| val);
    match gpu {
        Some(gpu) => json!({ "cpu": cpu, "gpu": gpu }),
        None => json!({ "cpu": cpu}),
    }
}

pub fn extract_report_data(claims: &Claim) -> ReportData {
    claims
        .iter()
        .for_each(|(value, key)| info!("{}:{}", key, value.to_string()));
    let cpu = claims
        .iter()
        .find(|(_val, key)| key == "cpu")
        .map(|(val, _key)| val)
        .unwrap();
    let report_data_str = cpu["report_data"].as_str().unwrap();
    info!("{}", report_data_str);
    match hex::decode(report_data_str) {
        Ok(r) => r.try_into().unwrap(),
        Err(_) => BASE64_STANDARD
            .decode(report_data_str)
            .unwrap()
            .try_into()
            .unwrap(),
    }
}
