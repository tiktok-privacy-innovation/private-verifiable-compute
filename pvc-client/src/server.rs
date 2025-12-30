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
use anyhow::Result;
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use rocket::State;
use rocket::form::Form;
use rocket::fs::TempFile;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;
use types::ReportData;
use types::{ApiCode, ApiResponse};

#[derive(Serialize, Deserialize, Debug)]
pub struct BackendResp {
    pub content: String,
}

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
) -> Result<Json<ApiResponse<Value>>, Status> {
    let req: AttestationRequest = serde_json::from_str(&payload).map_err(|_| Status::BadRequest)?;

    let mut pvc_client = client.write().await;
    let response = pvc_client
        .attest(Some(req.nonce), oauth_token.read().await.clone())
        .await
        .map_err(|_| Status::InternalServerError)?;
    info!("{:?}", response);
    let cpu_claim = extract_cpu(&response);
    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: String::new(),
        data: Some(cpu_claim),
    }))
}

#[post("/inference", data = "<payload>")]
pub async fn inference(
    client: &State<Arc<RwLock<PvcClient>>>,
    payload: String,
) -> Result<Json<ApiResponse<BackendResp>>, Status> {
    let mut pvc_client = client.write().await;
    let response = pvc_client
        .request_inference(&payload)
        .await
        .map_err(|_| Status::InternalServerError)?;

    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: String::new(),
        data: Some(BackendResp { content: response }),
    }))
}

#[post("/upload", data = "<form>")]
pub async fn upload(
    form: Form<Upload<'_>>,
    client: &State<Arc<RwLock<PvcClient>>>,
) -> Result<Json<ApiResponse<BackendResp>>, Status> {
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
        .await
        .map_err(|e| {
            error!("failed to upload knowledge document {:?}", e);
            Status::InternalServerError
        })?;
    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: "File uploaded successfully".to_string(),
        data: None,
    }))
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
