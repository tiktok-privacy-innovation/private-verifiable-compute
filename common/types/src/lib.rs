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

pub mod http;
pub mod keys;
pub mod utils;
use kbs_types::Tee;
use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{Request, Response, response::Responder};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Copy, Clone)]
pub enum ApiCode {
    Success = 0,
    BadRequest = 400,
    InternalServerError = 500,
}

impl PartialEq<i32> for ApiCode {
    fn eq(&self, other: &i32) -> bool {
        (*self as i32) == *other
    }
}

impl PartialEq<ApiCode> for i32 {
    fn eq(&self, other: &ApiCode) -> bool {
        *self == (*other as i32)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub message: String,
    pub data: Option<T>,
}

pub fn new_err(code: ApiCode, message: impl Into<String>) -> ApiResponse<()> {
    ApiResponse {
        code: code as i32,
        message: message.into(),
        data: None,
    }
}

impl<'r> Responder<'r, 'static> for ApiResponse<()> {
    fn respond_to(self, req: &'r Request<'_>) -> rocket::response::Result<'static> {
        Response::build_from(Json(self).respond_to(req)?)
            .status(Status::Ok)
            .ok()
    }
}

impl<T> ApiResponse<T> {
    pub fn ok(self) -> Result<(), ApiError> {
        if self.code == ApiCode::Success {
            Ok(())
        } else {
            Err(ApiError::InternalError {
                code: self.code,
                message: self.message,
            })
        }
    }

    pub fn into_data_or(self) -> Result<T, ApiError> {
        if self.code == 0 {
            self.data.ok_or(ApiError::MissingData)
        } else {
            Err(ApiError::InternalError {
                code: self.code,
                message: self.message,
            })
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct HandShakeResp {
    pub data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct EmptyResp {}

#[derive(Serialize, Deserialize, Debug)]
pub struct InferenceResp {
    pub content: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("non-success http status: {0}")]
    HttpStatus(reqwest::StatusCode),
    #[error("json decode error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("business error code={code}, message={message}")]
    InternalError { code: i32, message: String },
    #[error("missing data field on success")]
    MissingData,
}

pub type ReportData = [u8; 64];

#[derive(Serialize, Deserialize)]
pub struct AttestationResponse {
    pub tee_type: Tee,
    pub evidence: Value,
    pub device_evidences: Option<(Tee, Value)>,
    pub sid: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct UploadDocumentReq {
    pub filename: String,
    pub content: String,
}

#[derive(Serialize, Deserialize)]
pub struct UploadDocumentResp {}
