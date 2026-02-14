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

pub mod async_rw;
pub mod http;
pub mod keys;
pub mod utils;

use kbs_types::Tee;
use num_enum::TryFromPrimitive;
use rocket::http::{ContentType, Status};
use rocket::{Request, Response, response::Responder};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt;
use std::io::Cursor;
use tracing::error;

#[derive(Debug, Copy, Clone, TryFromPrimitive, Serialize, Deserialize)]
#[repr(i32)]
pub enum ApiCode {
    Success = 0,
    BadGateway = 502,
    InvalidRequestBody = 10000,
    NonceLengthMismatch = 10001,
    CreateNewSessionFailed = 10002,
    InvalidSessionId = 10003,
    NoiseDecryptFailed = 10004,
    NoiseHandShakeFailed = 10005,
    NoiseEncryptedFailed = 10006,
    InvalidIdentityToken = 10007,
    UnSupportedDocumentFormat = 10008,
    BlindSignFailed = 10009,
    InvalidResponseBody = 10010,
    TeeEvidenceFetchFailed = 20000,
    DeviceEvidenceFetchFailed = 20001,
    UnkownContextEncryptionKey = 20002,
    VectorStoreError = 20003,
    TeeLlmError = 20004,
    UnexpectedError = 20005,
}

impl fmt::Display for ApiCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            ApiCode::Success => "Success",
            ApiCode::BadGateway => "Bad gateway",
            ApiCode::InvalidRequestBody => "Invalid request body",
            ApiCode::NonceLengthMismatch => "Nonce length mismatch",
            ApiCode::CreateNewSessionFailed => "Failed to create new session",
            ApiCode::InvalidSessionId => "Invalid session ID",
            ApiCode::NoiseDecryptFailed => "Noise decrypt failed",
            ApiCode::NoiseEncryptedFailed => "Noise encrypt failed",
            ApiCode::NoiseHandShakeFailed => "Noise handshake failed",
            ApiCode::InvalidIdentityToken => "Invalid identity token",
            ApiCode::UnSupportedDocumentFormat => "Unsupported document format (chunked failed)",
            ApiCode::TeeEvidenceFetchFailed => "TEE evidence fetch failed",
            ApiCode::DeviceEvidenceFetchFailed => "Device evidence fetch failed",
            ApiCode::UnkownContextEncryptionKey => "Unkown context encryption key",
            ApiCode::VectorStoreError => "error happens in vector store",
            ApiCode::TeeLlmError => "error happens in tee llm",
            ApiCode::BlindSignFailed => "failed to blind sign",
            ApiCode::InvalidResponseBody => "invalid response body",
            ApiCode::UnexpectedError => "unexpected error",
        };
        write!(f, "{}", msg)
    }
}

impl<'r> Responder<'r, 'static> for ApiCode {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let response: ApiResponse<()> = ApiResponse {
            code: self as i32,
            message: format!("{}", self),
            data: None,
        };
        let body_bytes = match serde_json::to_vec(&response) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("JSON serialization error: {}", e);
                let error_json =
                    r#"{"code":-1,"message":"Internal Serialization Error","data":null}"#;
                error_json.as_bytes().to_vec()
            }
        };
        Response::build()
            .status(Status::Ok)
            .header(ContentType::JSON)
            .streamed_body(Cursor::new(body_bytes))
            .ok()
    }
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
pub enum ApiResult<T> {
    Ok(T),
    Err(ApiCode),
}

impl<T> ApiResult<T> {
    pub fn success(data: T) -> Self {
        ApiResult::Ok(data)
    }

    pub fn error(code: ApiCode) -> Self {
        ApiResult::Err(code)
    }
}

impl<T> From<Result<T, ApiCode>> for ApiResult<T> {
    fn from(res: Result<T, ApiCode>) -> Self {
        match res {
            Ok(data) => ApiResult::Ok(data),
            Err(code) => ApiResult::Err(code),
        }
    }
}

impl<'r, T: serde::Serialize> Responder<'r, 'static> for ApiResult<T> {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let (api_code, data) = match self {
            ApiResult::Ok(data) => (ApiCode::Success, Some(data)),
            ApiResult::Err(code) => (code, None),
        };
        let response = ApiResponse {
            code: api_code as i32,
            message: format!("{}", api_code),
            data,
        };
        let body_bytes = match serde_json::to_vec(&response) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("JSON serialization error: {}", e);
                let error_json =
                    r#"{"code":-1,"message":"Internal Serialization Error","data":null}"#;
                error_json.as_bytes().to_vec()
            }
        };
        Response::build()
            .status(Status::Ok)
            .header(ContentType::JSON)
            .sized_body(body_bytes.len(), Cursor::new(body_bytes))
            .ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub code: i32,
    pub message: String,
    pub data: Option<T>,
}

impl<T: serde::Serialize> ApiResponse<T> {
    pub fn to_vec(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> ApiResponse<T> {
        Self {
            code: 0,
            message: String::new(),
            data: Some(data),
        }
    }

    pub fn error(code: i32, message: impl Into<String>) -> ApiResponse<T> {
        ApiResponse {
            code: code,
            message: message.into(),
            data: None,
        }
    }

    pub fn ok(self) -> Result<(), ApiError> {
        if self.code == ApiCode::Success {
            Ok(())
        } else {
            Err(ApiError::BackendError {
                code: self.code,
                message: self.message,
            })
        }
    }

    pub fn data(self) -> Result<Option<T>, ApiError> {
        if self.code == 0 {
            Ok(self.data)
        } else {
            Err(ApiError::BackendError {
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

#[derive(Serialize, Deserialize, Debug)]
pub struct InferenceResp {
    pub content: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EmptyResp {}

#[derive(thiserror::Error, Debug)]
pub enum ApiError {
    #[error("http error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("response decode error: {0}")]
    DecodedError(#[from] serde_json::Error),
    #[error("backend error code={code}, message={message}")]
    BackendError { code: i32, message: String },
    #[error("missing data field on response")]
    MissingData,
    #[error("unkown error type")]
    UnkownError,
}

impl From<anyhow::Error> for ApiError {
    fn from(res: anyhow::Error) -> Self {
        match res.downcast::<ApiError>() {
            Ok(api_error) => api_error,
            Err(_) => ApiError::UnkownError,
        }
    }
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
