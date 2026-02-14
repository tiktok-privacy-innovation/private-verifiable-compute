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

use rocket::http::{ContentType, Status};
use rocket::{Request, Response, response::Responder};
use std::io::Cursor;
use types::ApiError;
use types::{ApiCode, ApiResponse};

#[derive(Debug)]
pub enum ServerResponse<T> {
    Ok(T),
    Err(ApiError),
}

impl<'r, T: serde::Serialize> Responder<'r, 'static> for ServerResponse<T> {
    fn respond_to(self, _req: &'r Request<'_>) -> rocket::response::Result<'static> {
        let (status_code, body_bytes) = match self {
            ServerResponse::Ok(data) => (Status::Ok, ApiResponse::success(data).to_vec()),
            ServerResponse::Err(api_error) => match api_error {
                ApiError::HttpError(_) => (
                    Status::BadGateway,
                    ApiResponse::<()>::error(
                        ApiCode::BadGateway as i32,
                        "failed to send http request",
                    )
                    .to_vec(),
                ),
                ApiError::DecodedError(_) => (
                    Status::BadRequest,
                    ApiResponse::<()>::error(
                        ApiCode::InvalidResponseBody as i32,
                        "failed to decode response body",
                    )
                    .to_vec(),
                ),
                ApiError::BackendError { code, message } => {
                    (Status::Ok, ApiResponse::<()>::error(code, message).to_vec())
                }
                ApiError::MissingData => (
                    Status::Ok,
                    ApiResponse::<()>::error(
                        ApiCode::InvalidResponseBody as i32,
                        "miss response data",
                    )
                    .to_vec(),
                ),
                ApiError::UnkownError => (
                    Status::InternalServerError,
                    ApiResponse::<()>::error(
                        ApiCode::UnexpectedError as i32,
                        "unexpected error type",
                    )
                    .to_vec(),
                ),
            },
        };
        Response::build()
            .status(status_code)
            .header(ContentType::JSON)
            .sized_body(body_bytes.len(), Cursor::new(body_bytes))
            .ok()
    }
}

impl<T> From<Result<T, ApiError>> for ServerResponse<T> {
    fn from(res: Result<T, ApiError>) -> Self {
        match res {
            Ok(data) => ServerResponse::Ok(data),
            Err(e) => ServerResponse::Err(e),
        }
    }
}
