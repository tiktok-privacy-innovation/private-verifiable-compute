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

use crate::{ApiError, ApiResponse};
use anyhow::Result;
pub use reqwest;
use reqwest::IntoUrl;
pub use reqwest::{
    Body, Response, StatusCode,
    header::{HeaderMap, HeaderValue},
};
use serde::de::DeserializeOwned;

/// A wrapper around `reqwest::Client`
#[derive(Clone)]
pub struct HttpClient {
    client: reqwest::Client,
}

impl Default for HttpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpClient {
    /// Create a new client pre-initialised with an API token.
    pub fn new() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }

    /// Perform a HTTP GET request, returning the `Response` for further processing.
    pub async fn get_with_raw_response<U: IntoUrl>(
        &self,
        url: U,
        headers: Option<HeaderMap>,
    ) -> Result<Response, ApiError> {
        let mut builder = self.client.get(url);
        builder = match headers {
            Some(h) => builder.headers(h),
            None => builder,
        };
        let response = builder.send().await?;
        Ok(response)
    }

    pub async fn get<U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        headers: Option<HeaderMap>,
    ) -> Result<Option<V>, ApiError> {
        let response = self.get_with_raw_response(url, headers).await?;
        let body = response.bytes().await?;
        let api_resp: ApiResponse<V> = serde_json::from_slice(&body)?;
        api_resp.data()
    }

    /// Perform a HTTP POST request.
    pub async fn post_with_raw_response<U: IntoUrl>(
        &self,
        url: U,
        body: &[u8],
        headers: Option<HeaderMap>,
    ) -> Result<Response, ApiError> {
        let mut builder = self.client.post(url);
        builder = match headers {
            Some(h) => builder.headers(h),
            None => builder,
        };
        let response = builder.body(body.to_vec()).send().await?;
        Ok(response)
    }

    pub async fn post<U: IntoUrl, V: DeserializeOwned>(
        &self,
        url: U,
        body: &[u8],
        headers: Option<HeaderMap>,
    ) -> Result<Option<V>, ApiError> {
        let response = self.post_with_raw_response(url, body, headers).await?;
        let body = response.bytes().await?;
        let api_resp: ApiResponse<V> = serde_json::from_slice(&body)?;
        api_resp.data()
    }
}
