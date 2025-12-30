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

use anyhow::Result;
use async_trait::async_trait;
pub use bhttp::{Message, Mode};
pub use ohttp::Error;
pub use ohttp::{ClientRequest, ClientResponse, KeyConfig};
use reqwest::IntoUrl;
use reqwest::header::HeaderMap;
use serde::de::DeserializeOwned;
#[async_trait]
pub trait OhttpClient {
    async fn ohttp_initialize<U>(ohttp_gateway_url: U) -> Result<KeyConfig>
    where
        U: IntoUrl + Send;
    async fn ohttp_post<V: DeserializeOwned>(
        &self,
        target_server: &str,
        path: &str,
        headers: Option<HeaderMap>,
        body: Option<Vec<u8>>,
    ) -> Result<V>;
}
