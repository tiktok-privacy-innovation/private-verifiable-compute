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
use blind_rsa::BlindPublicKey;
#[async_trait]
pub trait IdentityClient {
    /// Fetch RSA public key and algorithm params from remote Identity Server.
    async fn fetch_public_key(&self) -> Result<BlindPublicKey>;
    /// Request a blind signature for a blinded message.
    async fn request_blind_signature(
        &self,
        blinded_message: &[u8],
        id_token: Option<String>,
    ) -> Result<Vec<u8>>;
}
