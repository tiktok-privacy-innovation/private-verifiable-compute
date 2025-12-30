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

use crate::OauthValidator;
use anyhow::Result;
use async_trait::async_trait;
use openidconnect::IdTokenVerifier;
use openidconnect::core::{CoreIdToken, CoreProviderMetadata};
use openidconnect::reqwest::Client;
use openidconnect::{ClientId, IssuerUrl, Nonce, NonceVerifier};
use std::str::FromStr;
use tracing::info;

pub struct GoogleOauthValidator {
    issuer: String,
    client_id: String,
}

impl GoogleOauthValidator {
    pub fn new() -> Self {
        GoogleOauthValidator {
            issuer: "https://accounts.google.com".to_string(),
            client_id: get_google_oauth_client_id(),
        }
    }
}

pub struct GoogleNonceVerifier;

impl NonceVerifier for GoogleNonceVerifier {
    fn verify(self, _nonce: Option<&Nonce>) -> Result<(), String> {
        // skip nonce verification
        Ok(())
    }
}

#[async_trait]
impl OauthValidator for GoogleOauthValidator {
    async fn validate(&self, token: &str) -> Result<()> {
        let issuer = IssuerUrl::new(self.issuer.to_string())?;
        let client = Client::new();
        let provider_metadata =
            CoreProviderMetadata::discover_async(issuer.clone(), &client).await?;
        let client_id = ClientId::new(self.client_id.clone());
        let verifier = IdTokenVerifier::new_public_client(
            client_id.clone(),
            issuer,
            provider_metadata.jwks().clone(),
        );
        let id_token: CoreIdToken = CoreIdToken::from_str(token)?;
        id_token.claims(&verifier, GoogleNonceVerifier {})?;
        info!("verified google id token");
        Ok(())
    }
}

pub fn get_google_oauth_client_id() -> String {
    match std::env::var("GOOGLE_OAUTH_CLIENT_ID") {
        Ok(val) if !val.trim().is_empty() => val,
        _ => panic!("Oauth type set to google but oauth client id is not set"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_google_validate() {
        unsafe {
            std::env::set_var(
                "GOOGLE_OAUTH_CLIENT_ID",
                "1017976384424-01ohh9vc4hb7to02jop4uorajepkhn2n.apps.googleusercontent.com",
            );
        }
        let google = GoogleOauthValidator::new();
        assert!(google.validate("").await.is_err());
    }
}
