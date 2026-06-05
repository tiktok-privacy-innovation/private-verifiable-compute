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

use crate::config::ProfileOverrides;
use crate::output::OutputMode;
use crate::session::StoredSession;
use anyhow::{Result, anyhow};
use pvc_client_core::{Claim, PvcClient};
use serde_json::{Value, json};

#[derive(Debug, Clone)]
pub struct AttestCommand {
    pub overrides: ProfileOverrides,
    pub nonce: Option<String>,
    pub output: OutputMode,
}

pub async fn run(command: AttestCommand) -> Result<()> {
    let session = StoredSession::load()?.ok_or_else(|| anyhow!("run `pvc-cli login` first"))?;
    let profile = session.profile.merged_with(&command.overrides);
    let auth_token = session.auth_token()?.map(str::to_owned);
    let mut client = PvcClient::from_config(&profile.to_client_config()).await?;
    let claims = client.attest(command.nonce.clone(), auth_token).await?;
    let payload = build_attestation_payload(
        &profile.target_url,
        command.nonce.is_some(),
        client.session_id(),
        &claims,
    );

    match command.output {
        OutputMode::Human => {
            println!("Attestation verified for {}", profile.target_url);
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        OutputMode::Json => println!("{}", serde_json::to_string_pretty(&payload)?),
    }

    Ok(())
}

fn build_attestation_payload(
    target_url: &str,
    nonce_provided: bool,
    session_id: Option<&str>,
    claims: &Claim,
) -> Value {
    json!({
        "target_url": target_url,
        "verified": true,
        "nonce_provided": nonce_provided,
        "session_id": session_id,
        "claims": claims_to_json(claims),
    })
}

fn claims_to_json(claims: &Claim) -> Value {
    Value::Array(
        claims
            .iter()
            .map(|(claim, source)| {
                json!({
                    "source": source,
                    "claim": claim,
                })
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CliProfile;

    #[test]
    fn claims_to_json_preserves_sources_and_values() {
        let claims = vec![
            (json!({"report_data": "abc"}), "cpu".to_string()),
            (json!({"nonce": "def"}), "gpu".to_string()),
        ];

        let rendered = claims_to_json(&claims);
        assert_eq!(
            rendered,
            json!([
                {"source": "cpu", "claim": {"report_data": "abc"}},
                {"source": "gpu", "claim": {"nonce": "def"}}
            ])
        );
    }

    #[test]
    fn build_attestation_payload_marks_verified_and_nonce() {
        let claims = vec![(json!({"report_data": "abc"}), "cpu".to_string())];

        let payload = build_attestation_payload("localhost:9000", true, Some("sid-1"), &claims);

        assert_eq!(payload["target_url"], "localhost:9000");
        assert_eq!(payload["verified"], true);
        assert_eq!(payload["nonce_provided"], true);
        assert_eq!(payload["session_id"], "sid-1");
        assert_eq!(payload["claims"][0]["source"], "cpu");
    }

    #[test]
    fn build_attestation_payload_handles_missing_session_id() {
        let claims = vec![(json!({"report_data": "abc"}), "cpu".to_string())];

        let payload = build_attestation_payload("localhost:9000", false, None, &claims);

        assert!(payload["session_id"].is_null());
        assert_eq!(payload["nonce_provided"], false);
    }

    #[test]
    fn profile_overrides_are_applied() {
        let profile = CliProfile::default();
        let overrides = ProfileOverrides {
            target_url: Some("example.com:9000".to_string()),
            ..ProfileOverrides::default()
        };

        let merged = profile.merged_with(&overrides);

        assert_eq!(merged.target_url, "example.com:9000");
        assert_eq!(merged.identity_server_url, "http://localhost:8000");
    }
}
