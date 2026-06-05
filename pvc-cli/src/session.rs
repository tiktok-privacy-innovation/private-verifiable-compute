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

use crate::config::CliProfile;
use anyhow::{Result, anyhow};
use pvc_client_core::{
    IdTokenProvider, PvcClient, StaticIdToken, create_or_get_encryption_key, pvc_home_dir,
    read_json_file, remove_file_if_exists, write_private_json_file,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StoredAuth {
    Token { value: String },
    InteractivePending,
}

impl StoredAuth {
    pub fn redacted_json(&self) -> Value {
        match self {
            Self::Token { .. } => json!({
                "type": "token",
                "value": "[REDACTED]",
            }),
            Self::InteractivePending => json!({
                "type": "interactive_pending",
            }),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredSession {
    pub profile: CliProfile,
    pub auth: StoredAuth,
    pub session_id: Option<String>,
    pub last_bootstrap_unix_seconds: u64,
    pub last_command: String,
}

impl StoredSession {
    pub fn load() -> Result<Option<Self>> {
        read_json_file(&session_path()?)
    }

    pub fn save(&self) -> Result<()> {
        write_private_json_file(&session_path()?, self)
    }

    pub fn clear() -> Result<()> {
        remove_file_if_exists(&session_path()?)
    }

    pub fn auth_token(&self) -> Result<Option<&str>> {
        match &self.auth {
            StoredAuth::Token { value } => Ok(Some(value.as_str())),
            StoredAuth::InteractivePending => Err(anyhow!(
                "interactive login is not supported yet; run `pvc-cli login` with --token, --token-env-var, or --token-stdin"
            )),
        }
    }

    pub fn redacted_json(&self) -> Value {
        json!({
            "profile": self.profile,
            "auth": self.auth.redacted_json(),
            "session_id": self.session_id,
            "last_bootstrap_unix_seconds": self.last_bootstrap_unix_seconds,
            "last_command": self.last_command,
        })
    }

    pub async fn bootstrap_client(&self) -> Result<PvcClient> {
        let auth_token = self.auth_token()?.map(str::to_owned);
        let mut client = PvcClient::from_config(&self.profile.to_client_config()).await?;
        // Inject the disk-loaded token so the recovery path inside
        // `chat_completions` (after a tee-llm restart) re-handshakes with
        // the same credentials this CLI invocation was bootstrapped with,
        // matching the long-running pvc-client behavior.
        client.set_id_token_provider(Arc::new(StaticIdToken(auth_token.clone())));
        let key = create_or_get_encryption_key()?;
        client.handshake_with_attestation(auth_token).await?;
        client.upload_encryption_key(&key).await?;
        Ok(client)
    }

    pub async fn bootstrap_and_refresh(&self, command: &str) -> Result<(PvcClient, Self)> {
        let client = self.bootstrap_client().await?;
        let refreshed = self.refreshed(client.session_id().map(str::to_owned), command);
        Ok((client, refreshed))
    }

    pub fn refreshed(&self, session_id: Option<String>, command: impl Into<String>) -> Self {
        Self {
            profile: self.profile.clone(),
            auth: self.auth.clone(),
            session_id,
            last_bootstrap_unix_seconds: now_unix_seconds(),
            last_command: command.into(),
        }
    }
}

pub fn now_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn session_path() -> Result<PathBuf> {
    Ok(pvc_home_dir()?.join("cli").join("session.json"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_session(auth: StoredAuth) -> StoredSession {
        StoredSession {
            profile: CliProfile::default(),
            auth,
            session_id: Some("session-1".to_string()),
            last_bootstrap_unix_seconds: 42,
            last_command: "chat".to_string(),
        }
    }

    #[test]
    fn interactive_pending_auth_is_rejected() {
        let session = sample_session(StoredAuth::InteractivePending);

        let error = session.auth_token().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("interactive login is not supported yet")
        );
    }

    #[test]
    fn redacted_json_hides_token_value() {
        let session = sample_session(StoredAuth::Token {
            value: "super-secret-token".to_string(),
        });

        let rendered = session.redacted_json().to_string();
        assert!(!rendered.contains("super-secret-token"));
        assert!(rendered.contains("[REDACTED]"));
    }
}
