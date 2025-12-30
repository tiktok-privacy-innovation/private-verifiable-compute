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

use anyhow::{Error, Result};
use async_trait::async_trait;
use google::GoogleOauthValidator;
use std::str::FromStr;

mod google;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OauthType {
    Google,
    Disable,
}

impl FromStr for OauthType {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "google" => Ok(OauthType::Google),
            "disable" | "off" | "" => Ok(OauthType::Disable),
            _ => Ok(OauthType::Disable),
        }
    }
}

#[async_trait]
pub trait OauthValidator: Send {
    async fn validate(&self, token: &str) -> Result<()>;
}

pub struct DisabledOauthValidator;
#[async_trait]
impl OauthValidator for DisabledOauthValidator {
    async fn validate(&self, _token: &str) -> Result<()> {
        Ok(())
    }
}

pub fn get_oauth_type() -> OauthType {
    match std::env::var("OAUTH_TYPE") {
        Ok(val) if !val.trim().is_empty() => val.parse().unwrap(),
        _ => OauthType::Disable,
    }
}

pub fn get_oauth_validator() -> Box<dyn OauthValidator> {
    match get_oauth_type() {
        OauthType::Google => Box::new(GoogleOauthValidator::new()),
        OauthType::Disable => Box::new(DisabledOauthValidator),
    }
}
