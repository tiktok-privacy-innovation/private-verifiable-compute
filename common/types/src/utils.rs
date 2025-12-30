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

use std::env;

pub fn get_env_or_default(key: &str, default: impl Into<String>) -> String {
    match env::var(key) {
        Ok(val) if !val.trim().is_empty() => val.trim().to_string(),
        _ => default.into(),
    }
}

pub fn get_env_or_default_value<T: std::str::FromStr>(key: &str, default: T) -> T {
    match env::var(key) {
        Ok(val) if !val.trim().is_empty() => val.trim().parse().unwrap_or(default),
        _ => default,
    }
}
