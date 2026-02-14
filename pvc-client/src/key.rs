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

use anyhow::Result;
use rand::RngCore;
use rand::rngs::OsRng;
use std::env::home_dir;
use std::fs;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use types::keys::ContextKey;

const PVC_ROOT_DIR: &str = ".pvc";
const KEY_FILE: &str = "secret";
pub fn create_or_get_encryption_key() -> Result<ContextKey> {
    let path = key_path_in_home()?;
    if path.exists() {
        let mut file = fs::File::open(&path)?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        return Ok(ContextKey(buf));
    }

    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir)?;
    }

    let mut key = vec![0u8; 32];
    OsRng.fill_bytes(&mut key);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600) // -rw-------
        .open(&path)?;
    file.write_all(&key)?;
    file.sync_all()?;

    Ok(ContextKey(key))
}

fn key_path_in_home() -> Result<PathBuf> {
    let home = home_dir().unwrap();
    Ok(home.join(PVC_ROOT_DIR).join(KEY_FILE))
}
