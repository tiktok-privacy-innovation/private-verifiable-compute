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

use anyhow::{Result, anyhow};
use noise::{NoiseNnResponder, NoiseNnTransport};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::time::{Duration, Instant};
use types::keys::EncryptionKey;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Stage {
    Init,
    Established,
    Closed,
}

#[derive(Hash, Eq, PartialEq, Clone)]
pub struct Sid(Uuid);

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Sid {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

pub struct Session {
    sid: Sid,
    stage: Stage,
    responder: Option<NoiseNnResponder>,
    transport: Option<NoiseNnTransport>,
    encryption_key: Option<EncryptionKey>,
    last_active: Instant,
}

#[allow(dead_code)]
impl Session {
    pub fn new() -> Result<Self> {
        let uuid = Uuid::new_v4();
        let sid = Sid::new(uuid);
        // new a XX noise pattern
        let responder =
            NoiseNnResponder::new("Noise_NN_25519_ChaChaPoly_BLAKE2s".parse().unwrap(), None)?;
        Ok(Self {
            sid,
            stage: Stage::Init,
            last_active: Instant::now(),
            transport: None,
            encryption_key: None,
            responder: Some(responder),
        })
    }
    fn touch(&mut self) {
        self.last_active = Instant::now();
    }
    fn expired(&self, ttl: Duration) -> bool {
        self.last_active.elapsed() > ttl
    }

    pub fn get_sid(&self) -> Sid {
        self.sid.clone()
    }

    pub fn get_encryption_key(&self) -> Option<EncryptionKey> {
        self.encryption_key.clone()
    }

    pub fn set_encryption_key(&mut self, key: EncryptionKey) {
        self.encryption_key = Some(key);
    }

    pub fn handshake(self, data: &[u8]) -> Result<(Self, Vec<u8>)> {
        if self.stage != Stage::Init {
            return Err(anyhow!("internal error! wrong stage"));
        }
        if let Some(r) = self.responder {
            let (tp, msg) = r.handle_establish(data)?;
            Ok((
                Session {
                    sid: self.sid,
                    stage: Stage::Established,
                    responder: None,
                    transport: Some(tp),
                    encryption_key: None,
                    last_active: Instant::now(),
                },
                msg,
            ))
        } else {
            Err(anyhow!("internal error! noise responder is empty"))
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if self.stage != Stage::Established {
            return Err(anyhow!("internal error! wrong stage"));
        }

        if let Some(t) = &mut self.transport {
            t.decrypt(ciphertext)
        } else {
            Err(anyhow!("internal error! noise transport is empty"))
        }
    }

    pub fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.stage != Stage::Established {
            return Err(anyhow!("internal error! wrong stage"));
        }

        if let Some(t) = &mut self.transport {
            t.encrypt(plaintext)
        } else {
            Err(anyhow!("internal error! noise transport is empty"))
        }
    }
}
