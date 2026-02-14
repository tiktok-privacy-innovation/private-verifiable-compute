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

use crate::request::RequestError;
use anyhow::{Result, anyhow};
use noise::{NoiseNnResponder, NoiseNnTransport};
use rocket::fairing::AdHoc;
use rocket::http::Status;
use rocket::{
    Request,
    outcome::Outcome,
    request::{self, FromRequest},
};
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use types::keys::ContextKey;
use uuid::Uuid;

const SESSION_ID_HEADER: &str = "X-Session-ID";

enum Stage {
    Init(NoiseNnResponder),
    Established(NoiseNnTransport),
    Invalid,
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

#[async_trait]
impl<'r> FromRequest<'r> for Sid {
    type Error = RequestError;

    /// Extracts a Session ID (Sid) from the HTTP request headers.
    /// This implementation allows Sid to be used as a request guard in Rocket routes.
    ///
    /// # How it works:
    /// 1. Looks for the "X-Session-ID" header in the incoming request
    /// 2. If found, attempts to parse it as a UUID
    /// 3. If parsing succeeds, returns a successful Outcome containing the Sid
    /// 4. If parsing fails or header is missing, returns an Error Outcome with BadRequest status
    /// }
    /// ```
    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let sid = request.headers().get_one(SESSION_ID_HEADER);
        match sid {
            Some(s) => Uuid::parse_str(s).map_or_else(
                |_e| Outcome::Error((Status::BadRequest, Self::Error::InvalidSessionId)),
                |uuid| Outcome::Success(Sid::new(uuid)),
            ),
            None => Outcome::Error((Status::BadRequest, Self::Error::MissingSessionId)),
        }
    }
}

pub struct Session {
    sid: Sid,
    stage: Stage,
    context_key: Option<ContextKey>,
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
            stage: Stage::Init(responder),
            last_active: Instant::now(),
            context_key: None,
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

    pub fn get_context_key(&self) -> Option<ContextKey> {
        self.context_key.clone()
    }

    pub fn set_context_key(&mut self, key: ContextKey) {
        self.context_key = Some(key);
    }

    pub fn establish(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let current_stage = std::mem::replace(&mut self.stage, Stage::Invalid);
        match current_stage {
            Stage::Init(r) => {
                let (tp, msg) = r.handle_establish(data)?;
                self.stage = Stage::Established(tp);
                Ok(msg)
            }
            _ => Err(anyhow!("internal error! wrong noise stage")),
        }
    }

    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "noise")]
        match &mut self.stage {
            Stage::Established(t) => t.decrypt(ciphertext),
            _ => Err(anyhow!("internal error! wrong noise stage")),
        }

        #[cfg(not(feature = "noise"))]
        Ok(ciphertext.to_vec())
    }

    pub fn encrypt_with_prefix_len(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "noise")]
        match &mut self.stage {
            Stage::Established(t) => t.encrypt_with_prefix_len(plaintext),
            _ => Err(anyhow!("internal error! wrong noise stage")),
        }

        #[cfg(not(feature = "noise"))]
        {
            let len = plaintext.len();
            let mut c = Vec::with_capacity(len + 4);
            c.extend_from_slice(&(len as u32).to_be_bytes());
            c.extend_from_slice(plaintext);
            Ok(c)
        }
    }
}

pub struct Sessions(Arc<RwLock<HashMap<Sid, Arc<Mutex<Session>>>>>);

impl Sessions {
    pub fn new() -> Self {
        Sessions(Arc::new(RwLock::new(HashMap::new())))
    }

    pub async fn get(&self, sid: &Sid) -> Result<Arc<Mutex<Session>>> {
        let map = self.0.read().await;
        map.get(sid)
            .ok_or(anyhow!("failed to get session"))
            .cloned()
    }

    pub async fn insert(&self, sid: Sid, session: Arc<Mutex<Session>>) {
        let mut map = self.0.write().await;
        map.insert(sid, session);
    }
}

pub fn stage() -> AdHoc {
    AdHoc::on_ignite("Noise Server", |rocket| async {
        rocket.manage(Sessions::new())
    })
}
