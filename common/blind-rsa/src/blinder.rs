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

use crate::BlindPublicKey;
use anyhow::{Context, Result};
pub use blind_rsa_signatures::{
    BlindSignature, BlindingResult, DefaultRng, MessageRandomizer, Options, PublicKey, Signature,
};
pub use rsa::{PublicKeyParts, RsaPrivateKey, RsaPublicKey};

#[derive(Clone, Debug)]
pub struct BlindingState {
    pub msg: Vec<u8>,
    pub res: BlindingResult,
}

impl BlindingState {
    pub fn blinded_message(&self) -> Result<Vec<u8>> {
        Ok(self.res.blind_msg.0.clone())
    }

    pub fn message_randomizer(&self) -> Option<MessageRandomizer> {
        self.res.msg_randomizer
    }
}

pub struct RsaBlinder;

impl RsaBlinder {
    pub fn blind(&self, msg: &[u8], pk: BlindPublicKey) -> Result<BlindingState> {
        let options = Options::default();
        let rsa_pk: PublicKey = pk.try_into()?;
        let res = rsa_pk
            .blind(&mut DefaultRng, msg, false, &options)
            .context("failed to blind msg")?;
        Ok(BlindingState {
            msg: msg.to_vec(),
            res,
        })
    }

    pub fn verify(
        &self,
        blind_sig: &[u8],
        state: &BlindingState,
        pk: BlindPublicKey,
    ) -> Result<Vec<u8>> {
        let options = Options::default();
        let rsa_pk: PublicKey = pk.try_into()?;
        let msg_randomizer = state.message_randomizer();
        let sig = rsa_pk
            .finalize(
                &BlindSignature(blind_sig.to_vec()),
                &state.res.secret,
                msg_randomizer,
                &state.msg,
                &options,
            )
            .context("failed to blind msg")?;
        sig.verify(&rsa_pk, msg_randomizer, &state.msg, &options)
            .context("failed to verify signature")?;
        Ok(sig.0)
    }
}
