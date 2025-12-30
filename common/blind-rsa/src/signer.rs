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

use crate::{BlindRsaKeys, RsaBlindConfig};
use anyhow::{Context, Result};
use blind_rsa_signatures::{DefaultRng, PublicKey, SecretKey};
use rsa::RsaPublicKey;

const RSA_KEY_BITS: usize = 3072;

pub struct RsaBlindSigner {
    pub cfg: RsaBlindConfig,
    sk: SecretKey,
    pk: PublicKey,
}

impl RsaBlindSigner {
    pub fn new(cfg: RsaBlindConfig) -> Self {
        let (pk, sk) = BlindRsaKeys::generate(RSA_KEY_BITS).unwrap();
        Self { pk, sk, cfg }
    }

    pub fn pubkey(&self) -> RsaPublicKey {
        self.pk.0.clone()
    }

    pub fn blind_sign(&self, blind_msg: &[u8]) -> Result<Vec<u8>> {
        let blind_sig = self
            .sk
            .blind_sign(&mut DefaultRng, blind_msg, &self.cfg.options)
            .context("failed to blind sign")?;
        Ok(blind_sig.0.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use rsa::PublicKeyParts;

    use crate::{BlindPublicKey, blinder::RsaBlinder};

    use super::*;

    #[test]
    fn test_blind_sign() {
        let cfg = RsaBlindConfig::default();
        let signer: RsaBlindSigner = RsaBlindSigner::new(cfg);
        let msg = "hello world".as_bytes();

        let pk: RsaPublicKey = signer.pubkey();

        let blind_pk = BlindPublicKey {
            n: pk.n().to_bytes_le(),
            e: pk.e().to_bytes_le(),
        };

        let blinder = RsaBlinder {};

        let state = blinder.blind(msg, blind_pk.clone()).unwrap();

        let blind_msg = state.blinded_message().unwrap();

        let blinded_signature = signer.blind_sign(&blind_msg).unwrap();

        blinder
            .verify(&blinded_signature, &state, blind_pk)
            .unwrap();
    }
}
