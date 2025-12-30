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

pub mod blinder;
pub mod signer;

use anyhow::{Context, Result};
use blind_rsa_signatures::{KeyPair, Options, PublicKey, SecretKey};
use num_bigint_dig::BigUint;
use rsa::RsaPublicKey;

#[derive(Clone, Default, Debug)]
pub struct RsaBlindConfig {
    pub options: Options,
}

pub struct BlindRsaKeys;

impl BlindRsaKeys {
    /// generate rsa key pair, with bits 2048/3072/4096
    pub fn generate(bits: usize) -> Result<(PublicKey, SecretKey)> {
        let mut rng = rand::thread_rng();
        let kp = KeyPair::generate(&mut rng, bits)
            .with_context(|| format!("failed to generate RSA key pair ({} bits)", bits))?;
        Ok((kp.pk, kp.sk))
    }
}

#[derive(Clone)]
pub struct BlindPublicKey {
    pub n: Vec<u8>,
    pub e: Vec<u8>,
}

impl TryFrom<BlindPublicKey> for PublicKey {
    type Error = blind_rsa_signatures::Error;
    fn try_from(pk: BlindPublicKey) -> Result<Self, Self::Error> {
        let n = BigUint::from_bytes_le(&pk.n);
        let e = BigUint::from_bytes_le(&pk.e);
        Ok(PublicKey::new(RsaPublicKey::new(n, e).map_err(|_| {
            blind_rsa_signatures::Error::IncompatibleParameters
        })?))
    }
}
