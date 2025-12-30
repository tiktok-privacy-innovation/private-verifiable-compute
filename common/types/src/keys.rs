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

use anyhow::Result;
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{
    EncodedPoint, PublicKey,
    ecdsa::{SigningKey, VerifyingKey},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize, Deserialize)]
pub struct BlindMessageRequest {
    #[serde(rename = "blindedMessage")]
    pub blinded_message: String,
}

#[derive(Debug, Deserialize)]
pub struct BlindMessageResponse {
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PublicKeyFields {
    /// Modulus N represented as a decimal string
    pub n: String,
    /// Public exponent e represented as a decimal string
    pub e: String,
}

#[derive(Clone)]
pub struct EncryptionKey(pub Vec<u8>);

impl EncryptionKey {
    pub fn new(key: &[u8]) -> Self {
        Self(key.to_vec())
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.0);
        let digest = hasher.finalize();
        hex::encode(digest)
    }
}

pub fn encode_verifying_key(sk: &SigningKey) -> [u8; 64] {
    let vk = sk.verifying_key();
    let ep = vk.to_encoded_point(false); // uncompressed: 0x04 || X || Y
    let x = ep.x().unwrap(); // 32 bytes
    let y = ep.y().unwrap(); // 32 bytes
    let mut raw_pub64 = [0u8; 64];
    raw_pub64[..32].copy_from_slice(x);
    raw_pub64[32..].copy_from_slice(y);
    raw_pub64
}

pub fn decode_verifying_key(data: [u8; 64]) -> Result<VerifyingKey> {
    let ep2 = EncodedPoint::from_untagged_bytes(&data.into());
    let pk = PublicKey::from_encoded_point(&ep2).expect("point on curve");
    let vk = VerifyingKey::from(pk);
    Ok(vk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn test_sign() {
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key().clone();

        let data = encode_verifying_key(&sk);

        let vk2 = decode_verifying_key(data).unwrap();
        assert_eq!(vk, vk2);
    }
}
