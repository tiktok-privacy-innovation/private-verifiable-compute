// Copyright 2025 Tiktok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
mod async_rw;

use async_rw::{ChannelWriter, create_channel_pair_with_size};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use bhttp::{Message, Mode};
use blind_rsa::BlindPublicKey;
use blind_rsa::blinder::{BlindingState, RsaBlinder};
use futures::future::try_join;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use js_sys::{Object, Reflect, Uint8Array};
use ohttp::{ClientRequest, KeyConfig};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{
    EncodedPoint, PublicKey,
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
};
use rand::RngCore;
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use std::pin::Pin;
use wasm_bindgen::prelude::*;
use web_sys::console;

// Enable console logging
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

#[wasm_bindgen]
pub struct BlindSession {
    pk: BlindPublicKey,
    state: Option<BlindingState>,
}

#[wasm_bindgen]
impl BlindSession {
    #[wasm_bindgen(constructor)]
    pub fn new(n_b64: &str, e_b64: &str) -> Result<BlindSession, JsValue> {
        let n = BASE64_STANDARD
            .decode(n_b64)
            .map_err(|e| JsValue::from_str(&format!("Decode n failed: {}", e)))?;
        let e = BASE64_STANDARD
            .decode(e_b64)
            .map_err(|e| JsValue::from_str(&format!("Decode e failed: {}", e)))?;
        Ok(BlindSession {
            pk: BlindPublicKey { n, e },
            state: None,
        })
    }

    pub fn blind(&mut self) -> Result<JsValue, JsValue> {
        let mut msg = vec![0u8; 20];
        rand::thread_rng().fill_bytes(&mut msg);
        let blinder = RsaBlinder {};
        let state = blinder
            .blind(&msg, self.pk.clone())
            .map_err(|e| JsValue::from_str(&format!("Blind failed: {}", e)))?;
        let blinded_msg = state
            .blinded_message()
            .map_err(|e| JsValue::from_str(&format!("Get blinded message failed: {}", e)))?;
        self.state = Some(state);
        let result = Object::new();
        Reflect::set(
            &result,
            &JsValue::from_str("message"),
            &JsValue::from_str(&hex::encode(&msg)),
        )
        .map_err(|_| JsValue::from_str("Set message failed"))?;
        let blinded_array = Uint8Array::from(&blinded_msg[..]);
        Reflect::set(
            &result,
            &JsValue::from_str("blindedMessage"),
            &blinded_array,
        )
        .map_err(|_| JsValue::from_str("Set blindedMessage failed"))?;
        Ok(result.into())
    }

    pub fn unblind(&mut self, blind_sig: &[u8]) -> Result<String, JsValue> {
        let state = self
            .state
            .take()
            .ok_or_else(|| JsValue::from_str("Blind state missing"))?;
        let blinder = RsaBlinder {};
        let sig = blinder
            .verify(blind_sig, &state, self.pk.clone())
            .map_err(|e| JsValue::from_str(&format!("Unblind failed: {}", e)))?;
        Ok(hex::encode(&sig))
    }
}

#[wasm_bindgen]
pub struct OhttpResponseReader {
    decrypted_reader: Pin<Box<dyn AsyncRead + Unpin + Send>>,
}

#[wasm_bindgen]
pub struct OhttpResponseFeeder {
    encrypted_writer: ChannelWriter,
}

#[wasm_bindgen]
impl OhttpResponseFeeder {
    /// Feed encrypted bytes (e.g. from network) into the OHTTP session.
    pub async fn feed(&mut self, chunk: &[u8]) -> Result<(), JsValue> {
        if let Err(e) = self.encrypted_writer.write_all(chunk).await {
            return Err(JsValue::from_str(&format!(
                "Failed to write to enc writer: {}",
                e
            )));
        }
        if let Err(e) = self.encrypted_writer.flush().await {
            return Err(JsValue::from_str(&format!(
                "Failed to flush enc writer: {}",
                e
            )));
        }
        Ok(())
    }

    pub async fn close(&mut self) -> Result<(), JsValue> {
        if let Err(e) = self.encrypted_writer.close().await {
            return Err(JsValue::from_str(&format!(
                "Failed to close enc writer: {}",
                e
            )));
        }
        Ok(())
    }
}

#[wasm_bindgen]
impl OhttpResponseReader {
    /// Read available decrypted bytes.
    /// This will try to read 'max_size' bytes.
    /// If no data is available immediately, it will return an empty array (or throw Pending if we could return Promise).
    /// But for simplicity, let's allow it to yield/wait if data is pending in channel.
    pub async fn read(&mut self, max_size: u32) -> Result<Vec<u8>, JsValue> {
        let max_size = if max_size == 0 {
            4096
        } else {
            max_size as usize
        };
        let mut buf = vec![0u8; max_size];

        // We poll the reader.
        // If we get data, great.
        // If we get Pending, we wait (since this is async).
        // BUT, we want to return what we have if we have something, OR wait for at least 1 byte?
        // AsyncRead::read waits for at least 1 byte or EOF.

        let read_future = self.decrypted_reader.read(&mut buf);
        match read_future.await {
            Ok(0) => {
                // EOF
                Ok(Vec::new())
            }
            Ok(n) => {
                console::log_1(&format!("read {} bytes from ohttp response", n).into());
                buf.truncate(n);
                Ok(buf)
            }
            Err(e) => {
                let msg = format!("ohttp response read error: {}", e);
                console::error_1(&JsValue::from_str(&msg));
                Err(JsValue::from_str(&msg))
            }
        }
    }
}

#[wasm_bindgen]
pub struct OhttpEncapsulator {
    config: KeyConfig,
}

#[wasm_bindgen]
impl OhttpEncapsulator {
    #[wasm_bindgen(constructor)]
    pub fn new(config_bytes: &[u8]) -> Result<OhttpEncapsulator, JsValue> {
        let config = KeyConfig::decode(config_bytes)
            .map_err(|e| JsValue::from_str(&format!("Invalid config: {}", e)))?;

        Ok(OhttpEncapsulator { config })
    }

    /// Encapsulates a request.
    /// Returns [encrypted_request_bytes, session]
    pub async fn encapsulate(
        &self,
        method: &str,
        scheme: &str,
        authority: &str,
        path: &str,
        body: Option<Vec<u8>>,
        headers: Option<js_sys::Object>,
    ) -> Result<js_sys::Array, JsValue> {
        // 1. Create Request
        let mut request = Message::request(
            method.as_bytes().to_vec(),
            scheme.as_bytes().to_vec(),
            authority.as_bytes().to_vec(),
            path.as_bytes().to_vec(),
        );

        if let Some(h) = headers {
            let entries = js_sys::Object::entries(&h);
            for i in 0..entries.length() {
                let entry = entries.get(i);
                let entry_arr = js_sys::Array::from(&entry);
                let key = entry_arr.get(0).as_string().unwrap_or_default();
                let value = entry_arr.get(1).as_string().unwrap_or_default();
                if !key.is_empty() {
                    request.put_header(key.as_bytes(), value.as_bytes());
                }
            }
        }

        if let Some(b) = body {
            request.write_content(&b);
        }

        let mut request_buf = Vec::new();
        request
            .write_bhttp(Mode::KnownLength, &mut request_buf)
            .map_err(|e| JsValue::from_str(&format!("BHTTP write failed: {}", e)))?;

        // 2. Encapsulate
        let req_ctx = ClientRequest::from_config(&mut self.config.clone())
            .map_err(|e| JsValue::from_str(&format!("ClientRequest init failed: {}", e)))?;

        let (request_write, mut request_read) = create_channel_pair_with_size(4096);

        let mut enc_request_writer = req_ctx
            .encapsulate_stream(request_write)
            .map_err(|e| JsValue::from_str(&format!("Encapsulate stream failed: {}", e)))?;

        // Run write (write_all + close) and read (read_to_end) concurrently so that when the
        // channel backs up, the reader drains it and we avoid deadlock (same pattern as pvc-client).
        let mut encrypted_request = Vec::new();
        let write_fut = async move {
            enc_request_writer
                .write_all(&request_buf)
                .await
                .map_err(|e| JsValue::from_str(&format!("Write request failed: {}", e)))?;
            enc_request_writer
                .close()
                .await
                .map_err(|e| JsValue::from_str(&format!("Close request failed: {}", e)))?;
            Ok(enc_request_writer)
        };
        let read_fut = async {
            request_read
                .read_to_end(&mut encrypted_request)
                .await
                .map_err(|e| JsValue::from_str(&format!("Read encrypted failed: {}", e)))
        };
        let (enc_request_writer, _) = try_join(write_fut, read_fut).await?;

        // 3. Prepare Response Decapsulator
        // Use 0 buffer size to force immediate flushing
        let (enc_res_writer, enc_res_reader) = create_channel_pair_with_size(1024);

        let client_response = enc_request_writer
            .response(enc_res_reader)
            .map_err(|e| JsValue::from_str(&format!("Response setup failed: {:?}", e)))?;

        let session_reader = OhttpResponseReader {
            decrypted_reader: Box::pin(client_response),
        };

        let session_feeder = OhttpResponseFeeder {
            encrypted_writer: enc_res_writer,
        };

        let result = js_sys::Array::new();
        result.push(&js_sys::Uint8Array::from(&encrypted_request[..]));
        result.push(&JsValue::from(session_reader));
        result.push(&JsValue::from(session_feeder));

        Ok(result)
    }
}

// Noise Protocol

#[wasm_bindgen]
pub struct NoiseHandshake {
    state: HandshakeState,
}

#[wasm_bindgen]
pub struct NoiseSession {
    transport: TransportState,
}

#[wasm_bindgen]
impl NoiseHandshake {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<NoiseHandshake, JsValue> {
        let params: NoiseParams = "Noise_NN_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .map_err(|e| JsValue::from_str(&format!("Invalid params: {}", e)))?;
        let builder = Builder::new(params);
        let state = builder
            .build_initiator()
            .map_err(|e| JsValue::from_str(&format!("Build initiator failed: {}", e)))?;
        Ok(NoiseHandshake { state })
    }

    pub fn generate_ephemeral(&mut self) -> Result<Vec<u8>, JsValue> {
        let mut out = vec![0u8; 65535];
        let n = self
            .state
            .write_message(&[], &mut out)
            .map_err(|e| JsValue::from_str(&format!("Generate ephemeral failed: {}", e)))?;
        out.truncate(n);
        Ok(out)
    }

    pub fn recv_response(mut self, inbound: &[u8]) -> Result<NoiseSession, JsValue> {
        let mut buf = vec![0u8; 65535];
        self.state
            .read_message(inbound, &mut buf)
            .map_err(|e| JsValue::from_str(&format!("Read message failed: {}", e)))?;
        if !self.state.is_handshake_finished() {
            return Err(JsValue::from_str("Handshake not finished"));
        }
        let tp = self
            .state
            .into_transport_mode()
            .map_err(|e| JsValue::from_str(&format!("Into transport failed: {}", e)))?;
        Ok(NoiseSession { transport: tp })
    }
}

const NONCELEN: usize = 8;
const TAGLEN: usize = 16;
const MAX_CHUNK_SIZE: usize = 65535 - NONCELEN - TAGLEN;
const NN_HEADER_SIZE: usize = 8;

#[wasm_bindgen]
impl NoiseSession {
    fn calculate_sizes(msg_size: usize, header_size: usize) -> (usize, usize) {
        let num_chunks = (msg_size + MAX_CHUNK_SIZE - 1) / MAX_CHUNK_SIZE;
        let mut output_size: usize = header_size;
        output_size += num_chunks * (NONCELEN + TAGLEN) + msg_size;
        (num_chunks, output_size)
    }

    fn fill_header(&self, msg_len: u32, num_packages: u32, header: &mut [u8]) {
        assert_eq!(header.len(), NN_HEADER_SIZE);
        let msg_len_bytes = msg_len.to_be_bytes();
        let num_packages_bytes = num_packages.to_be_bytes();
        header[0..4].copy_from_slice(&msg_len_bytes);
        header[4..8].copy_from_slice(&num_packages_bytes);
    }

    fn take_header(&self, header: &[u8]) -> (u32, u32) {
        assert_eq!(header.len(), NN_HEADER_SIZE);
        let msg_len_bytes = &header[0..4];
        let num_packages_bytes = &header[4..8];
        let msg_len = u32::from_be_bytes([
            msg_len_bytes[0],
            msg_len_bytes[1],
            msg_len_bytes[2],
            msg_len_bytes[3],
        ]);
        let num_packages = u32::from_be_bytes([
            num_packages_bytes[0],
            num_packages_bytes[1],
            num_packages_bytes[2],
            num_packages_bytes[3],
        ]);
        (msg_len, num_packages)
    }

    /// out format: nonce (8) + aead_cipher + tag (16)
    fn encrypt_one_chunk(&mut self, pt: &[u8], out: &mut [u8]) -> Result<(), String> {
        if pt.len() > MAX_CHUNK_SIZE {
            return Err(format!("encrypt message too large"));
        }

        if out.len() != NONCELEN + pt.len() + TAGLEN {
            return Err(format!("output buffer size mismatch"));
        }

        let (out_nonce, out_ct) = out.split_at_mut(NONCELEN);
        let nonce = self.transport.sending_nonce();
        out_nonce.copy_from_slice(&nonce.to_be_bytes());
        let n = self
            .transport
            .write_message(pt, out_ct)
            .map_err(|e| format!("{}", e))?;
        assert_eq!(n, out_ct.len());
        Ok(())
    }

    /// require 0 < pt.len() < 2^16 * MAX_CHUNK_SIZE
    /// The output format:
    ///     msg_len(4bytes) | num_chunks(4bytes) | encrypted_chunk0 | .. | encrypted_chunkN
    /// Each encrypted chunk is formatted as:
    ///     nonce(8bytes) | AEAD (MAX_CHUNK_SIZE) | MAC (16bytes)
    fn do_encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>, JsValue> {
        let msg_len = pt.len();
        if msg_len >= (MAX_CHUNK_SIZE << 16) {
            return Err(JsValue::from_str(&format!(
                "Message length {} too large",
                msg_len
            )));
        }

        let (num_chunks, output_size) = Self::calculate_sizes(msg_len, NN_HEADER_SIZE);
        let mut out = vec![0u8; output_size];
        let (header, mut chunks_ct) = out.split_at_mut(NN_HEADER_SIZE);
        self.fill_header(msg_len as u32, num_chunks as u32, header);

        for i in 0..num_chunks {
            let start = i * MAX_CHUNK_SIZE;
            let end = std::cmp::min(msg_len, start + MAX_CHUNK_SIZE);

            let this_chunk_size = end - start;
            let chunk_pt = &pt[start..end];

            let (chunk_ct, remains) = chunks_ct.split_at_mut(this_chunk_size + NONCELEN + TAGLEN);
            self.encrypt_one_chunk(chunk_pt, chunk_ct).map_err(|e| {
                JsValue::from_str(&format!("Encrypt chunks failed at {} chunk for {}", i, e))
            })?;

            chunks_ct = remains;
        }
        Ok(out)
    }

    pub fn encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>, JsValue> {
        #[cfg(feature = "noise")]
        {
            self.do_encrypt(pt)
        }
        #[cfg(not(feature = "noise"))]
        {
            Ok(pt.to_vec())
        }
    }

    fn decrypt_one_chunk(&mut self, ct: &[u8], out: &mut [u8]) -> Result<(), String> {
        let (nonce, aead) = ct.split_at(NONCELEN);
        let nonce = u64::from_be_bytes(nonce.try_into().unwrap());
        self.transport.set_receiving_nonce(nonce);
        let n = self
            .transport
            .read_message(aead, out)
            .map_err(|e| format!("{}", e))?;
        assert_eq!(n, out.len());
        Ok(())
    }

    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>, JsValue> {
        #[cfg(not(feature = "noise"))]
        {
            return Ok(ct.to_vec());
        }
        if ct.len() < NN_HEADER_SIZE {
            return Err(JsValue::from_str("Invalid ciphertext header length"));
        }

        let (header, mut chunks_ct) = ct.split_at(NN_HEADER_SIZE);
        let (msg_len, num_chunks) = self.take_header(header);

        let num_chunks = num_chunks as usize;
        let msg_len = msg_len as usize;
        if msg_len >= (MAX_CHUNK_SIZE << 16) {
            return Err(JsValue::from_str(&format!(
                "Message length {} too large",
                msg_len
            )));
        }

        let ct_len = chunks_ct.len();
        let expected_len = num_chunks * (TAGLEN + NONCELEN) + msg_len;
        if ct_len != expected_len {
            return Err(JsValue::from_str(&format!(
                "ciphertext is length {}, but expected {}",
                ct_len, expected_len
            )));
        }
        let mut out = vec![0u8; msg_len];
        for i in 0..num_chunks {
            let start = i * MAX_CHUNK_SIZE;
            let end = std::cmp::min(msg_len, start + MAX_CHUNK_SIZE);
            let this_chunk_size = end - start;

            let (chunk_ct, rest) = chunks_ct.split_at(this_chunk_size + NONCELEN + TAGLEN);
            self.decrypt_one_chunk(chunk_ct, &mut out[start..end])
                .map_err(|e| {
                    JsValue::from_str(&format!("decrypt chunks failed at {} chunk for {} ", i, e))
                })?;
            chunks_ct = rest;
        }
        Ok(out)
    }
}

#[wasm_bindgen]
pub fn verify_noise_signature(
    verifying_key_bytes: &[u8],
    e: &[u8],
    ee: &[u8],
    signature: &[u8],
) -> Result<bool, JsValue> {
    if verifying_key_bytes.len() != 64 {
        return Err(JsValue::from_str("Verifying key must be 64 bytes"));
    }

    // Decode verifying key (uncompressed point)
    // p256::EncodedPoint::from_untagged_bytes expects 64 bytes (X || Y)
    // or tagged bytes.
    // pvc-client uses `from_untagged_bytes` on GenericArray<u8, U64>.
    let ep = EncodedPoint::from_untagged_bytes(verifying_key_bytes.into());
    let pk = PublicKey::from_encoded_point(&ep);

    if pk.is_none().into() {
        return Err(JsValue::from_str("Invalid public key point"));
    }
    let pk = pk.unwrap();
    let vk = VerifyingKey::from(pk);

    let mut message = Vec::new();
    message.extend_from_slice(e);
    message.extend_from_slice(ee);

    let sig = Signature::from_slice(signature)
        .map_err(|e| JsValue::from_str(&format!("Invalid signature format: {}", e)))?;

    Ok(vk.verify(&message, &sig).is_ok())
}
