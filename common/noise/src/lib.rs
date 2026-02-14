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

/// Noise NN wrapper with role-specific, step-oriented API.
///
/// Initiator flow:
/// 1) generate_ephemeral()       -> e
/// 2) recv_response(inbound)     <- e, ee, generate Transport
///
/// Responder flow:
/// 1) recv_init_and_respond(inbound) -> reads e, writes e, ee, and returns Transport
use anyhow::{Result, anyhow, bail};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

pub const NONCELEN: usize = 8;
pub const TAGLEN: usize = 16;

/// Session role for NN.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Initiator,
    Responder,
}

/// Initiator handshake session for NN.
/// Flow: generate_ephemeral() -> recv_response() => Transport
pub struct NoiseNnInitiator {
    inner: HandshakeState,
}

impl NoiseNnInitiator {
    pub fn new(params: NoiseParams, psk: Option<(u8, [u8; 32])>) -> Result<Self> {
        let name = &params.name;
        if !name.contains("_NN_") {
            bail!("only NN pattern is supported: got {}", name);
        }

        let mut builder = Builder::new(params);
        if let Some((p, key)) = &psk {
            builder = builder.psk(*p, key)?;
        }

        let hs = builder.build_initiator()?;

        Ok(Self { inner: hs })
    }

    /// Step 1 (initiator): produce `e`.
    pub fn generate_ephemeral(&mut self) -> Result<Vec<u8>> {
        let mut out = vec![0u8; 65535];
        let n = self.inner.write_message(&[], &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    /// Step 2 (initiator): read responder's `<- e, ee`, and transition to transport.
    pub fn recv_response(mut self, inbound: &[u8]) -> Result<NoiseNnTransport> {
        let mut buf = vec![0u8; 65535];
        self.inner.read_message(inbound, &mut buf)?;
        if !self.inner.is_handshake_finished() {
            bail!("handshake not finished after e, ee (unexpected for NN)");
        }
        let tp: TransportState = self.inner.into_transport_mode()?;
        Ok(NoiseNnTransport { inner: tp })
    }
}

/// Transport-phase session: same as your initiator’s transport.
#[derive(Debug)]
pub struct NoiseNnTransport {
    inner: TransportState,
}

const MAX_CHUNK_SIZE: usize = 65535 - NONCELEN - TAGLEN;
const NN_HEADER_SIZE: usize = 8;

impl NoiseNnTransport {
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

    /// require 0 < pt.len() < 2^16 * 65535
    fn _encrypt(&mut self, pt: &[u8], attach_len: bool) -> Result<Vec<u8>> {
        let msg_len = pt.len();
        if msg_len >= (MAX_CHUNK_SIZE << 16) {
            bail!("encrypt message too large");
        }

        let (num_chunks, output_size) = Self::calculate_sizes(msg_len, NN_HEADER_SIZE);
        let (header_size, obuff_size) = if attach_len {
            (NN_HEADER_SIZE + 4, output_size + 4)
        } else {
            (NN_HEADER_SIZE, output_size)
        };

        let mut out = vec![0u8; obuff_size];
        let (header, mut chunks_ct) = out.split_at_mut(header_size);

        if attach_len {
            let (l, h) = header.split_at_mut(4);
            l.copy_from_slice(&(output_size as u32).to_be_bytes());
            self.fill_header(msg_len as u32, num_chunks as u32, h);
        } else {
            self.fill_header(msg_len as u32, num_chunks as u32, header);
        }

        for i in 0..num_chunks {
            let start = i * MAX_CHUNK_SIZE;
            let end = std::cmp::min(msg_len, start + MAX_CHUNK_SIZE);

            let this_chunk_size = end - start;
            let chunk_pt = &pt[start..end];

            let (chunk_ct, remains) = chunks_ct.split_at_mut(this_chunk_size + NONCELEN + TAGLEN);
            self.encrypt_one_chunk(chunk_pt, chunk_ct)
                .map_err(|e| anyhow!("encrypt chunks failed at {} chunk for {} ", i, e))?;

            chunks_ct = remains;
        }
        Ok(out)
    }

    /// encrypt the message via noise protocol
    /// handling long messages by splitting them into chunks
    /// output format: msg_len (4bytes) | num_chunks (4bytes) | chunk0 | ... | chunkN
    pub fn encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        self._encrypt(pt, /*attach_len*/ false)
    }

    /// encrypt the message and attach the ciphertext length in prefix (4 bytes)
    /// the result can be parsed by tiko's LengthDelimitedCodec.
    ///
    /// ```
    /// use tiko::codec::LengthDelimitedCodec;
    ///
    /// let ct = encrypt_with_prefix_len("message")?;
    /// let mut codec = LengthDelimitedCodec::builder().length_delimiter(4).build().new_reader(ct);
    /// codec.then(move |frame| {
    ///    // the prefix field (4bytes) is already stripped
    ///    decrypt(frame)
    /// })
    ///
    /// ```
    pub fn encrypt_with_prefix_len(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        self._encrypt(pt, /*attach_len*/ true)
    }

    /// out format: nonce (8) + aead_cipher + tag (16)
    fn encrypt_one_chunk(&mut self, pt: &[u8], out: &mut [u8]) -> Result<()> {
        if pt.len() > MAX_CHUNK_SIZE {
            bail!("encrypt message too large");
        }
        if out.len() != NONCELEN + pt.len() + TAGLEN {
            bail!("output buffer size mismatch");
        }

        let (out_nonce, out_ct) = out.split_at_mut(NONCELEN);
        let nonce = self.inner.sending_nonce();
        out_nonce.copy_from_slice(&nonce.to_be_bytes());
        let n = self.inner.write_message(pt, out_ct)?;
        assert_eq!(n, out_ct.len());
        Ok(())
    }

    /// the prefix length is **not included** in the header
    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let (header, mut chunks_ct) = ct.split_at(NN_HEADER_SIZE);
        let (msg_len, num_chunks) = self.take_header(header);

        let num_chunks = num_chunks as usize;
        let msg_len = msg_len as usize;
        if msg_len >= (MAX_CHUNK_SIZE << 16) {
            bail!("invalid msg_len {} to decrypt", msg_len);
        }

        let ct_len = chunks_ct.len();
        if ct_len != num_chunks * (TAGLEN + NONCELEN) + msg_len {
            bail!("ciphertext length mismatch");
        }

        let mut out = vec![0u8; msg_len];
        for i in 0..num_chunks {
            let start = i * MAX_CHUNK_SIZE;
            let end = std::cmp::min(msg_len, start + MAX_CHUNK_SIZE);
            let this_chunk_size = end - start;

            let (chunk_ct, rest) = chunks_ct.split_at(this_chunk_size + NONCELEN + TAGLEN);
            self.decrypt_one_chunk(chunk_ct, &mut out[start..end])
                .map_err(|e| anyhow!("decrypt chunks failed at {} chunk for {} ", i, e))?;
            chunks_ct = rest;
        }
        Ok(out)
    }

    fn decrypt_one_chunk(&mut self, ct: &[u8], out: &mut [u8]) -> Result<()> {
        let (nonce, aead) = ct.split_at(NONCELEN);
        let nonce = u64::from_be_bytes(nonce.try_into()?);
        self.inner.set_receiving_nonce(nonce);
        let n = self.inner.read_message(aead, out)?;
        assert_eq!(n, out.len());
        Ok(())
    }
}

/// Responder handshake session for NN.
/// Flow: handle_init(inbound) -> handle_final(self, inbound) => Transport
pub struct NoiseNnResponder {
    hs: HandshakeState,
}

impl NoiseNnResponder {
    /// Create a new NN responder handshake.
    pub fn new(params: NoiseParams, psk: Option<(u8, [u8; 32])>) -> Result<Self> {
        let name = &params.name;
        if !name.contains("_NN_") {
            bail!("only NN pattern is supported: got {}", name);
        }
        let mut builder = Builder::new(params);
        if let Some((p, key)) = &psk {
            builder = builder.psk(*p, key)?;
        }
        let hs = builder.build_responder()?;
        Ok(Self { hs })
    }

    /// (responder): read initiator `-> e`, then write `<- e, ee`.
    ///
    /// Returns the responder’s reply to send back to the initiator, generate to transport
    pub fn handle_establish(mut self, inbound: &[u8]) -> Result<(NoiseNnTransport, Vec<u8>)> {
        // Read initiator `e`
        let mut _payload = Vec::new();
        self.hs.read_message(inbound, &mut _payload)?;
        // Write `<- e, ee`
        let mut out = vec![0u8; 1024];
        let n = self.hs.write_message(&[], &mut out)?;
        out.truncate(n);
        let tp = self.hs.into_transport_mode()?;
        Ok((NoiseNnTransport { inner: tp }, out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use snow::params::NoiseParams;

    fn nn_params() -> NoiseParams {
        "Noise_NN_25519_ChaChaPoly_BLAKE2s"
            .parse()
            .expect("valid params")
    }

    /// End-to-end NN handshake: Initiator and Responder exchange messages and both enter transport.
    #[test]
    fn nn_handshake_initiator_responder_happy_path() -> Result<()> {
        let params = nn_params();
        // Construct initiator and responder
        let mut init = NoiseNnInitiator::new(params.clone(), None)?;
        let resp = NoiseNnResponder::new(params.clone(), None)?;
        // Initiator step 1: -> e
        let msg1: Vec<u8> = init.generate_ephemeral()?;
        assert!(!msg1.is_empty());
        // Responder step 1: read e, write <- e, ee, s, es
        let (mut resp_transport, msg2) = resp.handle_establish(&msg1)?;
        assert!(!msg2.is_empty());
        // Initiator step 2: read responder response
        let mut init_transport = init.recv_response(&msg2)?;

        let pt = b"hello";
        let ct = init_transport.encrypt(pt)?;
        let dec = resp_transport.decrypt(&ct)?;
        assert_eq!(dec, pt);

        let long_pt = [11u8; 65535 + 32768];
        let long_ct = init_transport.encrypt(&long_pt)?;
        let long_dec = resp_transport.decrypt(&long_ct)?;
        assert_eq!(long_dec, long_pt);
        // Reverse direction: encrypt on responder, decrypt on initiator
        let pt2 = b"server -> client";
        let ct2 = resp_transport.encrypt(pt2)?;
        let dec2 = init_transport.decrypt(&ct2)?;
        assert_eq!(dec2, pt2);
        Ok(())
    }

    /// Transport encryption/decryption should be symmetric and authenticated.
    #[test]
    fn transport_roundtrip_after_handshake() -> Result<()> {
        let params = nn_params();
        let mut init = NoiseNnInitiator::new(params.clone(), None)?;
        let resp = NoiseNnResponder::new(params.clone(), None)?;

        let msg1 = init.generate_ephemeral()?;
        let (mut resp_tp, msg2) = resp.handle_establish(&msg1)?;
        let mut init_tp = init.recv_response(&msg2)?;
        // Multiple messages in both directions
        for i in 0..5 {
            let payload = format!("msg-{i}-from-init").into_bytes();
            let ct = init_tp.encrypt(&payload)?;
            let dec = resp_tp.decrypt(&ct)?;
            assert_eq!(dec, payload);
            let payload = format!("msg-{i}-from-resp").into_bytes();
            let ct = resp_tp.encrypt(&payload)?;
            let dec = init_tp.decrypt(&ct)?;
            assert_eq!(dec, payload);
        }
        Ok(())
    }

    /// Calling a responder step out of order should error.
    #[test]
    fn responder_step_enforcement() -> Result<()> {
        let params = nn_params();
        let resp = NoiseNnResponder::new(params, None)?;
        // Attempt to call final step before initial step
        let bogus = vec![0u8; 48]; // not a valid NN message but enough to hit state check
        let err = resp.handle_establish(&bogus).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("decrypt error"), "got: {msg}");
        Ok(())
    }

    /// Malformed inbound should fail: MAC/auth check fails during read_message.
    #[test]
    fn malformed_inbound_fails_handshake() -> Result<()> {
        let params = nn_params();
        let resp = NoiseNnResponder::new(params, None)?;
        // Feed random bytes as initiator's e; should fail at read_message
        let bogus = vec![0xAA; 64];
        let err = resp.handle_establish(&bogus).unwrap_err();
        let msg = format!("{err}");
        // The exact error string comes from snow; just assert it's an error.
        assert!(!msg.is_empty());
        Ok(())
    }
}
