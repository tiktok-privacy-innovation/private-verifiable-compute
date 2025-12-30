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
use anyhow::{Result, bail};
use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};

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

impl NoiseNnTransport {
    pub fn encrypt(&mut self, pt: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; pt.len() + 32];
        let n = self.inner.write_message(pt, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    pub fn decrypt(&mut self, ct: &[u8]) -> Result<Vec<u8>> {
        let mut out = vec![0u8; ct.len()];
        let n = self.inner.read_message(ct, &mut out)?;
        out.truncate(n);
        Ok(out)
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
