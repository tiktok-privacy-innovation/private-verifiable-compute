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

// End-to-end test for `PvcApiClient.chat` session-recovery behavior.
//
// The test models the deployed flow where the tee-llm pod restarts (or
// otherwise forgets our `sid`) between two chat requests. We mock the
// WASM client so the OHTTP / Noise primitives become observable counters,
// then drive the public `chat()` API and assert:
//
//   * exactly two attempts at decapsulating the chat response stream
//     (the original attempt + the post-recovery retry),
//   * exactly one re-handshake (handshake JSON + establish JSON) between
//     the two attempts,
//   * the retry's plaintext SSE chunk is what `chat()` returns to the
//     caller — confirming we did not silently drop the recovered result.
//
// Mirrors the Rust-side `execute_with_session_recovery_*` tests in
// `common/pvc-client-core/src/lib.rs`.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { PvcApiClient, SessionRejectedError, isSessionRejected, encodeBase64 } from './api'

const verifyNoiseSignature = vi.fn(() => true)
const encapsulateRequest = vi.fn()
const decapsulateResponse = vi.fn()
const decapsulateResponseStream = vi.fn()
const blind = vi.fn()
const unblind = vi.fn()
const generateEphemeral = vi.fn()
const noiseEncrypt = vi.fn()
const noiseDecrypt = vi.fn()
const recvResponse = vi.fn(() => ({ encrypt: noiseEncrypt, decrypt: noiseDecrypt }))

vi.mock('./wasm_client', () => {
  class MockWasmClient {
    BlindSession = class {
      constructor() {}
      blind = blind
      unblind = unblind
    }

    NoiseHandshake = class {
      generate_ephemeral = generateEphemeral
      recv_response = recvResponse
    }

    NoiseSession = class {}

    static async create() {
      return new MockWasmClient()
    }

    async encapsulateRequest(request: Request) {
      return encapsulateRequest(request)
    }

    async decapsulateResponse(response: Response) {
      return decapsulateResponse(response)
    }

    decapsulateResponseStream = decapsulateResponseStream
    verifyNoiseSignature = verifyNoiseSignature
  }

  return { WasmClient: MockWasmClient }
})

function streamOfBytes(bytes: Uint8Array): ReadableStream<Uint8Array> {
  return new ReadableStream({
    start(controller) {
      controller.enqueue(bytes)
      controller.close()
    },
  })
}

function lengthPrefixedNoiseFrame(payload: Uint8Array): Uint8Array {
  const frame = new Uint8Array(4 + payload.length)
  const view = new DataView(frame.buffer)
  view.setUint32(0, payload.length, false)
  frame.set(payload, 4)
  return frame
}

function sseChunkBytes(content: string): Uint8Array {
  const sse = `data: {"choices":[{"delta":{"content":${JSON.stringify(content)}}}]}\ndata: [DONE]\n`
  return new TextEncoder().encode(sse)
}

const HANDSHAKE_BODY = (sid: string, handshakeVerifyingKey: Uint8Array) =>
  JSON.stringify({
    code: 0,
    data: {
      attestation: {
        cpu: {
          tee_type: 'sample',
          evidence: { report_data: encodeBase64(new Uint8Array(64).fill(3)) },
        },
      },
      binding: {
        handshake_verifying_key: encodeBase64(handshakeVerifyingKey),
      },
      session: { id: sid },
    },
  })

const ESTABLISH_BODY = JSON.stringify({
  code: 0,
  data: { data: [4, 5, 6], signature: [7, 8, 9] },
})

const INVALID_SESSION_ENVELOPE = new TextEncoder().encode(
  JSON.stringify({ code: 10003, message: 'Invalid session ID', data: null })
)

describe('PvcApiClient.chat session recovery', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    vi.resetAllMocks()

    blind.mockReturnValue({
      message: 'blind-message',
      blindedMessage: new Uint8Array([1, 2, 3]),
    })
    unblind.mockReturnValue('blind-signature')
    generateEphemeral.mockReturnValue(new Uint8Array([9, 8, 7]))
    recvResponse.mockReturnValue({ encrypt: noiseEncrypt, decrypt: noiseDecrypt })
    noiseEncrypt.mockImplementation((b: Uint8Array) => b)
    noiseDecrypt.mockImplementation((b: Uint8Array) => b)
    encapsulateRequest.mockImplementation(async (request: Request) => ({
      encryptedRequest: new TextEncoder().encode(request.url),
      reader: {},
      feeder: {},
    }))

    // Default relay/identity stubs. Individual tests can override.
    global.fetch = vi.fn(async (input: RequestInfo | URL) => {
      const url = input.toString()
      if (url.includes('ohttp-configs')) {
        return new Response(new Uint8Array([0, 0, 1, 2, 3]).buffer, { status: 200 })
      }
      if (url.includes('/pubkey')) {
        return Response.json({ data: { n: 'AQ==', e: 'AQ==' } })
      }
      if (url.includes('/sign')) {
        return Response.json({ data: { signature: 'AQ==' } })
      }
      if (url.includes('http://localhost/ohttp-relay')) {
        return new Response(new Uint8Array([1, 2, 3]).buffer, { status: 200 })
      }
      throw new Error(`Unexpected fetch: ${url}`)
    }) as typeof fetch
  })

  afterEach(() => {
    global.fetch = originalFetch
  })

  it('re-handshakes and retries chat once on InvalidSessionId envelope', async () => {
    const handshakeVerifyingKey = new Uint8Array(64).fill(11)

    // init: /v1/handshake → /v1/establish
    decapsulateResponse
      .mockResolvedValueOnce(new Response(HANDSHAKE_BODY('sid-original', handshakeVerifyingKey)))
      .mockResolvedValueOnce(new Response(ESTABLISH_BODY))
      // recovery handshake after the first chat fails
      .mockResolvedValueOnce(new Response(HANDSHAKE_BODY('sid-fresh', handshakeVerifyingKey)))
      .mockResolvedValueOnce(new Response(ESTABLISH_BODY))

    // First chat: server replies with InvalidSessionId envelope; retry
    // chat returns a valid Noise-framed SSE chunk containing "hello".
    decapsulateResponseStream
      .mockReturnValueOnce(streamOfBytes(INVALID_SESSION_ENVELOPE))
      .mockReturnValueOnce(streamOfBytes(lengthPrefixedNoiseFrame(sseChunkBytes('hello'))))

    const client = new PvcApiClient()
    await client.init({
      identityServerUrl: 'http://localhost/identity',
      ohttpGatewayUrl: 'http://localhost/ohttp-gateway',
      ohttpRelayUrl: 'http://localhost/ohttp-relay',
      targetServerUrl: 'http://localhost:9000',
    })

    const result = await client.chat('say hi')

    expect(result).toBe('hello')
    // 2 chat attempts (original + post-recovery retry).
    expect(decapsulateResponseStream).toHaveBeenCalledTimes(2)
    // 4 envelope decapsulations total: 2 for init's handshake + establish,
    // 2 for the recovery's handshake + establish. Critically *not* 6,
    // which would indicate a second extraneous recovery cycle.
    expect(decapsulateResponse).toHaveBeenCalledTimes(4)
    // Recovery must have re-run `generate_ephemeral` exactly once.
    expect(generateEphemeral).toHaveBeenCalledTimes(2)
  })

  it('does not retry on a non-session-rejection error', async () => {
    const handshakeVerifyingKey = new Uint8Array(64).fill(11)

    decapsulateResponse
      .mockResolvedValueOnce(new Response(HANDSHAKE_BODY('sid-original', handshakeVerifyingKey)))
      .mockResolvedValueOnce(new Response(ESTABLISH_BODY))

    // Server emits a non-success envelope that is NOT InvalidSessionId
    // (here: NoiseDecryptFailed = 10004). The client must propagate the
    // error verbatim and must NOT touch the session.
    const otherErrorEnvelope = new TextEncoder().encode(
      JSON.stringify({ code: 10004, message: 'Noise decrypt failed', data: null })
    )
    decapsulateResponseStream.mockReturnValueOnce(streamOfBytes(otherErrorEnvelope))

    const client = new PvcApiClient()
    await client.init({
      identityServerUrl: 'http://localhost/identity',
      ohttpGatewayUrl: 'http://localhost/ohttp-gateway',
      ohttpRelayUrl: 'http://localhost/ohttp-relay',
      targetServerUrl: 'http://localhost:9000',
    })

    await expect(client.chat('say hi')).rejects.toThrow(/code=10004/)
    expect(decapsulateResponseStream).toHaveBeenCalledTimes(1)
    // No recovery: only the original init's two decapsulations.
    expect(decapsulateResponse).toHaveBeenCalledTimes(2)
  })

  it('does not loop: a second InvalidSessionId after recovery surfaces as SessionRejectedError', async () => {
    const handshakeVerifyingKey = new Uint8Array(64).fill(11)

    decapsulateResponse
      .mockResolvedValueOnce(new Response(HANDSHAKE_BODY('sid-original', handshakeVerifyingKey)))
      .mockResolvedValueOnce(new Response(ESTABLISH_BODY))
      .mockResolvedValueOnce(new Response(HANDSHAKE_BODY('sid-fresh', handshakeVerifyingKey)))
      .mockResolvedValueOnce(new Response(ESTABLISH_BODY))

    decapsulateResponseStream
      .mockReturnValueOnce(streamOfBytes(INVALID_SESSION_ENVELOPE))
      .mockReturnValueOnce(streamOfBytes(INVALID_SESSION_ENVELOPE))

    const client = new PvcApiClient()
    await client.init({
      identityServerUrl: 'http://localhost/identity',
      ohttpGatewayUrl: 'http://localhost/ohttp-gateway',
      ohttpRelayUrl: 'http://localhost/ohttp-relay',
      targetServerUrl: 'http://localhost:9000',
    })

    const err = await client.chat('say hi').catch((e) => e)
    expect(isSessionRejected(err)).toBe(true)
    expect(err).toBeInstanceOf(SessionRejectedError)
    // Exactly 2 chat attempts, not 3+.
    expect(decapsulateResponseStream).toHaveBeenCalledTimes(2)
  })
})
