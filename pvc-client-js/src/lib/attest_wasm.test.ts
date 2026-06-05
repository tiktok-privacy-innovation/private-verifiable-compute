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

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { PvcApiClient, encodeBase64 } from './api'

const verifyNoiseSignature = vi.fn(() => true)
const encapsulateRequest = vi.fn()
const decapsulateResponse = vi.fn()
const blind = vi.fn()
const unblind = vi.fn()
const generateEphemeral = vi.fn()
const recvResponse = vi.fn(() => ({ encrypt: vi.fn(), decrypt: vi.fn() }))

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

    verifyNoiseSignature = verifyNoiseSignature
  }

  return { WasmClient: MockWasmClient }
})

describe('PvcApiClient Attestation', () => {
  const originalFetch = global.fetch

  beforeEach(() => {
    vi.resetAllMocks()

    blind.mockReturnValue({
      message: 'blind-message',
      blindedMessage: new Uint8Array([1, 2, 3]),
    })
    unblind.mockReturnValue('blind-signature')
    generateEphemeral.mockReturnValue(new Uint8Array([9, 8, 7]))
    recvResponse.mockReturnValue({ encrypt: vi.fn(), decrypt: vi.fn() })

    encapsulateRequest.mockImplementation(async (request: Request) => ({
      encryptedRequest: new TextEncoder().encode(request.url),
      reader: {},
      feeder: {},
    }))
    decapsulateResponse.mockResolvedValue(
      new Response(JSON.stringify({ code: 0, data: { data: [4, 5, 6], signature: [7, 8, 9] } }))
    )
  })

  afterEach(() => {
    global.fetch = originalFetch
  })

  it('uses binding.handshake_verifying_key and session.id from the normalized handshake contract', async () => {
    const handshakeVerifyingKey = new Uint8Array(64).fill(11)

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

    decapsulateResponse
      .mockResolvedValueOnce(
        new Response(
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
              session: {
                id: 'session-123',
              },
            },
          })
        )
      )
      .mockResolvedValueOnce(
        new Response(JSON.stringify({ code: 0, data: { data: [4, 5, 6], signature: [7, 8, 9] } }))
      )

    const client = new PvcApiClient()
    await client.init({
      identityServerUrl: 'http://localhost/identity',
      ohttpGatewayUrl: 'http://localhost/ohttp-gateway',
      ohttpRelayUrl: 'http://localhost/ohttp-relay',
      targetServerUrl: 'http://localhost:9000',
    })

    expect(verifyNoiseSignature).toHaveBeenCalledWith(
      handshakeVerifyingKey,
      new Uint8Array([9, 8, 7]),
      new Uint8Array([4, 5, 6]),
      new Uint8Array([7, 8, 9])
    )

    const establishRequest = encapsulateRequest.mock.calls[1]?.[0] as Request
    expect(establishRequest.headers.get('X-Session-ID')).toBe('session-123')
  })

  it('fails clearly when handshake binding material is missing', async () => {
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

    decapsulateResponse.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          code: 0,
          data: {
            attestation: {
              cpu: {
                tee_type: 'sample',
                evidence: { report_data: encodeBase64(new Uint8Array(64).fill(3)) },
              },
            },
            session: {
              id: 'session-123',
            },
          },
        })
      )
    )

    const client = new PvcApiClient()
    await expect(
      client.init({
        identityServerUrl: 'http://localhost/identity',
        ohttpGatewayUrl: 'http://localhost/ohttp-gateway',
        ohttpRelayUrl: 'http://localhost/ohttp-relay',
        targetServerUrl: 'http://localhost:9000',
      })
    ).rejects.toThrow('Handshake binding material missing')
  })
})
