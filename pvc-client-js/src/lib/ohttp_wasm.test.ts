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

import { describe, it, expect } from 'vitest'
import { WasmClient } from './wasm_client'

describe('OhttpClient WASM Integration', () => {
  it('should fetch config and send a request successfully using WASM', async () => {
    // NOTE: These services must be running locally for this test to pass.
    // Gateway: 8082
    // Relay: 8787
    // Backend (TEE LLM): 9000

    const gatewayUrl = 'http://localhost:8082'
    const relayUrl = 'http://localhost:8787'
    const targetAuthority = 'localhost:9000'

    const configResp = await fetch(`${gatewayUrl}/ohttp-configs`)
    if (!configResp.ok) {
      throw new Error(`Failed to fetch config: ${configResp.status}`)
    }
    const configBytes = new Uint8Array(await configResp.arrayBuffer())

    // The config response is a list of KeyConfigs, prefixed by a 2-byte length.
    // We assume we want the first config.
    const configs = configBytes.slice(2)

    const client = await WasmClient.create(configs)
    const targetUrl = `http://${targetAuthority}/health`
    const request = new Request(targetUrl, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })

    const { encryptedRequest, reader, feeder } = await client.encapsulateRequest(request)

    const relayResponse = await fetch(relayUrl, {
      method: 'POST',
      body: encryptedRequest,
      headers: {
        'Content-Type': 'message/ohttp-req',
      },
    })

    if (!relayResponse.ok) {
      const text = await relayResponse.text()
      throw new Error(`Relay failed: ${relayResponse.status} - ${text}`)
    }

    const decapsulatedResponse = await client.decapsulateResponse(relayResponse, reader, feeder)

    const responseText = await decapsulatedResponse.text()
    expect(responseText).toContain('Success')
  })
})
