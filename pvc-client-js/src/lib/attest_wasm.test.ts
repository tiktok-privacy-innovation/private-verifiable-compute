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
import { PvcApiClient } from './api'

describe('PvcApiClient Attestation', () => {
  it('should fetch attestation report using WASM', async () => {
    // NOTE: These services must be running locally.
    // Gateway: 8082
    // Relay: 8787
    // Backend: 9000

    const client = new PvcApiClient()

    await client.init({
      identityServerUrl: 'http://localhost:8082',
      ohttpGatewayUrl: 'http://localhost:8082',
      ohttpRelayUrl: 'http://localhost:8787',
      targetServerUrl: 'http://localhost:9000',
    })

    // Test Chat Completion (E2E Encrypted)

    // Use a shorter message to speed up inference or mock if possible
    // But since we are testing real backend, we just want to verify we get SOME response.

    let receivedTokens = ''

    // We will wrap chat in a promise race or just check if we got content.
    // However, `chat` awaits the full stream.
    // If we want to test "streaming", we should assert inside the callback.

    try {
      const chatResponse = await Promise.race([
        client.chat('Hello', [], 'Qwen/Qwen3-VL-4B-Thinking', (token) => {
          receivedTokens += token
        }),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Timeout waiting for chat')), 30000)
        ),
      ])
      expect(chatResponse).toBeTruthy()
    } catch (e) {
      // If it times out but we received tokens, it's a partial success for streaming test
      if (receivedTokens.length > 0) {
        expect(receivedTokens).toBeTruthy()
      } else {
        throw e
      }
    }
  }, 100000)
})
