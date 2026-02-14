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

import * as pvcWasm from 'pvc-wasm'
import { BHttpDecoder } from 'bhttp-js'
import { encodeBase64 } from './api'

const {
  init,
  OhttpEncapsulator,
  OhttpResponseReader,
  OhttpResponseFeeder,
  NoiseHandshake,
  NoiseSession,
  BlindSession,
  verify_noise_signature,
} = pvcWasm

export class WasmClient {
  private encapsulator: OhttpEncapsulator

  public NoiseHandshake = NoiseHandshake
  public NoiseSession = NoiseSession
  public BlindSession = BlindSession

  static async create(configBytes: Uint8Array): Promise<WasmClient> {
    init()
    const encapsulator = new OhttpEncapsulator(configBytes)
    return new WasmClient(encapsulator)
  }

  constructor(encapsulator: OhttpEncapsulator) {
    this.encapsulator = encapsulator
  }

  async encapsulateRequest(originalRequest: Request): Promise<{
    encryptedRequest: Uint8Array
    reader: OhttpResponseReader
    feeder: OhttpResponseFeeder
  }> {
    // ... (request preparation code) ...
    const method = originalRequest.method
    const url = new URL(originalRequest.url)
    const scheme = url.protocol.replace(':', '')
    const authority = url.host
    const path = url.pathname + url.search

    const body = originalRequest.body
      ? new Uint8Array(await originalRequest.arrayBuffer())
      : undefined

    const headers: Record<string, string> = {}
    originalRequest.headers.forEach((value, key) => (headers[key] = value))

    const result = await this.encapsulator.encapsulate(
      method,
      scheme,
      authority,
      path,
      body,
      headers
    )

    const [_req, reader, feeder] = result as [Uint8Array, OhttpResponseReader, OhttpResponseFeeder]

    const b64 = encodeBase64(_req)
    const encryptedRequest = new TextEncoder().encode(b64)
    console.log('Encrypted request length:', encryptedRequest.length)
    return { encryptedRequest, reader, feeder }
  }

  /**
   * Feed relay body chunks to OHTTP for decryption. Small chunks (e.g. 128 bytes from
   * gateway) can split an HPKE record and cause "a problem occurred with the AEAD".
   * AEAD errors are more common in Chrome incognito: no extensions and raw stream delivery
   * yield smaller chunks; normal mode often gets larger chunks (extensions or browser buffering).
   */
  decapsulateResponseStream(
    networkStream: ReadableStream<Uint8Array>,
    reader: OhttpResponseReader,
    feeder: OhttpResponseFeeder
  ): ReadableStream<Uint8Array> {
    const networkReader = networkStream.getReader()

    ;(async () => {
      try {
        while (true) {
          const { done, value } = await networkReader.read()
          if (done) {
            await feeder.close()
            break
          }
          if (value) {
            await feeder.feed(value)
          }
        }
      } catch {}
    })()

    return new ReadableStream({
      async pull(controller) {
        try {
          const chunk = await reader.read(4096)
          if (chunk && chunk.length > 0) {
            controller.enqueue(chunk)
          } else {
            controller.close()
          }
        } catch (e) {
          controller.error(e)
        }
      },
    })
  }

  async decapsulateResponse(
    response: Response,
    reader: OhttpResponseReader,
    feeder: OhttpResponseFeeder
  ): Promise<Response> {
    if (!response.body) throw new Error('No body')

    const stream = this.decapsulateResponseStream(response.body, reader, feeder)
    const chunks = []
    const readerStream = stream.getReader()

    while (true) {
      const { done, value } = await readerStream.read()
      if (done) break
      chunks.push(value)
    }

    const totalLen = chunks.reduce((acc, c) => acc + c.length, 0)
    const fullDecrypted = new Uint8Array(totalLen)
    let pos = 0
    for (const c of chunks) {
      fullDecrypted.set(c, pos)
      pos += c.length
    }

    const decoder = new BHttpDecoder()
    try {
      return decoder.decodeResponse(fullDecrypted)
    } catch (e) {
      return new Response(fullDecrypted, {
        status: 200,
        statusText: 'OK',
        headers: { 'Content-Type': 'application/octet-stream' },
      })
    }
  }

  // ... (verifyNoiseSignature) ...
  verifyNoiseSignature(
    verifyingKey: Uint8Array,
    ephemeral: Uint8Array,
    serverEphemeral: Uint8Array,
    signature: Uint8Array
  ): boolean {
    return verify_noise_signature(verifyingKey, ephemeral, serverEphemeral, signature)
  }
}

export { NoiseHandshake, NoiseSession, BlindSession, verify_noise_signature }
