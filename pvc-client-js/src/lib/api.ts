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

import { WasmClient } from './wasm_client'

const PATH_HANDSHAKE = '/v1/handshake'
const PATH_ESTABLISH = '/v1/establish'
const PATH_CHAT = '/v1/chat/completions'

/** Trustee attestation service: verifies TEE evidence before proceeding with handshake */
export type AttestationServiceConfig = {
  /** Base URL of the attestation service. In dev use same-origin proxy to avoid CORS (e.g. /attestation-service/attestation with Vite proxy to real trustee). */
  attestationServiceUrl: string
  /** Optional TEE type override; if omitted, uses backend-reported tee_type */
  teeType?: string
  /** Optional policy IDs to pass to the attestation service */
  policyIds?: string[]
}

type PvcApiClientInit = {
  identityServerUrl: string
  ohttpGatewayUrl: string
  ohttpRelayUrl: string
  targetServerUrl: string
  identityToken?: string
  /** If set, attestation report from handshake is sent to this service for verification before Noise handshake */
  attestationService?: AttestationServiceConfig
}

const baseOrigin =
  typeof window !== 'undefined' && window.location?.origin
    ? window.location.origin
    : 'http://localhost'

const resolveBaseUrl = (value: string) => {
  const base = new URL(value, baseOrigin)
  if (!base.pathname.endsWith('/')) {
    base.pathname = `${base.pathname}/`
  }
  return base
}

/**
 * Encodes a Uint8Array to a base64 string.
 * Supports both browser (btoa) and Node.js (Buffer) environments.
 * @param value The Uint8Array to encode
 * @returns Base64 encoded string
 * @throws Error if no base64 encoder is available
 */
export const encodeBase64 = (value: Uint8Array): string => {
  if (typeof btoa === 'function') {
    const binary = String.fromCharCode(...value)
    return btoa(binary)
  }
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(value).toString('base64')
  }
  throw new Error('No base64 encoder available')
}

/**
 * Decodes a base64 string to a Uint8Array.
 * Supports both browser (atob) and Node.js (Buffer) environments.
 * @param value The base64 string to decode
 * @returns Decoded Uint8Array
 * @throws Error if no base64 decoder is available
 */
const decodeBase64 = (value: string) => {
  if (typeof atob === 'function') {
    const binary = atob(value)
    return Uint8Array.from(binary, (c) => c.charCodeAt(0))
  }
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(value, 'base64'))
  }
  throw new Error('No base64 decoder available')
}

/**
 * Encodes data to base64url format without padding.
 * Trustee attestation service expects this specific format.
 * @param evidence The data to encode (string or object)
 * @returns Base64url encoded string without padding
 * @throws Error if no base64 encoder is available
 */
function toBase64urlNoPadding(evidence: unknown): string {
  let b64: string
  if (typeof evidence === 'string') {
    b64 = evidence.replace(/\s/g, '')
  } else {
    const json = JSON.stringify(evidence)
    if (typeof btoa !== 'undefined') {
      b64 = btoa(unescape(encodeURIComponent(json)))
    } else if (typeof Buffer !== 'undefined') {
      b64 = (Buffer as any).from(json, 'utf8').toString('base64')
    } else {
      throw new Error('No base64 encoder available')
    }
  }
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

/**
 * Decodes report data that can be in hex or base64 format.
 * Expects the decoded data to be exactly 64 bytes long.
 * @param value The report data string to decode
 * @returns Decoded report data as Uint8Array (64 bytes)
 * @throws Error if decoding fails or data length is invalid
 */
const decodeReportData = (value: string) => {
  const trimmed = value.trim()
  if (!trimmed) {
    throw new Error('Empty report_data')
  }

  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    const bytes = new Uint8Array(trimmed.length / 2)
    for (let i = 0; i < trimmed.length; i += 2) {
      bytes[i / 2] = Number.parseInt(trimmed.slice(i, i + 2), 16)
    }
    if (bytes.length === 64) {
      return bytes
    }
  }

  let decoded: Uint8Array | null = null
  if (typeof atob === 'function') {
    const binary = atob(trimmed)
    decoded = Uint8Array.from(binary, (c) => c.charCodeAt(0))
  } else if (typeof Buffer !== 'undefined') {
    decoded = new Uint8Array(Buffer.from(trimmed, 'base64'))
  }

  if (!decoded || decoded.length !== 64) {
    throw new Error('Invalid report_data encoding')
  }
  return decoded
}

/** Result from attestation service: JWT token (signed by trustee) and optional parsed payload for display. */
export type AttestationVerificationResult = {
  /** Raw response (JWT token or JSON body) from attestation service. */
  token: string
  /** TEE type used for verification (e.g. "tdx", "sample"). */
  teeType: string
  /** Decoded JWT payload for display; undefined if response is not a JWT. */
  payload?: Record<string, unknown>
}

/** One row for the attestation details table (key-value). */
export type AttestationDisplayRow = { key: string; value: string }

const TDX_DISPLAY_KEYS: { field: string; label: string }[] = [
  { field: 'report_data', label: 'Report Data' },
  { field: 'debug', label: 'Debug' },
  { field: 'tcb_status', label: 'TCB Status' },
  { field: 'mr_seam', label: 'MR_SEAM' },
  { field: 'mr_td', label: 'MR_TD' },
  { field: 'rtmr0', label: 'RTMR0' },
  { field: 'rtmr1', label: 'RTMR1' },
  { field: 'rtmr2', label: 'RTMR2' },
  { field: 'rtmr3', label: 'RTMR3' },
  { field: 'tcb_svn', label: 'TCB SVN' },
]

/** Extract evidence object from Veraison EAR submods (ear.veraison.annotated-evidence). */
function getAnnotatedEvidenceFromSubmods(
  payload: Record<string, unknown>
): Record<string, unknown> | null {
  const submods = payload?.submods as Record<string, unknown> | undefined
  if (!submods || typeof submods !== 'object') return null
  const first = Object.values(submods)[0] as Record<string, unknown> | undefined
  if (!first || typeof first !== 'object') return null
  const ann = first['ear.veraison.annotated-evidence'] ?? first['annotated-evidence'] ?? first
  if (ann && typeof ann === 'object') return ann as Record<string, unknown>
  return null
}

/** Extract report_data from attestation result JWT payload (for handshake). Supports both TDX and sample EAR. */
function getReportDataFromAttestationPayload(
  payload: Record<string, unknown> | null | undefined
): string {
  if (!payload) return ''
  const evidence = getAnnotatedEvidenceFromSubmods(payload)
  if (!evidence || typeof evidence.report_data !== 'string') return ''
  return evidence.report_data
}

/** Get nested value from object by path (e.g. "tdx.quote.body.mr_seam"). */
function getNestedVal(obj: Record<string, unknown>, path: string): string {
  const parts = path.split('.')
  let cur: unknown = obj
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return ''
    cur = (cur as Record<string, unknown>)[p]
  }
  if (cur == null) return ''
  if (typeof cur === 'boolean') return String(cur)
  if (Array.isArray(cur)) return cur.join(', ')
  return String(cur)
}

/** Build attestation table rows from result: sample → Report Data + sample fields; tdx → Report Data + TDX fields from JWT. */
export function getAttestationDisplayRows(
  result: AttestationVerificationResult
): AttestationDisplayRow[] {
  const rows: AttestationDisplayRow[] = []
  const teeLabel = result.teeType === 'tdx' ? 'Intel TDX' : result.teeType
  rows.push({ key: 'TEE', value: teeLabel })

  const evidence = result.payload ? getAnnotatedEvidenceFromSubmods(result.payload) : null
  if (!evidence) return rows

  const getVal = (key: string): string => {
    const v = evidence[key] ?? evidence[key.replace(/_/g, '-')]
    if (v == null) return ''
    if (typeof v === 'boolean') return String(v)
    return String(v)
  }

  if (result.teeType === 'sample') {
    rows.push({ key: 'Report Data', value: getVal('report_data') })
    const sample = evidence.sample as Record<string, unknown> | undefined
    if (sample && typeof sample === 'object') {
      if (sample.debug != null) rows.push({ key: 'Debug', value: String(sample.debug) })
      if (sample.launch_digest != null)
        rows.push({ key: 'Launch Digest', value: String(sample.launch_digest) })
      if (sample.svn != null) rows.push({ key: 'SVN', value: String(sample.svn) })
    }
    return rows
  }

  if (result.teeType === 'tdx') {
    // JWT structure: evidence.report_data (top-level), evidence.tdx.{ quote.body.*, tcb_status, td_attributes.debug, advisory_ids, ... }
    const tdx = evidence.tdx as Record<string, unknown> | undefined
    const body =
      tdx?.quote && typeof tdx.quote === 'object'
        ? ((tdx.quote as Record<string, unknown>).body as Record<string, unknown> | undefined)
        : undefined
    const tdAttrs =
      tdx?.td_attributes && typeof tdx.td_attributes === 'object'
        ? (tdx.td_attributes as Record<string, unknown>)
        : undefined

    rows.push({ key: 'Report Data', value: getVal('report_data') })
    rows.push({
      key: 'Debug',
      value:
        tdAttrs?.debug != null
          ? String(tdAttrs.debug)
          : getNestedVal(evidence, 'tdx.td_attributes.debug'),
    })
    rows.push({
      key: 'TCB Status',
      value: tdx?.tcb_status != null ? String(tdx.tcb_status) : getVal('tcb_status'),
    })
    rows.push({
      key: 'MR_SEAM',
      value: body?.mr_seam != null ? String(body.mr_seam) : getVal('mr_seam'),
    })
    rows.push({ key: 'MR_TD', value: body?.mr_td != null ? String(body.mr_td) : getVal('mr_td') })
    rows.push({ key: 'RTMR0', value: body?.rtmr_0 != null ? String(body.rtmr_0) : getVal('rtmr0') })
    rows.push({ key: 'RTMR1', value: body?.rtmr_1 != null ? String(body.rtmr_1) : getVal('rtmr1') })
    rows.push({ key: 'RTMR2', value: body?.rtmr_2 != null ? String(body.rtmr_2) : getVal('rtmr2') })
    rows.push({ key: 'RTMR3', value: body?.rtmr_3 != null ? String(body.rtmr_3) : getVal('rtmr3') })
    rows.push({
      key: 'TCB SVN',
      value: body?.tcb_svn != null ? String(body.tcb_svn) : getVal('tcb_svn'),
    })
    if (tdx?.advisory_ids && Array.isArray(tdx.advisory_ids)) {
      rows.push({ key: 'Advisory IDs', value: (tdx.advisory_ids as string[]).join(', ') })
    }
    // Show attestation JWT token expiration (exp)
    if (result.payload?.exp != null) {
      const expVal = result.payload.exp
      const expStr =
        typeof expVal === 'number'
          ? new Date(expVal * 1000).toISOString()
          : String(expVal)
      rows.push({ key: 'Token Expiration', value: expStr })
    }
    if (tdx?.platform_provider_id != null) {
      rows.push({ key: 'Platform Provider ID', value: String(tdx.platform_provider_id) })
    }
    return rows
  }

  rows.push({ key: 'Report Data', value: getVal('report_data') })
  return rows
}

/** Decode JWT payload (middle part) without verification; for display only. */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.trim().split('.')
    if (parts.length !== 3) return null
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const pad = base64.length % 4
    const padded = pad ? base64 + '='.repeat(4 - pad) : base64
    let raw: string
    if (typeof atob !== 'undefined') {
      raw = atob(padded)
    } else {
      return null
    }
    const json = decodeURIComponent(escape(raw))
    return JSON.parse(json) as Record<string, unknown>
  } catch {
    return null
  }
}

/** Call trustee attestation service to verify TEE evidence. Returns attestation result (JWT); throws if verification fails. */
async function verifyAttestationWithTrustee(
  attestationServiceUrl: string,
  tee: string,
  evidence: unknown,
  policyIds: string[] = []
): Promise<AttestationVerificationResult> {
  const evidenceStr = toBase64urlNoPadding(evidence)
  const body: AttestationVerificationRequest = {
    verification_requests: [{ tee, evidence: evidenceStr }],
    policy_ids: policyIds,
  }
  const url = attestationServiceUrl.replace(/\/$/, '')
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
  const text = await res.text()
  if (!res.ok) {
    throw new Error(`Attestation verification failed (${res.status}): ${text || res.statusText}`)
  }
  let token = text
  try {
    const parsed = JSON.parse(text) as { token?: string }
    if (typeof parsed?.token === 'string') token = parsed.token
  } catch {
    /* response is raw JWT */
  }
  const payload = decodeJwtPayload(token)
  return { token, teeType: tee, payload: payload ?? undefined }
}

export class PvcApiClient {
  private wasmClient: WasmClient | null = null
  private noiseHandshakeState: any | null = null
  private noiseSession: any | null = null
  private sessionId: string | null = null
  private identityAuthToken: string | null = null
  private identityMessage: string | null = null
  private identitySignature: string | null = null
  private identityServerUrl: string | null = null
  private ohttpGatewayUrl: string | null = null
  private ohttpRelayUrl: string | null = null
  private targetServerUrl: string | null = null
  private attestationResult: AttestationVerificationResult | null = null

  constructor() {}

  /** Attestation verification result (JWT + decoded payload) after init; null if attestation was not run. */
  getAttestationResult(): AttestationVerificationResult | null {
    return this.attestationResult
  }

  async init({
    identityServerUrl,
    ohttpGatewayUrl,
    ohttpRelayUrl,
    targetServerUrl,
    identityToken,
    attestationService,
  }: PvcApiClientInit) {
    if (this.wasmClient && this.noiseSession) {
      return
    }
    this.identityServerUrl = identityServerUrl
    this.ohttpGatewayUrl = ohttpGatewayUrl
    this.ohttpRelayUrl = ohttpRelayUrl
    this.targetServerUrl = targetServerUrl
    if (identityToken) {
      this.identityAuthToken = identityToken
    }

    const gatewayBase = resolveBaseUrl(this.ohttpGatewayUrl)
    const configUrl = new URL('ohttp-configs', gatewayBase).toString()
    const configResp = await fetch(configUrl)
    if (!configResp.ok) throw new Error('Failed to fetch OHTTP config')
    const configBytes = new Uint8Array(await configResp.arrayBuffer())
    const configs = configBytes.slice(2)

    this.wasmClient = await WasmClient.create(configs)

    await this.prepareIdentityToken()
    const headers: Record<string, string> = {
      'Content-Type': 'application/octet-stream',
      'X-Identity-Token': this.identitySignature,
      'X-Identity-Message': this.identityMessage,
    }

    const respBody = await this.ohttpPost(PATH_HANDSHAKE, headers, new Uint8Array(0))
    const respText = new TextDecoder().decode(respBody)

    try {
      const json = JSON.parse(respText) as Record<string, unknown>
      // Backend may return { data: { sid, tee_type, evidence } } or top-level { sid, tee_type, evidence } (e.g. pvc-tee-llm AttestationResponse)
      const data = (json?.data != null && typeof json.data === 'object' ? json.data : json) as {
        sid?: string
        tee_type?: string
        evidence?: unknown & { report_data?: string }
      }
      console.debug('[PVC] handshake response data:', data)

      let reportData = ''

      if (data?.sid) {
        this.sessionId = data.sid
      }

      // If trustee attestation service is configured, verify evidence first; report_data then comes from attestation result JWT
      if (attestationService?.attestationServiceUrl && data?.evidence != null) {
        const tee =
          attestationService.teeType ?? (typeof data?.tee_type === 'string' ? data.tee_type : 'tdx')
        const policyIds = attestationService.policyIds ?? []
        // For TDX, attestation verification service expects field name "TdQuote" instead of "quote"
        let evidenceForVerify: unknown = data.evidence
        if (
          tee === 'tdx' &&
          data.evidence &&
          typeof data.evidence === 'object' &&
          'quote' in data.evidence
        ) {
          const raw = data.evidence as Record<string, unknown>
          evidenceForVerify = Object.fromEntries(
            Object.entries(raw).map(([k, v]) => (k === 'quote' ? ['TdQuote', v] : [k, v]))
          )
        }
        this.attestationResult = await verifyAttestationWithTrustee(
          attestationService.attestationServiceUrl,
          tee,
          evidenceForVerify,
          policyIds
        )
        reportData = getReportDataFromAttestationPayload(this.attestationResult?.payload ?? null)
      } else if (
        data?.evidence &&
        typeof data.evidence === 'object' &&
        (data.evidence as Record<string, unknown>).report_data
      ) {
        reportData = (data.evidence as Record<string, unknown>).report_data as string
      }

      // Start Noise Handshake using the report data (public key)
      if (reportData) {
        await this.handshake(reportData)
      } else {
        const errMsg =
          'No report data found in attestation response. Cannot proceed with handshake.'
        console.warn('[PVC]', errMsg)
        throw new Error(errMsg)
      }
    } catch (e) {
      console.error('[PVC] Failed to parse attestation response or perform handshake:', e)
      throw e
    }
  }

  // Helper to perform OHTTP POST using WasmClient
  private async ohttpPost(
    path: string,
    headers: Record<string, string>,
    body?: Uint8Array
  ): Promise<Uint8Array> {
    if (!this.wasmClient) throw new Error('WasmClient not initialized')
    if (!this.ohttpRelayUrl || !this.targetServerUrl) {
      throw new Error('PvcApiClient not initialized')
    }

    const targetBase = resolveBaseUrl(this.targetServerUrl)
    const targetUrl = new URL(path.replace(/^\//, ''), targetBase).toString()
    const requestInit: RequestInit = {
      method: 'POST',
      headers: headers,
    }
    if (body) {
      requestInit.body = body
    }

    const request = new Request(targetUrl, requestInit)
    const { encryptedRequest, reader, feeder } = await this.wasmClient.encapsulateRequest(request)

    const relayUrl = new URL(this.ohttpRelayUrl, baseOrigin).toString()
    const relayResponse = await fetch(relayUrl, {
      method: 'POST',
      body: encryptedRequest,
      headers: {
        'Content-Type': 'message/ohttp-req',
        Connection: 'close',
      },
    })

    if (!relayResponse.ok) {
      throw new Error(`Relay request failed: ${relayResponse.status}`)
    }

    const decapsulatedResponse = await this.wasmClient.decapsulateResponse(
      relayResponse,
      reader,
      feeder
    )
    return new Uint8Array(await decapsulatedResponse.arrayBuffer())
  }

  private async prepareIdentityToken() {
    if (!this.wasmClient) throw new Error('WasmClient not initialized')
    if (!this.identityServerUrl) {
      throw new Error('Identity server URL missing')
    }
    const identityBase = resolveBaseUrl(this.identityServerUrl)
    const pubkeyBase = identityBase
    const pubkeyUrl = new URL('pubkey', pubkeyBase).toString()
    const pubkeyResp = await fetch(pubkeyUrl)
    if (!pubkeyResp.ok) {
      throw new Error(`Identity server pubkey failed: ${pubkeyResp.status}`)
    }
    const pubkeyJson = await pubkeyResp.json()
    const pubkeyData = pubkeyJson.data ?? pubkeyJson
    const n = pubkeyData?.n
    const e = pubkeyData?.e
    if (!n || !e) {
      throw new Error('Identity server pubkey missing n/e')
    }
    const blindSession = new this.wasmClient.BlindSession(n, e)
    const blindResult = blindSession.blind() as {
      message: string
      blindedMessage: Uint8Array
    }
    const signUrl = new URL('sign', pubkeyBase).toString()
    const signHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
    }
    if (this.identityAuthToken) {
      signHeaders.Authorization = `Bearer ${this.identityAuthToken}`
    }
    const signResp = await fetch(signUrl, {
      method: 'POST',
      headers: signHeaders,
      body: JSON.stringify({
        blindedMessage: Array.from(blindResult.blindedMessage),
      }),
    })
    if (!signResp.ok) {
      throw new Error(`Identity server sign failed: ${signResp.status}`)
    }
    const signJson = await signResp.json()
    if (typeof signJson.code === 'number' && signJson.code !== 0) {
      throw new Error(signJson.message || 'Identity server sign failed')
    }
    const signatureB64 = signJson.data?.signature ?? signJson.signature
    if (!signatureB64) {
      throw new Error('Identity server signature missing')
    }
    const signatureBytes = decodeBase64(signatureB64)
    const token = blindSession.unblind(signatureBytes)
    this.identityMessage = blindResult.message
    this.identitySignature = token
  }

  async handshake(reportData: string) {
    if (!this.wasmClient) throw new Error('WasmClient not initialized')
    if (this.noiseSession) return
    if (!this.identitySignature || !this.identityMessage) {
      await this.prepareIdentityToken()
    }
    if (!this.identitySignature || !this.identityMessage) {
      throw new Error('Identity token unavailable')
    }

    // 1. Initialize Noise Initiator
    // Use WASM implementation
    this.noiseHandshakeState = new this.wasmClient.NoiseHandshake()

    // 2. Generate Ephemeral Key (as client nonce)
    const ephemeral = this.noiseHandshakeState.generate_ephemeral()
    // 3. Prepare headers
    const headers: Record<string, string> = {
      'Content-Type': 'application/octet-stream',
      'X-Identity-Token': this.identitySignature,
      'X-Identity-Message': this.identityMessage,
    }
    if (this.sessionId) {
      headers['X-Session-ID'] = this.sessionId
    }

    // 4. Send /establish request
    const respBody = await this.ohttpPost(PATH_ESTABLISH, headers, ephemeral)
    const respText = new TextDecoder().decode(respBody)

    // 5. Parse Response
    // Rust expects `HandShakeResp { data: Vec<u8>, signature: Vec<u8> }`
    try {
      const json = JSON.parse(respText)
      if (json.code !== 0) {
        throw new Error(`Handshake failed with code ${json.code}: ${json.message}`)
      }

      const handshakeResp = json.data // { data: number[], signature: number[] }
      if (!handshakeResp || !handshakeResp.data || !handshakeResp.signature) {
        throw new Error('Invalid handshake response format')
      }

      const serverEphemeral = new Uint8Array(handshakeResp.data)
      const signature = new Uint8Array(handshakeResp.signature)
      if (serverEphemeral.length === 0 || signature.length === 0) {
        throw new Error('Handshake payload missing')
      }

      // 6. Verify Signature
      // `verify_noise_script_signature(verifying_key, &ephemeral, &resp.data, &resp.signature)?;`
      // `verifying_key` comes from `attest` report data.
      // We need to decode `reportData` (base64) -> verifying_key (64 bytes).

      const verifyingKey = decodeReportData(reportData)
      // Verify signature: verify(vk, client_ephemeral || server_ephemeral, signature)
      // We need to use `verify_noise_signature` from WASM.

      const isValid = this.wasmClient.verifyNoiseSignature(
        verifyingKey,
        ephemeral,
        serverEphemeral,
        signature
      )
      if (!isValid) {
        throw new Error('Noise signature verification failed!')
      }
      // 7. Finish Handshake
      // `noise_initiator.recv_response(&resp.data)?;`
      this.noiseSession = this.noiseHandshakeState.recv_response(serverEphemeral)
    } catch (e) {
      console.error('Handshake failed:', e)
      throw e
    }
  }

  async chat(
    message: string,
    history: any[] = [],
    model: string = 'Qwen/Qwen3-VL-4B-Thinking',
    onToken?: (token: string) => void,
    options?: { enableThinking?: boolean; onReasoning?: (token: string) => void }
  ) {
    if (!this.noiseSession) throw new Error('Secure channel not established')

    const messages = [...history, { role: 'user', content: message }]
    const input: Record<string, any> = { messages, stream: true }
    if (options?.enableThinking) {
      // DeepSeek-style thinking mode: https://api-docs.deepseek.com/guides/thinking_mode
      input.thinking = { type: 'enabled' }
      input.extra_body = {
        ...(input.extra_body ?? {}),
        chat_template_kwargs: { enable_thinking: true },
      }
    } else {
      // Explicitly disable thinking when model may default to thinking mode
      input.thinking = { type: 'disabled' }
      input.extra_body = {
        ...(input.extra_body ?? {}),
        chat_template_kwargs: { enable_thinking: false },
      }
    }
    const plaintext = new TextEncoder().encode(JSON.stringify(input))
    const ciphertext = this.noiseSession.encrypt(plaintext)
    const headers: Record<string, string> = { 'Content-Type': 'application/octet-stream' }
    if (this.sessionId) headers['X-Session-ID'] = this.sessionId

    // We need to fetch and read the stream
    if (!this.targetServerUrl || !this.ohttpRelayUrl) {
      throw new Error('PvcApiClient not initialized')
    }
    const targetBase = resolveBaseUrl(this.targetServerUrl)
    const targetUrl = new URL(PATH_CHAT.replace(/^\//, ''), targetBase).toString()
    const requestInit: RequestInit = {
      method: 'POST',
      headers: headers,
      // Body will be set later but type def needs it?
      // We will pass it to wasm encapsulation.
    }

    // Encapsulate Request using WASM
    if (!this.wasmClient) throw new Error('WasmClient not initialized')

    // Manually set body for encapsulation.
    // Note: Request constructor takes body.
    const encRequest = new Request(targetUrl, {
      method: 'POST',
      headers: headers,
      body: ciphertext,
    })

    const {
      encryptedRequest,
      reader: ohttpReader,
      feeder: ohttpFeeder,
    } = await this.wasmClient.encapsulateRequest(encRequest)

    const relayUrl = new URL(this.ohttpRelayUrl, baseOrigin).toString()
    const relayResponse = await fetch(relayUrl, {
      method: 'POST',
      body: encryptedRequest,
      headers: {
        'Content-Type': 'message/ohttp-req',
      },
    })

    if (!relayResponse.ok) {
      throw new Error(`Relay request failed: ${relayResponse.status}`)
    }

    if (!relayResponse.body) throw new Error('Response has no body')

    // Use decapsulateResponseStream to get the inner stream (still encrypted/framed by Noise).
    // OHTTP (HPKE) response has record framing; feeding tiny chunks that split a record can cause
    // "a problem occurred with the AEAD". We feed in larger chunks (see wasm_client) to reduce that.
    let decryptedOhttpStream: ReadableStream<Uint8Array>
    try {
      const stream = this.wasmClient.decapsulateResponseStream(
        relayResponse.body,
        ohttpReader,
        ohttpFeeder
      )
      if (!stream || typeof (stream as ReadableStream).getReader !== 'function') {
        throw new Error('decapsulateResponseStream did not return a valid ReadableStream')
      }
      decryptedOhttpStream = stream
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e)
      throw new Error(`OHTTP response decapsulation failed: ${msg}`)
    }
    const reader = decryptedOhttpStream.getReader()

    let buffer = new Uint8Array(0)
    let combinedResponse = ''
    let totalReadBytes = 0

    // Max reasonable frame payload (10MB); larger suggests first 4 bytes are not our length header (e.g. HTML/text)
    const MAX_FRAME_PAYLOAD = 10 * 1024 * 1024

    // Process complete frames in buffer (4-byte big-endian length + payload)
    const processBufferFrames = (): void => {
      while (buffer.length >= 4) {
        const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength)
        const frameLen = view.getUint32(0, false)

        if (frameLen > MAX_FRAME_PAYLOAD) break // Not our protocol: first 4 bytes look like ASCII, parsed as huge length

        if (buffer.length < 4 + frameLen) break

        const frameData = buffer.slice(4, 4 + frameLen)
        buffer = buffer.slice(4 + frameLen)

        try {
          const decryptedChunk = this.noiseSession.decrypt(frameData)
          const chunkText = new TextDecoder().decode(decryptedChunk)

          // Parse SSE stream
          const lines = chunkText.split('\n')
          for (const line of lines) {
            const trimmed = line.trim()
            if (!trimmed || !trimmed.startsWith('data: ')) continue

            const data = trimmed.slice(6)
            if (data === '[DONE]') continue

            try {
              const json = JSON.parse(data)
              const contentDelta = json.choices?.[0]?.delta?.content
              const reasoningDelta =
                json.choices?.[0]?.delta?.reasoning_content ?? json.choices?.[0]?.delta?.reasoning
              if (reasoningDelta != null && reasoningDelta !== '' && options?.onReasoning) {
                options.onReasoning(reasoningDelta)
              }
              if (contentDelta) {
                combinedResponse += contentDelta
                if (onToken) {
                  onToken(contentDelta)
                }
              }
            } catch (e) {
              console.warn('Failed to parse SSE data:', data)
            }
          }
        } catch (e: unknown) {
          const errMsg =
            e instanceof Error
              ? e.message
              : typeof e === 'object' && e != null && 'toString' in e
                ? String((e as Error).toString())
                : String(e)
          console.error(
            '[PVC] Decryption failed:',
            errMsg,
            'frameLen:',
            frameLen,
            'frameData.byteLength:',
            frameData.byteLength,
            'error:',
            e
          )
          throw e
        }
      }
    }

    while (true) {
      const { done, value } = await reader.read()
      if (done) {
        processBufferFrames()
        if (buffer.length > 0) {
          const view = new DataView(buffer.buffer, buffer.byteOffset, Math.min(4, buffer.length))
          const declaredLen = buffer.length >= 4 ? view.getUint32(0, false) : 0
          const wantLen = 4 + declaredLen
          const firstBytesHex =
            Array.from(buffer.slice(0, Math.min(16, buffer.length)))
              .map((b) => b.toString(16).padStart(2, '0'))
              .join(' ')
          const firstChars = new TextDecoder().decode(buffer.slice(0, Math.min(80, buffer.length))).replace(/[\x00-\x1f]/g, '.')
          if (declaredLen > MAX_FRAME_PAYLOAD) {
            const fullBodyText = new TextDecoder().decode(buffer)
            console.error(
              '[PVC] Stream data is not our binary frame format (expected 4-byte length + Noise payload).',
              'First bytes (hex):',
              firstBytesHex,
              '— likely HTML/error page from relay or wrong decapsulation.'
            )
            console.error('[PVC] Full response body (decoded as text), length:', buffer.length, 'chars:')
            console.error(fullBodyText)
            throw new Error(
              `OHTTP response body is not PVC frame format (looks like text/HTML). First bytes: ${firstChars.slice(0, 60)}… Full body logged above.`
            )
          }
          console.warn(
            '[PVC] Stream ended with incomplete frame. buffer remaining:',
            buffer.length,
            'need at least:',
            wantLen,
            'combinedResponse length:',
            combinedResponse.length
          )
        } else {
          console.debug('[PVC] Stream ended. totalReadBytes:', totalReadBytes, 'combinedResponse length:', combinedResponse.length)
        }
        break
      }
      if (!value) continue
      totalReadBytes += value.length

      // Append new data to buffer
      const newBuffer = new Uint8Array(buffer.length + value.length)
      newBuffer.set(buffer)
      newBuffer.set(value, buffer.length)
      buffer = newBuffer

      processBufferFrames()
    }

    return combinedResponse
  }
}
