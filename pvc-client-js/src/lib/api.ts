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

/**
 * Backend ApiCode for "the session ID you sent is unknown or expired".
 * Mirrors `types::ApiCode::InvalidSessionId` (10003) — when the tee-llm
 * pod restarts or evicts the session, the request guard surfaces this
 * code in the JSON envelope and the client must re-handshake.
 */
const INVALID_SESSION_ID_CODE = 10003

/**
 * Thrown by `PvcApiClient.chat` (and friends) when the backend rejects
 * the current `sid`. Used as the sole signal for the single-shot
 * re-handshake-and-retry path inside `chat`.
 */
export class SessionRejectedError extends Error {
  readonly code: number
  constructor(message: string, code: number = INVALID_SESSION_ID_CODE) {
    super(message)
    this.name = 'SessionRejectedError'
    this.code = code
  }
}

/**
 * True when an error from the secure-request path indicates that the
 * server-side `sid` is no longer valid and the client should re-handshake.
 *
 * Strict mode: only `SessionRejectedError`. We intentionally do NOT do the
 * fuzzy "502 / 'InvalidSessionId' substring" match that the Rust client
 * does — the JS path always goes through the OHTTP gateway which we control
 * end-to-end, so a structured envelope is always available. Keeping the
 * detector narrow avoids spurious recovery on unrelated transport blips.
 */
export function isSessionRejected(err: unknown): err is SessionRejectedError {
  return err instanceof SessionRejectedError
}

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

type ApiResponse<T> = {
  code?: number
  message?: string
  data?: T
}

type AttestationEvidence = {
  tee_type: string
  evidence: unknown
}

type AttestationEnvelope = {
  cpu: AttestationEvidence
  devices?: AttestationEvidence[]
}

type BindingMaterial = {
  handshake_verifying_key: string
}

type SessionInfo = {
  id: string
}

type HandshakeAttestationResponse = {
  attestation: AttestationEnvelope
  binding?: BindingMaterial
  session?: SessionInfo
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

function parseHandshakeResponse(payload: unknown): HandshakeAttestationResponse {
  if (!payload || typeof payload !== 'object') {
    throw new Error('Handshake response payload missing')
  }

  const response = payload as HandshakeAttestationResponse
  if (!response.attestation || typeof response.attestation !== 'object') {
    throw new Error('Handshake attestation missing')
  }
  if (!response.attestation.cpu || typeof response.attestation.cpu !== 'object') {
    throw new Error('Handshake CPU attestation missing')
  }
  if (!response.binding?.handshake_verifying_key) {
    throw new Error('Handshake binding material missing')
  }
  if (!response.session?.id) {
    throw new Error('Handshake session missing')
  }

  return response
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
        typeof expVal === 'number' ? new Date(expVal * 1000).toISOString() : String(expVal)
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
  /**
   * Cached so the session recovery path (driven by `chat` on
   * `SessionRejectedError`) can re-run handshake + optional trustee
   * verification with the same configuration the original `init` used.
   */
  private attestationServiceConfig: AttestationServiceConfig | null = null
  /**
   * Coalesces concurrent recovery attempts. If two `chat` calls run in
   * parallel and both observe `InvalidSessionId`, the second one awaits
   * the first one's handshake instead of issuing a redundant
   * `/v1/handshake` + `/v1/establish` pair.
   */
  private recoveryInFlight: Promise<void> | null = null

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
    this.attestationServiceConfig = attestationService ?? null
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

    await this.performSessionHandshake()
  }

  /**
   * Performs `POST /v1/handshake` + optional trustee verification + Noise
   * `POST /v1/establish`. Extracted from `init` so that
   * [`recoverSession`] can re-run the same flow after the backend evicts
   * our `sid`. Assumes `wasmClient` is already created — i.e. that
   * `init` (which fetches OHTTP configs) has already been called once.
   */
  private async performSessionHandshake() {
    if (!this.wasmClient) {
      throw new Error('WasmClient not initialized; call init() first')
    }

    await this.prepareIdentityToken()
    const headers: Record<string, string> = {
      'Content-Type': 'application/octet-stream',
      'X-Identity-Token': this.identitySignature,
      'X-Identity-Message': this.identityMessage,
    }

    const respBody = await this.ohttpPost(PATH_HANDSHAKE, headers, new Uint8Array(0))
    const respText = new TextDecoder().decode(respBody)

    try {
      const json = JSON.parse(respText) as ApiResponse<HandshakeAttestationResponse>
      if (typeof json.code === 'number' && json.code !== 0) {
        throw new Error(
          `Handshake attestation failed with code ${json.code}: ${json.message ?? ''}`
        )
      }

      const data = parseHandshakeResponse(json.data)
      console.debug('[PVC] handshake response data:', data)

      this.sessionId = data.session.id

      const attestationService = this.attestationServiceConfig
      if (attestationService?.attestationServiceUrl) {
        const tee = attestationService.teeType ?? data.attestation.cpu.tee_type
        const policyIds = attestationService.policyIds ?? []
        let evidenceForVerify: unknown = data.attestation.cpu.evidence
        if (
          tee === 'tdx' &&
          evidenceForVerify &&
          typeof evidenceForVerify === 'object' &&
          'quote' in evidenceForVerify
        ) {
          const raw = evidenceForVerify as Record<string, unknown>
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
      }

      await this.handshake(data.binding.handshake_verifying_key)
    } catch (e) {
      console.error('[PVC] Failed to parse attestation response or perform handshake:', e)
      throw e
    }
  }

  /**
   * Drops the cached session state and re-runs the handshake. Mirrors
   * the Rust side's `PvcClient::recover_session`. Concurrent callers are
   * coalesced through `recoveryInFlight` so only one handshake runs at a
   * time — important because two chat requests in flight can both
   * observe `InvalidSessionId` after a pod restart.
   */
  private async recoverSession(): Promise<void> {
    if (this.recoveryInFlight) {
      return this.recoveryInFlight
    }
    const task = (async () => {
      try {
        this.sessionId = null
        this.noiseSession = null
        this.noiseHandshakeState = null
        await this.performSessionHandshake()
      } finally {
        this.recoveryInFlight = null
      }
    })()
    this.recoveryInFlight = task
    return task
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

  async handshake(handshakeVerifyingKey: string) {
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

      // 6. Verify Signature using the canonical binding material returned by /v1/handshake.
      const verifyingKey = decodeBase64(handshakeVerifyingKey)
      if (verifyingKey.length !== 64) {
        throw new Error('Invalid handshake verifying key length')
      }

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

  /**
   * Sends a chat completion request, transparently re-handshaking and
   * retrying ONCE if the backend rejects our `sid`.
   *
   * Mirrors `PvcClient::chat_completions` on the Rust side. The single
   * retry is structurally bounded — there is no loop and no recursion —
   * so a chronic mismatch fails fast instead of hammering the backend.
   * Non-`SessionRejectedError` failures (network, decryption, …) are
   * propagated verbatim without touching the session.
   */
  async chat(
    message: string,
    history: any[] = [],
    model: string = 'Qwen/Qwen3-VL-4B-Thinking',
    onToken?: (token: string) => void,
    options?: { enableThinking?: boolean; onReasoning?: (token: string) => void }
  ): Promise<string> {
    try {
      return await this.chatOnce(message, history, model, onToken, options)
    } catch (e) {
      if (!isSessionRejected(e)) {
        throw e
      }
      console.warn('[PVC] session rejected by tee-llm, re-handshaking and retrying once', e)
      await this.recoverSession()
      console.info('[PVC] session re-established, retrying chat completions')
      return this.chatOnce(message, history, model, onToken, options)
    }
  }

  /**
   * Single attempt of the chat request. Throws `SessionRejectedError`
   * when the body comes back as an InvalidSessionId envelope instead of
   * a Noise frame stream — that error is the only signal `chat` uses to
   * trigger session recovery.
   */
  private async chatOnce(
    message: string,
    history: any[],
    model: string,
    onToken?: (token: string) => void,
    options?: { enableThinking?: boolean; onReasoning?: (token: string) => void }
  ): Promise<string> {
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
    /**
     * `true` once we have observed a leading `{` and committed to
     * interpreting the entire response as a JSON `ApiResponse` envelope.
     * Set on the first chunk so we never enter the frame loop in this
     * call — the envelope is always small (under a few KB) so we just
     * accumulate it and decode at end-of-stream.
     */
    let envelopeMode = false

    // Max reasonable frame payload (10MB); larger suggests first 4 bytes are not our length header (e.g. HTML/text)
    const MAX_FRAME_PAYLOAD = 10 * 1024 * 1024
    // A JSON `ApiResponse` envelope is at most a few hundred bytes; cap
    // buffering to keep an attacker who manages to inject a large
    // `{...` from forcing us to hoard the entire stream.
    const MAX_ENVELOPE_BYTES = 64 * 1024

    /**
     * If the buffered response is a JSON `ApiResponse` envelope, throw a
     * typed error (so `chat`'s wrapper can react to `InvalidSessionId`)
     * or a generic `Error` for any other non-success code. Returns
     * `false` when the body is not a parseable envelope, so the caller
     * can fall back to its normal "looks like text/HTML" reporting.
     */
    const throwIfErrorEnvelope = (bytes: Uint8Array): void => {
      let text: string
      try {
        text = new TextDecoder().decode(bytes)
      } catch {
        return
      }
      let envelope: ApiResponse<unknown>
      try {
        envelope = JSON.parse(text) as ApiResponse<unknown>
      } catch {
        return
      }
      if (typeof envelope.code !== 'number' || envelope.code === 0) {
        return
      }
      const message = envelope.message ?? `backend error ${envelope.code}`
      if (envelope.code === INVALID_SESSION_ID_CODE) {
        throw new SessionRejectedError(message, envelope.code)
      }
      throw new Error(`Backend error code=${envelope.code}: ${message}`)
    }

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
        if (envelopeMode) {
          // Whole response body was a JSON envelope (e.g. an
          // `InvalidSessionId` rejection from the request guard). Throw
          // a typed error so `chat` can react. If it doesn't parse, fall
          // through to the existing "not PVC frame format" diagnostics.
          throwIfErrorEnvelope(buffer)
        }
        processBufferFrames()
        if (buffer.length > 0) {
          const view = new DataView(buffer.buffer, buffer.byteOffset, Math.min(4, buffer.length))
          const declaredLen = buffer.length >= 4 ? view.getUint32(0, false) : 0
          const wantLen = 4 + declaredLen
          const firstBytesHex = Array.from(buffer.slice(0, Math.min(16, buffer.length)))
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(' ')
          const firstChars = new TextDecoder()
            .decode(buffer.slice(0, Math.min(80, buffer.length)))
            .replace(/[\x00-\x1f]/g, '.')
          if (declaredLen > MAX_FRAME_PAYLOAD) {
            const fullBodyText = new TextDecoder().decode(buffer)
            console.error(
              '[PVC] Stream data is not our binary frame format (expected 4-byte length + Noise payload).',
              'First bytes (hex):',
              firstBytesHex,
              '— likely HTML/error page from relay or wrong decapsulation.'
            )
            console.error(
              '[PVC] Full response body (decoded as text), length:',
              buffer.length,
              'chars:'
            )
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
          console.debug(
            '[PVC] Stream ended. totalReadBytes:',
            totalReadBytes,
            'combinedResponse length:',
            combinedResponse.length
          )
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

      // First-byte sniff: a Noise frame begins with a 4-byte big-endian
      // length whose top byte is `0x00` for any < 16 MiB payload, while
      // an `ApiResponse` envelope always begins with `{` (`0x7B`). If
      // we're already in envelope mode, keep buffering; otherwise sniff
      // the very first byte once.
      if (!envelopeMode && buffer.length >= 1 && buffer[0] === 0x7b /* '{' */) {
        envelopeMode = true
      }

      if (envelopeMode) {
        // Try to parse early so we can fail fast — small envelopes
        // typically fit in the first chunk. `throwIfErrorEnvelope` only
        // throws when the buffer is a complete, non-success envelope;
        // otherwise it returns and we keep buffering until end-of-stream.
        throwIfErrorEnvelope(buffer)
        if (buffer.length > MAX_ENVELOPE_BYTES) {
          // Either a malformed envelope or someone is trying to flood us
          // with `{...`. Treat it as a generic transport error rather
          // than burning unbounded memory.
          throw new Error(
            `Response body looked like a JSON envelope but exceeded ${MAX_ENVELOPE_BYTES} bytes without parsing`
          )
        }
        continue
      }

      processBufferFrames()
    }

    return combinedResponse
  }
}
