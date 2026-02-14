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

/**
 * Runtime config loaded from /config.json (served by nginx or static).
 * Build-time env (VITE_*) are used as defaults; config.json overrides them per deployment.
 */

export type RuntimeConfig = {
  identityServerUrl?: string
  ohttpGatewayUrl?: string
  ohttpRelayUrl?: string
  targetServerUrl?: string
  attestationServiceUrl?: string
  model?: string
}

const CONFIG_URL = '/config.json'
const FETCH_TIMEOUT_MS = 2000

/** Build-time defaults from Vite env */
export function getBuildTimeConfig(): RuntimeConfig {
  return {
    identityServerUrl: import.meta.env.VITE_IDENTITY_SERVER_URL ?? undefined,
    ohttpGatewayUrl: import.meta.env.VITE_OHTTP_GATEWAY_URL ?? undefined,
    ohttpRelayUrl: import.meta.env.VITE_OHTTP_RELAY_URL ?? undefined,
    targetServerUrl: import.meta.env.VITE_TARGET_SERVER_URL ?? undefined,
    attestationServiceUrl: import.meta.env.VITE_ATTESTATION_SERVICE_URL ?? undefined,
    model: import.meta.env.VITE_MODEL ?? undefined,
  }
}

/**
 * Fetch runtime config from /config.json. On 404 or timeout, returns build-time defaults only.
 */
export async function loadRuntimeConfig(): Promise<RuntimeConfig> {
  const defaults = getBuildTimeConfig()
  const controller = new AbortController()
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS)
  try {
    const res = await fetch(CONFIG_URL, { signal: controller.signal, cache: 'no-store' })
    clearTimeout(timeout)
    if (!res.ok) return defaults
    const json = (await res.json()) as Record<string, unknown>
    return {
      ...defaults,
      ...(json.identityServerUrl != null && { identityServerUrl: String(json.identityServerUrl) }),
      ...(json.ohttpGatewayUrl != null && { ohttpGatewayUrl: String(json.ohttpGatewayUrl) }),
      ...(json.ohttpRelayUrl != null && { ohttpRelayUrl: String(json.ohttpRelayUrl) }),
      ...(json.targetServerUrl != null && { targetServerUrl: String(json.targetServerUrl) }),
      ...(json.attestationServiceUrl != null && {
        attestationServiceUrl: String(json.attestationServiceUrl),
      }),
      ...(json.model != null && { model: String(json.model) }),
    }
  } catch {
    clearTimeout(timeout)
    return defaults
  }
}
