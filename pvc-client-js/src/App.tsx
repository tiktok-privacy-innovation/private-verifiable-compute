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

import { useEffect, useMemo, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import { PvcApiClient, getAttestationDisplayRows, type AttestationVerificationResult } from '@/lib/api'
import { loadRuntimeConfig } from '@/lib/runtime_config'
import './index.css'
import { AlertCircle, Bot, Loader2, MessageSquare, Plus, Send, ShieldCheck, User } from 'lucide-react'

type ChatSession = {
  id: string
  name: string
  messages: { id: string; role: 'user' | 'assistant' | 'system'; content: string; reasoning?: string }[]
}

type ChatMessage = {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  reasoning?: string
}

/** Build-time defaults; overridden by /config.json at runtime when served by nginx */
const DEFAULT_CLIENT_CONFIG = {
  identityServerUrl: '/identity',
  ohttpGatewayUrl: '/ohttp-gateway',
  ohttpRelayUrl: '/ohttp-relay',
  targetServerUrl: 'http://localhost:9000',
  attestationService: {
    attestationServiceUrl: '/attestation-service/attestation',
    policyIds: [] as string[],
  },
}

const DEFAULT_MODEL = 'Qwen/Qwen3-VL-4B-Thinking'

/** Normalize AI reply: trim and collapse excessive newlines (3+ → 2) to avoid huge gaps; keep \n\n for one paragraph break */
function normalizeMarkdownContent(s: string): string {
  return s
    .trim()
    .replace(/\n(\s*\n)+/g, '\n\n')
}

const storageKeys = {
  sessions: 'pvc-chat-sessions',
  activeSessionId: 'pvc-chat-active-session-id',
  thinkingEnabled: 'pvc-thinking-enabled',
}

/** Stable empty array to avoid effect re-running when setMessages([]) is in useEffect deps */
const EMPTY_MESSAGES: ChatMessage[] = []

function App() {
  const apiClient = useRef(new PvcApiClient())
  const connectOnce = useRef(false)
  const bottomRef = useRef<HTMLDivElement | null>(null)
  const [runtimeConfig, setRuntimeConfig] = useState<Awaited<ReturnType<typeof loadRuntimeConfig>> | null>(null)
  const [ready, setReady] = useState(false)
  const [status, setStatus] = useState<'connected' | 'disconnected' | 'connecting'>('connecting')
  const [errorMsg, setErrorMsg] = useState<string>('')
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null)
  const [input, setInput] = useState('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [thinkingEnabled, setThinkingEnabled] = useState(true)
  const [expandedReasoning, setExpandedReasoning] = useState<Record<string, boolean>>({})
  const [attestationDetails, setAttestationDetails] = useState<AttestationVerificationResult | null>(null)
  const [shieldHover, setShieldHover] = useState(false)

  const clientConfig = useMemo(() => {
    if (!runtimeConfig) return null
    return {
      identityServerUrl: runtimeConfig.identityServerUrl ?? DEFAULT_CLIENT_CONFIG.identityServerUrl,
      ohttpGatewayUrl: runtimeConfig.ohttpGatewayUrl ?? DEFAULT_CLIENT_CONFIG.ohttpGatewayUrl,
      ohttpRelayUrl: runtimeConfig.ohttpRelayUrl ?? DEFAULT_CLIENT_CONFIG.ohttpRelayUrl,
      targetServerUrl: runtimeConfig.targetServerUrl ?? DEFAULT_CLIENT_CONFIG.targetServerUrl,
      attestationService: {
        attestationServiceUrl:
          runtimeConfig.attestationServiceUrl ?? DEFAULT_CLIENT_CONFIG.attestationService.attestationServiceUrl,
        policyIds: DEFAULT_CLIENT_CONFIG.attestationService.policyIds,
      },
    }
  }, [runtimeConfig])

  const model = runtimeConfig?.model ?? DEFAULT_MODEL

  useEffect(() => {
    loadRuntimeConfig().then(setRuntimeConfig)
  }, [])

  const activeSession = useMemo(
    () => sessions.find((session) => session.id === activeSessionId) || null,
    [sessions, activeSessionId]
  )

  useEffect(() => {
    if (typeof window === 'undefined') return
    const storedSessions = window.localStorage.getItem(storageKeys.sessions)
    const storedActiveSessionId = window.localStorage.getItem(storageKeys.activeSessionId)
    const storedThinking = window.localStorage.getItem(storageKeys.thinkingEnabled)
    if (storedSessions) {
      const parsed = JSON.parse(storedSessions) as ChatSession[]
      setSessions(parsed)
      if (parsed.length && !storedActiveSessionId) {
        setActiveSessionId(parsed[0].id)
      }
    }
    if (storedActiveSessionId) {
      setActiveSessionId(storedActiveSessionId)
    }
    if (storedThinking !== null && storedThinking !== undefined) {
      try {
        setThinkingEnabled(JSON.parse(storedThinking))
      } catch {
        // keep default true
      }
    }
  }, [])

  useEffect(() => {
    if (typeof window === 'undefined') return
    window.localStorage.setItem(storageKeys.sessions, JSON.stringify(sessions))
    if (activeSessionId) {
      window.localStorage.setItem(storageKeys.activeSessionId, activeSessionId)
    }
  }, [sessions, activeSessionId])

  useEffect(() => {
    if (typeof window === 'undefined') return
    window.localStorage.setItem(storageKeys.thinkingEnabled, JSON.stringify(thinkingEnabled))
  }, [thinkingEnabled])

  // When active session id changes, load messages from that session; depend only on activeSessionId to avoid loops
  useEffect(() => {
    setMessages(activeSession?.messages ?? EMPTY_MESSAGES)
  }, [activeSessionId])

  // Sync current messages back into the active session; functional update avoids writing stale messages back
  useEffect(() => {
    if (!activeSessionId) return
    setSessions((prev) =>
      prev.map((session) => (session.id === activeSessionId ? { ...session, messages } : session))
    )
  }, [messages, activeSessionId])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  useEffect(() => {
    if (!clientConfig) return
    const connect = async () => {
      if (connectOnce.current) return
      connectOnce.current = true
      setStatus('connecting')
      setErrorMsg('')
      try {
        await apiClient.current.init(clientConfig)
        setAttestationDetails(apiClient.current.getAttestationResult())
        setReady(true)
        setStatus('connected')
      } catch (e: any) {
        setReady(false)
        setStatus('disconnected')
        setErrorMsg(e?.message || e?.toString() || 'Unknown error')
      }
    }
    connect()
  }, [clientConfig])

  const createSession = () => {
    const id = new Date().toISOString()
    const name = `Session ${sessions.length + 1}`
    const newSession: ChatSession = { id, name, messages: [] }
    setSessions((prev) => [newSession, ...prev])
    setActiveSessionId(id)
    setMessages([])
  }

  const handleSend = async () => {
    if (!input.trim() || !ready || isLoading) return
    const text = input
    const userMessage: ChatMessage = {
      id: `user-${Date.now()}`,
      role: 'user',
      content: text,
    }
    const assistantId = `assistant-${Date.now()}`
    const assistantPlaceholder: ChatMessage = {
      id: assistantId,
      role: 'assistant',
      content: '',
      reasoning: '',
    }
    if (!activeSessionId) {
      const id = new Date().toISOString()
      const name = `Session ${sessions.length + 1}`
      const initialMessages: ChatMessage[] = [userMessage, assistantPlaceholder]
      setSessions((prev) => [{ id, name, messages: initialMessages }, ...prev])
      setActiveSessionId(id)
      setMessages(initialMessages)
      setInput('')
    } else {
      setInput('')
      setMessages((prev) => [...prev, userMessage, assistantPlaceholder])
    }
    const history = [...messages]
      .filter((message) => message.role !== 'system')
      .filter(
        (message) =>
          !(message.role === 'assistant' && message.content.trim().startsWith('Error:'))
      )
      .map((message) => ({ role: message.role as 'user' | 'assistant', content: message.content }))
    const onToken = (delta: string) => {
      setMessages((prev) =>
        prev.map((message) =>
          message.id === assistantId
            ? { ...message, content: `${message.content}${delta}` }
            : message
        )
      )
      // As soon as first content token arrives, thinking has ended — collapse reasoning immediately
      setExpandedReasoning((prev) => ({ ...prev, [assistantId]: false }))
    }
    const onReasoning = (delta: string) => {
      setMessages((prev) =>
        prev.map((message) =>
          message.id === assistantId
            ? { ...message, reasoning: `${message.reasoning ?? ''}${delta}` }
            : message
        )
      )
    }
    try {
      setIsLoading(true)
      const full = await apiClient.current.chat(text, history, model, onToken, {
        enableThinking: thinkingEnabled,
        onReasoning,
      })
      setMessages((prev) =>
        prev.map((message) =>
          message.id === assistantId ? { ...message, content: full } : message
        )
      )
      // When stream ends, collapse reasoning and show final answer
      setExpandedReasoning((prev) => ({ ...prev, [assistantId]: false }))
    } catch (e: any) {
      setMessages((prev) =>
        prev.map((message) =>
          message.id === assistantId
            ? { ...message, content: `Error: ${e?.message || e?.toString() || 'Unknown error'}` }
            : message
        )
      )
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="pvc-app">
      <aside className="pvc-sidebar">
        <div className="pvc-sidebar-header">
          <div className="pvc-sidebar-title">
            <MessageSquare className="pvc-icon" />
            <span>Conversations</span>
          </div>
          <button onClick={createSession} className="pvc-button mini">
            <Plus className="pvc-icon" />
          </button>
        </div>
        <div className="pvc-sidebar-tip">Conversations are saved only in this browser</div>
        <div className="pvc-session-list">
          {sessions.map((session) => (
            <button
              key={session.id}
              onClick={() => setActiveSessionId(session.id)}
              className={`pvc-session-item ${session.id === activeSessionId ? 'active' : ''}`}
            >
              <div className="pvc-session-name">{session.name}</div>
              <div className="pvc-session-meta">{session.messages.length} message{session.messages.length !== 1 ? 's' : ''}</div>
            </button>
          ))}
          {sessions.length === 0 && <div className="pvc-session-empty">Click + New Chat</div>}
        </div>
      </aside>

      <div className="pvc-content">
        <header className="pvc-header">
          <div
            className="pvc-header-left pvc-attestation-trigger"
            onMouseEnter={() => setShieldHover(true)}
            onMouseLeave={() => setShieldHover(false)}
          >
            <div className={`pvc-status-icon ${status}`}>
              {status === 'connected' ? <ShieldCheck className="pvc-icon" /> : <MessageSquare className="pvc-icon" />}
            </div>
            <div className="pvc-header-text">
              <h1>{activeSession?.name || 'PVC Secure Chat'}</h1>
              <div className="pvc-status-line">
                <span className={`pvc-status ${status} ${status === 'disconnected' && errorMsg ? 'pvc-status-error' : ''}`}>
                  {status === 'connected'
                    ? 'Encrypted Tunnel Active'
                    : status === 'connecting'
                      ? 'Handshaking...'
                      : errorMsg
                        ? 'Secure tunnel not established'
                        : 'Disconnected'}
                </span>
                {status === 'connected' && attestationDetails && (
                  <span className="pvc-attestation-hint"> · Hover for attestation details</span>
                )}
              </div>
            </div>
            {shieldHover && attestationDetails && status === 'connected' && (
              <div className="pvc-attestation-popover">
                <div className="pvc-attestation-title">
                  {attestationDetails.teeType === 'tdx' ? 'TDX Protection Details' : 'Attestation Details'}
                </div>
                <div className="pvc-attestation-fields">
                  {getAttestationDisplayRows(attestationDetails).map((row) => (
                    <div key={row.key} className="pvc-attestation-row">
                      <span className="pvc-attestation-key">{row.key}</span>
                      <span
                        className="pvc-attestation-val"
                        title={row.value.length > 48 ? row.value : undefined}
                      >
                        {row.value.length > 48 ? `${row.value.slice(0, 24)}…${row.value.slice(-20)}` : row.value}
                      </span>
                    </div>
                  ))}
                </div>
                <div className="pvc-attestation-active">
                  <ShieldCheck className="pvc-icon" />
                  <span>
                    {attestationDetails.teeType === 'tdx' ? 'TDX Protection Active' : 'Attestation Active'}
                  </span>
                </div>
              </div>
            )}
          </div>
          {status === 'disconnected' && (
            <div className="pvc-error-badge" title={errorMsg || undefined}>
              <AlertCircle className="pvc-icon" />
              <span className="pvc-error-msg">{errorMsg || 'Connection Error'}</span>
            </div>
          )}
        </header>

        <main className="pvc-main">
          {messages.length === 0 && <div className="pvc-empty">Select or create a conversation to start</div>}
          {messages.map((message) => (
            <div
              key={message.id}
              className={`pvc-msg ${message.role === 'user' ? 'right' : 'left'}`}
            >
              <div className={`pvc-avatar ${message.role}`}>
                {message.role === 'user' ? (
                  <User className="pvc-icon" />
                ) : (
                  <Bot className="pvc-icon" />
                )}
              </div>
              <div className="pvc-message-body">
                <div className={`pvc-bubble ${message.role} ${message.role === 'assistant' && !message.content ? 'pvc-bubble-typing' : ''}`}>
                  {message.role === 'assistant' && !message.content ? (
                    <p className="pvc-typing-indicator"><span>.</span><span>.</span><span>.</span></p>
                  ) : message.role === 'assistant' && message.content ? (
                    <div className="pvc-markdown">
                      <div className="pvc-markdown-inner">
                        <ReactMarkdown>{normalizeMarkdownContent(message.content)}</ReactMarkdown>
                      </div>
                    </div>
                  ) : (
                    <p>{message.content ? message.content.trim() : '\u00a0'}</p>
                  )}
                </div>
                {message.role === 'assistant' && message.reasoning && (() => {
                  const expanded = expandedReasoning[message.id] === true || (expandedReasoning[message.id] === undefined && !message.content)
                  return (
                    <div className="pvc-reasoning">
                      <button
                        type="button"
                        className="pvc-reasoning-toggle"
                        onClick={() =>
                          setExpandedReasoning((prev) => ({
                            ...prev,
                            [message.id]: !expanded,
                          }))
                        }
                      >
                        {expanded ? 'Collapse reasoning' : 'Expand reasoning'}
                      </button>
                      {expanded && (
                        <div className="pvc-reasoning-content">{message.reasoning}</div>
                      )}
                    </div>
                  )
                })()}
              </div>
            </div>
          ))}
          <div ref={bottomRef} className="pvc-bottom-anchor" />
        </main>

        <footer className="pvc-footer">
          <div className="pvc-input-wrap">
            <textarea
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                  e.preventDefault()
                  handleSend()
                }
              }}
              placeholder={ready ? 'Type a message and press Enter' : 'Waiting for secure channel...'}
              disabled={!ready}
              rows={1}
              className="pvc-input"
            />
            <button
              onClick={handleSend}
              disabled={!input.trim() || !ready || isLoading}
              className={`pvc-button primary ${!ready || isLoading ? 'disabled' : ''}`}
            >
              {isLoading ? <Loader2 className="pvc-icon spin" /> : <Send className="pvc-icon" />}
            </button>
          </div>
          <p className="pvc-footer-tip">
            Messages are encrypted with OHTTP + Noise Protocol before leaving the browser.
          </p>
        </footer>
      </div>
    </div>
  )
}

export default App
