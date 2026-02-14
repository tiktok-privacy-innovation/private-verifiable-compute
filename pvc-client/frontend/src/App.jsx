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

import { useState, useEffect, useRef } from "react";
import "./App.css";

const fetchApiResponse = async (url, options) => {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  const json = await response.json();
  if (json.code !== 0) {
    throw new Error(json.message || 'Unknown backend error');
  }
  return json.data;
};

function App() {
    const [messages, setMessages] = useState([
        { id: 1, text: "Hello! How can I help you today?", sender: "bot" },
    ]);
    const [inputText, setInputText] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    const [isTooltipVisible, setIsTooltipVisible] = useState(false);
    const [isInitializing, setIsInitializing] = useState(true);
    const [teeInfo, setTeeInfo] = useState({});
    const [authConfig, setAuthConfig] = useState(null);
    const [conversationHistory, setConversationHistory] = useState([
        {
            role: "assistant",
            content: "Hello! How can I help you today?",
        },
    ]);

    const [selectedFile, setSelectedFile] = useState(null);
    const [isUploading, setIsUploading] = useState(false);
    const fileInputRef = useRef(null);
    const messagesEndRef = useRef(null);
    const [isUploadTooltipVisible, setIsUploadTooltipVisible] = useState(false);
    const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);
    const [isClearHistoryModalOpen, setIsClearHistoryModalOpen] =
        useState(false);
    const [expandedReasoning, setExpandedReasoning] = useState({});

    const scrollToBottom = (smooth = true) => {
        messagesEndRef.current?.scrollIntoView({
            behavior: smooth ? "smooth" : "auto",
        });
    };

    useEffect(() => {
        scrollToBottom(true);
    }, [messages]);

    const handleSend = async () => {
        if (inputText.trim() === "") return;

        const newUserMessage = {
            id: messages.length + 1,
            text: inputText,
            reasoning: "",
            sender: "user",
        };

        setMessages([...messages, newUserMessage]);
        setIsLoading(true);
        let botResponseAdded = false;
        let botResponseId = messages.length + 2;

        // Prepare messages for API call - include all history plus current message
        const userHistoryEntry = {
            role: "user",
            content: inputText,
        };
        const apiMessages = [...conversationHistory, userHistoryEntry];

        try {
            const response = await fetch("/v1/chat/completions", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    messages: apiMessages,
                    stream: true,
                }),
            });

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }

            // Read the stream
            if (!response.body) {
                throw new Error("Response body is null or undefined");
            }

            const contentType = response.headers.get("content-type") || "";

            // Create initial bot message with empty text
            const botResponse = {
                id: botResponseId,
                text: "",
                reasoning: "",
                sender: "bot",
            };

            // Add the bot message to the chat
            setMessages((prev) => [...prev, botResponse]);
            botResponseAdded = true;

            if (contentType.includes("application/json")) {
                const parsed = await response.json();
                const message = parsed?.error?.message || "Unknown error";
                setMessages((prev) =>
                    prev.map((msg) =>
                        msg.id === botResponseId
                            ? {
                                  ...msg,
                                  text: `Sorry, an error occurred: ${message}`,
                              }
                            : msg,
                    ),
                );
                return;
            }

            const reader = response.body.getReader();
            const decoder = new TextDecoder();
            let buffer = "";
            let accumulatedText = "";
            let accumulatedReasoning = "";
            let hasStreamError = false;

            try {
                const firstChunk = await reader.read();
                if (firstChunk.done) {
                    throw new Error("Empty response");
                }
                const firstText = decoder.decode(firstChunk.value);
                const firstTrimmed = firstText.trim();
                if (firstTrimmed.startsWith("{")) {
                    try {
                        const parsed = JSON.parse(firstTrimmed);
                        if (parsed?.error?.message) {
                            const message = parsed.error.message;
                            hasStreamError = true;
                            setMessages((prev) =>
                                prev.map((msg) =>
                                    msg.id === botResponseId
                                        ? {
                                              ...msg,
                                              text: `Sorry, an error occurred: ${message}`,
                                          }
                                        : msg,
                                ),
                            );
                            await reader.cancel();
                        } else {
                            buffer += firstText;
                        }
                    } catch {
                        buffer += firstText;
                    }
                } else {
                    buffer += firstText;
                }

                if (hasStreamError) {
                    return;
                }

                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    // Decode the chunk and process SSE format
                    const chunk = decoder.decode(value);
                    buffer += chunk;

                    // Process complete SSE lines
                    const lines = buffer.split("\n");
                    buffer = lines.pop() || ""; // Keep incomplete line in buffer

                    for (const line of lines) {
                        if (line.startsWith("data: ")) {
                            const data = line.slice(6); // Remove 'data: ' prefix

                            // Skip [DONE] marker
                            if (data.trim() === "[DONE]") {
                                continue;
                            }

                            try {
                                const parsed = JSON.parse(data);
                                if (parsed?.error?.message) {
                                    const message = parsed.error.message;
                                    hasStreamError = true;
                                    setMessages((prev) =>
                                        prev.map((msg) =>
                                            msg.id === botResponseId
                                                ? {
                                                      ...msg,
                                                      text: `Sorry, an error occurred: ${message}`,
                                                  }
                                                : msg,
                                        ),
                                    );
                                    await reader.cancel();
                                    break;
                                }
                                // Extract content from the response
                                if (
                                    parsed.choices &&
                                    parsed.choices[0] &&
                                    parsed.choices[0].delta
                                ) {
                                    const content =
                                        parsed.choices[0].delta.content;
                                    const reasoning =
                                        parsed.choices[0].delta.reasoning ||
                                        parsed.choices[0].delta.reasoning_content;
                                    if (content) {
                                        accumulatedText += content;
                                        // Update the bot message with the new text
                                        setMessages((prev) =>
                                            prev.map((msg) =>
                                                msg.id === botResponse.id
                                                    ? {
                                                          ...msg,
                                                          text: accumulatedText,
                                                      }
                                                    : msg,
                                            ),
                                        );
                                    }
                                    if (reasoning) {
                                        accumulatedReasoning += reasoning;
                                        setMessages((prev) =>
                                            prev.map((msg) =>
                                                msg.id === botResponse.id
                                                    ? {
                                                          ...msg,
                                                          reasoning: accumulatedReasoning,
                                                      }
                                                    : msg,
                                            ),
                                        );
                                        setExpandedReasoning((prev) => ({
                                            ...prev,
                                            [botResponse.id]: true,
                                        }));
                                    }
                                }
                            } catch (e) {
                                console.warn(
                                    "Failed to parse SSE data:",
                                    e,
                                    "Data:",
                                    data,
                                );
                            }
                        }
                        if (hasStreamError) {
                            break;
                        }
                    }
                    if (hasStreamError) {
                        break;
                    }
                }

                if (!hasStreamError) {
                    const assistantHistoryEntry = {
                        role: "assistant",
                        content: accumulatedText,
                    };
                    if (accumulatedReasoning) {
                        setExpandedReasoning((prev) => ({
                            ...prev,
                            [botResponse.id]: false,
                        }));
                    }
                    setConversationHistory((prev) => [
                        ...prev,
                        userHistoryEntry,
                        assistantHistoryEntry,
                    ]);
                }
            } catch (error) {
                // If streaming fails, append error message to the current bot response instead of removing it
                setMessages((prev) =>
                    prev.map((msg) =>
                        msg.id === botResponse.id
                            ? {
                                  ...msg,
                                  text: msg.text + `\n\n[Error: Stream interrupted - ${error.message}]`,
                              }
                            : msg,
                    ),
                );
                throw error;
            } finally {
                reader.releaseLock();
            }
        } catch (error) {
            console.error("Error during fetch:", error);
            if (botResponseAdded) {
                setMessages((prev) =>
                    prev.map((msg) =>
                        msg.id === botResponseId
                            ? {
                                  ...msg,
                                  text: `Sorry, an error occurred: ${error.message}`,
                              }
                            : msg,
                    ),
                );
            } else {
                const errorMessage = {
                    id: botResponseId,
                    text: `Sorry, an error occurred: ${error.message}`,
                    reasoning: "",
                    sender: "bot",
                };
                setMessages((prev) => [...prev, errorMessage]);
            }
            console.error("Error:", error);
        } finally {
            setIsLoading(false);
            setInputText("");
        }
    };

    useEffect(() => {
        const initializeApp = async () => {
            try {
                const authData = await fetchApiResponse("/api/auth/config");
                setAuthConfig(authData);
                if (authData.loggedin) {
                    const randomArray = new Uint8Array(64);
                    crypto.getRandomValues(randomArray);
                    const base64Data = btoa(
                        String.fromCharCode(...randomArray),
                    );
                    const teeData = await fetchApiResponse(
                        "/api/attestation",
                        {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify({ nonce: base64Data }),
                        },
                    );
                    console.log(teeData);
                    setTeeInfo(teeData);
                }
            } catch (error) {
                console.error("Failed to initialize app:", error);
                setAuthConfig({ enabled: false, client_id: "" });
            } finally {
                setIsInitializing(false);
            }
        };

        initializeApp();
    }, []);

    const handleKeyPress = (e) => {
        if (e.key === "Enter") {
            handleSend();
        }
    };

    const handleFileChange = (e) => {
        if (fileInputRef.current) {
            fileInputRef.current.value = "";
        }
        if (e.target.files && e.target.files[0]) {
            const file = e.target.files[0];
            const fileName = file.name.toLowerCase();

            if (!fileName.endsWith(".txt") && !fileName.endsWith(".md")) {
                alert("Please select only .txt or .md files");
                e.target.value = "";
                return;
            }

            if (file.size > 4 * 1024 * 1024) {
                alert("File size exceeds 5MB limit");
                e.target.value = "";
                return;
            }

            setSelectedFile(file);
            setIsConfirmModalOpen(true);
        }
    };

    const handleUpload = async () => {
        if (!selectedFile) return;

        setIsUploading(true);
        const formData = new FormData();
        formData.append("file", selectedFile);

        try {
            const _result = await fetchApiResponse("/api/upload", {
                method: "POST",
                body: formData,
            });

            const uploadMessage = {
                id: messages.length + 1,
                text: `File uploaded successfully: ${selectedFile.name}`,
                sender: "user",
            };
            setMessages((prev) => [...prev, uploadMessage]);

            // Add file upload notification to conversation history
            const uploadHistoryEntry = {
                role: "user",
                content: `File uploaded successfully: ${selectedFile.name}`,
            };
            setConversationHistory((prev) => [...prev, uploadHistoryEntry]);

            setSelectedFile(null);
            setIsConfirmModalOpen(false);
            if (fileInputRef.current) {
                fileInputRef.current.value = "";
            }
        } catch (error) {
            console.error("Upload failed:", error);
            const errorMessage = {
                id: messages.length + 1,
                text: `Sorry, file upload failed: ${error.message || "Unknown error"}`,
                sender: "bot",
            };
            setMessages((prev) => [...prev, errorMessage]);

            // Add error message to conversation history
            const errorHistoryEntry = {
                role: "assistant",
                content: `Sorry, file upload failed: ${error.message || "Unknown error"}`,
            };
            setConversationHistory((prev) => [...prev, errorHistoryEntry]);

            setIsConfirmModalOpen(false);
        } finally {
            setIsUploading(false);
        }
    };

    if (isInitializing) {
        return (
            <div className="app-loading">
                <div className="loading-container">
                    <div className="loading-spinner"></div>
                </div>
            </div>
        );
    }

    if (!authConfig.loggedin) {
        const handleGoogleLogin = () => {
            var oauth2Endpoint = "https://accounts.google.com/o/oauth2/v2/auth";
            const randomArray = new Uint8Array(64);
            crypto.getRandomValues(randomArray);
            const randomState = btoa(String.fromCharCode(...randomArray));
            var params = new URLSearchParams({
                client_id: authConfig.clientID,
                redirect_uri: "http://localhost:8083/auth/google/callback",
                response_type: "id_token",
                scope: "openid profile",
                state: randomState,
                nonce: "pvc-client",
            });
            const authUrl = `${oauth2Endpoint}?${params.toString()}`;
            window.location.href = authUrl;
        };

        return (
            <div className="app-login">
                <div className="login-container">
                    <h2>Welcome to Private Verifiable Cloud</h2>
                    <p>Please sign in to continue</p>
                    <button
                        className="google-login-btn"
                        onClick={handleGoogleLogin}
                    >
                        <svg
                            xmlns="http://www.w3.org/2000/svg"
                            viewBox="0 0 24 24"
                            width="24"
                            height="24"
                        >
                            <path
                                fill="#4285F4"
                                d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                            />
                            <path
                                fill="#34A853"
                                d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                            />
                            <path
                                fill="#FBBC05"
                                d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                            />
                            <path
                                fill="#EA4335"
                                d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                            />
                        </svg>
                        <span>Sign in with Google</span>
                    </button>
                </div>
            </div>
        );
    }

    return (
        <div className="app">
            <div className="chat-container">
                <div className="chat-header">
                    <h1>Privacy Persevering AI Chat</h1>
                    <button
                        className="clear-history-btn"
                        onClick={() => setIsClearHistoryModalOpen(true)}
                        title="Clear conversation history"
                    >
                        <svg
                            width="20"
                            height="20"
                            viewBox="0 0 24 24"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                        >
                            <path
                                d="M3 6H5H21"
                                stroke="currentColor"
                                strokeWidth="2"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                            />
                            <path
                                d="M8 6V4C8 3.46957 8.21071 2.96086 8.58579 2.58579C8.96086 2.21071 9.46957 2 10 2H14C14.5304 2 15.0391 2.21071 15.4142 2.58579C15.7893 2.96086 16 3.46957 16 4V6M19 6V20C19 20.5304 18.7893 21.0391 18.4142 21.4142C18.0391 21.7893 17.5304 22 17 22H7C6.46957 22 5.96086 21.7893 5.58579 21.4142C5.21071 21.0391 5 20.5304 5 20V6H19Z"
                                stroke="currentColor"
                                strokeWidth="2"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                            />
                            <path
                                d="M10 11V17"
                                stroke="currentColor"
                                strokeWidth="2"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                            />
                            <path
                                d="M14 11V17"
                                stroke="currentColor"
                                strokeWidth="2"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                            />
                        </svg>
                        Clear History
                    </button>
                </div>
                <div className="chat-messages">
                    {messages.map((message) => (
                        <div
                            key={message.id}
                            className={`message ${message.sender === "user" ? "user-message" : "bot-message"}`}
                        >
                            <div className="message-text">{message.text}</div>
                            {message.sender === "bot" && message.reasoning && (
                                <div className="message-reasoning">
                                    <button
                                        type="button"
                                        className="reasoning-toggle"
                                        onClick={() =>
                                            setExpandedReasoning((prev) => ({
                                                ...prev,
                                                [message.id]: !prev[message.id],
                                            }))
                                        }
                                    >
                                    {expandedReasoning[message.id]
                                            ? "Hide reasoning"
                                            : "Show reasoning"}
                                    </button>
                                    {expandedReasoning[message.id] && (
                                        <div className="reasoning-text">
                                            {message.reasoning}
                                        </div>
                                    )}
                                </div>
                            )}
                        </div>
                    ))}
                    <div ref={messagesEndRef} />
                    {isLoading && (
                        <div className="message bot-message">
                            <div className="message-text">
                                <div className="loading-dots">
                                    <span></span>
                                    <span></span>
                                    <span></span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>
                <div className="chat-input">
                    <input
                        type="text"
                        value={inputText}
                        onChange={(e) => setInputText(e.target.value)}
                        onKeyDown={handleKeyPress}
                        placeholder="Type your message here..."
                        disabled={isLoading}
                    />
                    <div className="button-group">
                        <button
                            onClick={handleSend}
                            disabled={isLoading || inputText.trim() === ""}
                        >
                            {isLoading ? "Sending..." : "Send"}
                        </button>
                        <label className="file-upload-label">
                            <input
                                type="file"
                                onChange={handleFileChange}
                                disabled={isUploading}
                                style={{ display: "none" }}
                                accept=".txt,.md,text/plain,text/markdown"
                            />
                            <span
                                className="file-upload-icon"
                                onMouseEnter={() =>
                                    setIsUploadTooltipVisible(true)
                                }
                                onMouseLeave={() =>
                                    setIsUploadTooltipVisible(false)
                                }
                            >
                                <svg
                                    width="30"
                                    height="30"
                                    viewBox="0 0 24 24"
                                    fill="none"
                                    xmlns="http://www.w3.org/2000/svg"
                                >
                                    <path
                                        d="M14 3v4a1 1 0 0 0 1 1h4"
                                        stroke="currentColor"
                                        strokeWidth="2"
                                    />
                                    <path
                                        d="M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2z"
                                        stroke="currentColor"
                                        strokeWidth="2"
                                    />
                                    <path
                                        d="M12 11v6"
                                        stroke="currentColor"
                                        strokeWidth="2"
                                    />
                                    <path
                                        d="M9.5 13.5L12 11l2.5 2.5"
                                        stroke="currentColor"
                                        strokeWidth="2"
                                    />
                                </svg>
                            </span>
                            {isUploadTooltipVisible && (
                                <div className="upload-tooltip">
                                    <div className="tooltip-header">
                                        Upload Knowledge Documents
                                    </div>
                                    <div className="tooltip-content">
                                        Upload documents to enhance the AI's
                                        knowledge with your specific information
                                    </div>
                                </div>
                            )}
                        </label>
                    </div>
                </div>

                <div
                    className="status-bar"
                    onMouseEnter={() => setIsTooltipVisible(true)}
                    onMouseLeave={() => setIsTooltipVisible(false)}
                >
                    <div className="shield-icon">
                        <svg
                            width="20"
                            height="20"
                            viewBox="0 0 24 24"
                            fill="none"
                            xmlns="http://www.w3.org/2000/svg"
                        >
                            <path
                                d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z"
                                stroke="white"
                                strokeWidth="2"
                                strokeLinecap="round"
                                strokeLinejoin="round"
                            />
                        </svg>
                    </div>
                    <span className="status-text">TDX Protection Active</span>

                    {/* Tooltip */}
                    {isTooltipVisible && (
                        <div className="tooltip">
                            <div className="tooltip-header">
                                TDX Protection Details
                            </div>
                            <div className="tooltip-content">
                                <div className="tooltip-row">
                                    <span className="tooltip-label">TEE:</span>
                                    <span className="tooltip-value">
                                        Intel TDX
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        ReportData:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.report_data ?? ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        Debug:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.td_attributes?.debug?.toString?.() ??
                                            ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        TCB Status:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.tcb_status ?? ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        MR_SEAM:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.quote?.body?.mr_seam ??
                                            ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        MR_TD:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.quote?.body?.mr_seam ??
                                            ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        RTMR0:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.quote?.body?.rtmr_0 ??
                                            ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        RTMR1:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.quote?.body?.rtmr_1 ??
                                            ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        RTMR2:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.quote?.body?.rtmr_2 ??
                                            ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        RTMR3:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.quote?.body?.rtmr_3 ??
                                            ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        TCB SVN:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.cpu?.quote?.body?.tcb_svn ??
                                            ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        GPU Hardware Model:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.gpu?.hwmodel ?? ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        x-nvidia-gpu-attestation-report-cert-chain-fwid-match:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.gpu?.[
                                            "x-nvidia-gpu-attestation-report-cert-chain-fwid-match"
                                        ].toString?.() ?? ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        x-nvidia-gpu-attestation-report-nonce-match:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.gpu?.[
                                            "x-nvidia-gpu-attestation-report-nonce-match"
                                        ].toString?.() ?? ""}
                                    </span>
                                </div>
                                <div className="tooltip-row">
                                    <span className="tooltip-label">
                                        x-nvidia-gpu-attestation-report-cert-chain:
                                    </span>
                                    <span className="tooltip-value">
                                        {teeInfo?.gpu?.[
                                            "x-nvidia-gpu-attestation-report-cert-chain"
                                        ]?.["x-nvidia-cert-status"] ?? ""}
                                    </span>
                                </div>
                            </div>
                        </div>
                    )}
                </div>

                {isConfirmModalOpen && selectedFile && (
                    <div
                        className="modal-overlay"
                        onClick={() => setIsConfirmModalOpen(false)}
                    >
                        <div
                            className="modal-content"
                            onClick={(e) => e.stopPropagation()}
                        >
                            <div className="modal-header">
                                <h3>Upload File</h3>
                                <button
                                    className="modal-close"
                                    onClick={() => setIsConfirmModalOpen(false)}
                                >
                                    ×
                                </button>
                            </div>
                            <div className="modal-body">
                                <p>
                                    Are you sure you want to upload the
                                    following file?
                                </p>
                                <div className="file-info">
                                    <strong>File Name:</strong>{" "}
                                    {selectedFile.name}
                                    <br />
                                    <strong>File Size:</strong>{" "}
                                    {(selectedFile.size / 1024).toFixed(2)} KB
                                    <br />
                                    <strong>File Type:</strong>{" "}
                                    {selectedFile.type || "text/plain"}
                                </div>
                            </div>
                            <div className="modal-footer">
                                <button
                                    className="modal-cancel-btn"
                                    onClick={() => setIsConfirmModalOpen(false)}
                                >
                                    Cancel
                                </button>
                                <button
                                    className="modal-confirm-btn"
                                    onClick={handleUpload}
                                    disabled={isUploading}
                                >
                                    {isUploading ? "Uploading..." : "Upload"}
                                </button>
                            </div>
                        </div>
                    </div>
                )}

                {isClearHistoryModalOpen && (
                    <div
                        className="modal-overlay"
                        onClick={() => setIsClearHistoryModalOpen(false)}
                    >
                        <div
                            className="modal-content"
                            onClick={(e) => e.stopPropagation()}
                        >
                            <div className="modal-header">
                                <h3>Clear Conversation History</h3>
                                <button
                                    className="modal-close"
                                    onClick={() =>
                                        setIsClearHistoryModalOpen(false)
                                    }
                                >
                                    ×
                                </button>
                            </div>
                            <div className="modal-body">
                                <p>
                                    Are you sure you want to clear the
                                    conversation history?
                                </p>
                                <p className="warning-text">
                                    This will reset the chat context and the AI
                                    will forget previous conversations.
                                </p>
                            </div>
                            <div className="modal-footer">
                                <button
                                    className="modal-cancel-btn"
                                    onClick={() =>
                                        setIsClearHistoryModalOpen(false)
                                    }
                                >
                                    Cancel
                                </button>
                                <button
                                    className="modal-confirm-btn"
                                    onClick={() => {
                                        setConversationHistory([
                                            {
                                                role: "assistant",
                                                content:
                                                    "Hello! How can I help you today?",
                                            },
                                        ]);
                                        setMessages([
                                            {
                                                id: 1,
                                                text: "Hello! How can I help you today?",
                                                sender: "bot",
                                            },
                                        ]);
                                        setIsClearHistoryModalOpen(false);
                                    }}
                                >
                                    Clear History
                                </button>
                            </div>
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

export default App;
