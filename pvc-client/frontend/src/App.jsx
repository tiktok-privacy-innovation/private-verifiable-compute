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

import { useState, useEffect, useRef } from 'react'
import './App.css'

function App() {
  const [messages, setMessages] = useState([
    { id: 1, text: "Hello! How can I help you today?", sender: "bot" }
  ]);
  const [inputText, setInputText] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isTooltipVisible, setIsTooltipVisible] = useState(false);
  const [isInitializing, setIsInitializing] = useState(true);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [teeInfo, setTeeInfo] = useState({});
  const [authConfig, setAuthConfig] = useState(null);

  const [selectedFile, setSelectedFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef(null);
  const messagesEndRef = useRef(null);
  const [isUploadTooltipVisible, setIsUploadTooltipVisible] = useState(false);
  const [isConfirmModalOpen, setIsConfirmModalOpen] = useState(false);

  const scrollToBottom = (smooth = true) => {
    const el = messagesEndRef.current;
    const behavior = smooth ? "smooth" : "auto";
    messagesEndRef.current?.scrollIntoView({
      behavior: smooth ? "smooth" : "auto"
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
      sender: "user"
    };

    setMessages([...messages, newUserMessage]);
    setIsLoading(true);

    try {
      const response = await fetch('/api/inference', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(inputText),
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const data = await response.json();

      if (data.code !== 0) {
        const businessError = new Error(data.message);
        throw businessError;
      }

      const botResponse = {
        id: messages.length + 2,
        text: data.data.content,
        sender: "bot"
      };

      setMessages(prev => [...prev, botResponse]);
    } catch (error) {
      console.error("Error during fetch:", error);
      const errorMessage = {
        id: messages.length + 2,
        text: `Sorry, an error occurred: ${error.message}`,
        sender: "bot"
      };

      setMessages(prev => [...prev, errorMessage]);
      console.error("Error:", error);
    } finally {
      setIsLoading(false);
      setInputText("");
    }
  };

  useEffect(() => {
    const initializeApp = async () => {

      try {
        const authResponse = await fetch('/api/auth/config');
        if (!authResponse.ok) {
          throw new Error('Failed to fetch auth config');
        }
        const authData = await authResponse.json();
        setAuthConfig(authData.data);
        if (authData.data.loggedin) {
          const randomArray = new Uint8Array(64);
          crypto.getRandomValues(randomArray);
          const base64Data = btoa(String.fromCharCode(...randomArray));
          const attestationResponse = await fetch('/api/attestation', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nonce: base64Data }),
          });
          if (!attestationResponse.ok) {
            throw new Error(`HTTP error! status: ${attestationResponse.status}`);
          }
          const teeData = await attestationResponse.json();
          console.log(teeData.data)
          setTeeInfo(teeData.data);
        }
      } catch (error) {
        console.error("Failed to initialize app:", error);
        setAuthConfig({ enabled: false, client_id: '' });
      } finally {
        setIsInitializing(false);
      }
    };

    initializeApp();
  }, [isLoggedIn]);

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      handleSend();
    }
  };

  const handleFileChange = (e) => {
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      const fileName = file.name.toLowerCase();
      
      if (!fileName.endsWith('.txt') && !fileName.endsWith('.md')) {
        alert('Please select only .txt or .md files');
        e.target.value = '';
        return;
      }
      
      if (file.size > 4 * 1024 * 1024) {
        alert('File size exceeds 5MB limit');
        e.target.value = '';
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
    formData.append('file', selectedFile);

    try {
      const response = await fetch('/api/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      const result = await response.json();
      const uploadMessage = {
        id: messages.length + 1,
        text: `File uploaded successfully: ${selectedFile.name}`,
        sender: "user"
      };
      setMessages(prev => [...prev, uploadMessage]);
      setSelectedFile(null);
      setIsConfirmModalOpen(false);
      if (fileInputRef.current) {
        fileInputRef.current.value = '';
      }
    } catch (error) {
      console.error("Upload failed:", error);
      const errorMessage = {
        id: messages.length + 1,
        text: "Sorry, file upload failed. Please try again.",
        sender: "bot"
      };
      setMessages(prev => [...prev, errorMessage]);
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
      var oauth2Endpoint = 'https://accounts.google.com/o/oauth2/v2/auth';
      const randomArray = new Uint8Array(64);
      crypto.getRandomValues(randomArray);
      const randomState = btoa(String.fromCharCode(...randomArray));
      var params = new URLSearchParams({
        'client_id': authConfig.clientID,
        'redirect_uri': 'http://localhost:8083/auth/google/callback',
        'response_type': 'id_token',
        'scope': 'openid profile',
        'state': randomState,
        'nonce': "pvc-client"
      });
      const authUrl = `${oauth2Endpoint}?${params.toString()}`;
      window.location.href = authUrl;
    };

    return (
      <div className="app-login">
        <div className="login-container">
          <h2>Welcome to Private Verifiable Cloud</h2>
          <p>Please sign in to continue</p>
          <button className="google-login-btn" onClick={handleGoogleLogin}>
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="24" height="24">
              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" />
              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" />
              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" />
              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" />
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
        </div>
        <div className="chat-messages">
          {messages.map((message) => (
            <div
              key={message.id}
              className={`message ${message.sender === "user" ? "user-message" : "bot-message"}`}
            >
              <div className="message-text">{message.text}</div>
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
            <button onClick={handleSend} disabled={isLoading || inputText.trim() === ""}>
              {isLoading ? "Sending..." : "Send"}
            </button>
            <label className="file-upload-label">
              <input
                type="file"
                onChange={handleFileChange}
                disabled={isUploading}
                style={{ display: 'none' }}
                accept=".txt,.md,text/plain,text/markdown"
              />
              <span 
                className="file-upload-icon" 
                onMouseEnter={() => setIsUploadTooltipVisible(true)}
                onMouseLeave={() => setIsUploadTooltipVisible(false)}
              >
                <svg width="30" height="30" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                  <path d="M14 3v4a1 1 0 0 0 1 1h4" stroke="currentColor" strokeWidth="2" />
                  <path d="M17 21H7a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7l5 5v11a2 2 0 0 1-2 2z" stroke="currentColor" strokeWidth="2" />
                  <path d="M12 11v6" stroke="currentColor" strokeWidth="2" />
                  <path d="M9.5 13.5L12 11l2.5 2.5" stroke="currentColor" strokeWidth="2" />
                </svg>
              </span>
              {isUploadTooltipVisible && (
                <div className="upload-tooltip">
                  <div className="tooltip-header">Upload Knowledge Documents</div>
                  <div className="tooltip-content">
                    Upload documents to enhance the AI's knowledge with your specific information
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
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
              <path d="M12 22C12 22 20 18 20 12V5L12 2L4 5V12C4 18 12 22 12 22Z" stroke="white" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </div>
          <span className="status-text">TDX Protection Active</span>

          {/* Tooltip */}
          {isTooltipVisible && (
            <div className="tooltip">
              <div className="tooltip-header">TDX Protection Details</div>
              <div className="tooltip-content">
                <div className="tooltip-row">
                  <span className="tooltip-label">TEE:</span>
                  <span className="tooltip-value">Intel TDX</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">ReportData:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.report_data ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">Debug:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.td_attributes?.debug?.toString?.() ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">TCB Status:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.tcb_status ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">MR_SEAM:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.quote?.body?.mr_seam ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">MR_TD:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.quote?.body?.mr_seam ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">RTMR0:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.quote?.body?.rtmr_0 ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">RTMR1:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.quote?.body?.rtmr_1 ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">RTMR2:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.quote?.body?.rtmr_2 ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">RTMR3:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.quote?.body?.rtmr_3 ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">TCB SVN:</span>
                  <span className="tooltip-value">{teeInfo?.cpu?.quote?.body?.tcb_svn ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">GPU Hardware Model:</span>
                  <span className="tooltip-value">{teeInfo?.gpu?.hwmodel ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">x-nvidia-gpu-attestation-report-cert-chain-fwid-match:</span>
                  <span className="tooltip-value">{teeInfo?.gpu?.["x-nvidia-gpu-attestation-report-cert-chain-fwid-match"].toString?.() ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">x-nvidia-gpu-attestation-report-nonce-match:</span>
                  <span className="tooltip-value">{teeInfo?.gpu?.["x-nvidia-gpu-attestation-report-nonce-match"].toString?.() ?? ''}</span>
                </div>
                <div className="tooltip-row">
                  <span className="tooltip-label">x-nvidia-gpu-attestation-report-cert-chain:</span>
                  <span className="tooltip-value">{teeInfo?.gpu?.["x-nvidia-gpu-attestation-report-cert-chain"]?.["x-nvidia-cert-status"] ?? ''}</span>
                </div>
              </div>
            </div>
          )}
        </div>

        {isConfirmModalOpen && selectedFile && (
          <div className="modal-overlay" onClick={() => setIsConfirmModalOpen(false)}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
              <div className="modal-header">
                <h3>Upload File</h3>
                <button className="modal-close" onClick={() => setIsConfirmModalOpen(false)}>×</button>
              </div>
              <div className="modal-body">
                <p>Are you sure you want to upload the following file?</p>
                <div className="file-info">
                  <strong>File Name:</strong> {selectedFile.name}<br />
                  <strong>File Size:</strong> {(selectedFile.size / 1024).toFixed(2)} KB<br />
                  <strong>File Type:</strong> {selectedFile.type || 'text/plain'}
                </div>
              </div>
              <div className="modal-footer">
                <button className="modal-cancel-btn" onClick={() => setIsConfirmModalOpen(false)}>
                  Cancel
                </button>
                <button className="modal-confirm-btn" onClick={handleUpload} disabled={isUploading}>
                  {isUploading ? "Uploading..." : "Upload"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default App
