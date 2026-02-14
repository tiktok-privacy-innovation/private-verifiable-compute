// Copyright 2025 TikTok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use futures::io::Cursor;
use futures::stream::StreamExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use ohttp_gateway::{error::GatewayError, state::AppState};
use ohttp_wrap::Message;
use tracing::{debug, error, info, warn};
use types::async_rw;

const OHTTP_REQUEST_CONTENT_TYPE: &str = "message/ohttp-req";
const OHTTP_RESPONSE_CONTENT_TYPE: &str = "message/ohttp-res";

pub async fn handle_stream_ohttp_request(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    state.metrics.requests_total.inc();

    #[cfg(feature = "base64")]
    let body = {
        use base64::engine::general_purpose;

        use base64::Engine as _;
        let decoded = general_purpose::STANDARD.decode(&body).unwrap();
        Bytes::from(decoded)
    };

    // Extract key ID from the request if possible
    let key_id = extract_key_id_from_request(&body);

    let result = handle_stream_ohttp_request_inner(state.clone(), headers, body, key_id).await;

    match result {
        Ok(response) => response,
        Err(e) => {
            error!("OHTTP request failed: {:?}", e);

            // Log metrics based on error type
            match &e {
                GatewayError::DecryptionError(_) => state.metrics.decryption_errors_total.inc(),
                GatewayError::EncryptionError(_) => state.metrics.encryption_errors_total.inc(),
                GatewayError::BackendError(_) => state.metrics.backend_errors_total.inc(),
                _ => {}
            }

            e.into_response()
        }
    }
}

async fn handle_stream_ohttp_request_inner(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    key_id: Option<u8>,
) -> Result<Response, GatewayError> {
    // Validate request
    validate_ohttp_request(&headers, &body, &state)?;

    // Get the appropriate server based on key ID
    let ohttp_server = if let Some(id) = key_id {
        // Try to get server for specific key ID
        match state.key_manager.get_server_by_id(id).await {
            Some(server) => {
                debug!("Using server for key ID: {}", id);
                server
            }
            None => {
                warn!("Unknown key ID: {}, falling back to current server", id);
                state
                    .key_manager
                    .get_current_server()
                    .await
                    .map_err(|e| GatewayError::ConfigurationError(e.to_string()))?
            }
        }
    } else {
        // Use current active server
        state
            .key_manager
            .get_current_server()
            .await
            .map_err(|e| GatewayError::ConfigurationError(e.to_string()))?
    };

    // Decrypt the OHTTP request
    // ohttp server decrypts the incoming ohttp encrypted request
    let mut server_request_reader = ohttp_server.decapsulate_stream(Cursor::new(&body));
    let mut bhttp_request = Vec::new();
    AsyncReadExt::read_to_end(&mut server_request_reader, &mut bhttp_request)
        .await
        .map_err(|e| {
            GatewayError::DecryptionError(format!("Failed to decapsulate input request: {e}"))
        })?;

    // Parse binary HTTP message
    let message = parse_bhttp_message(&bhttp_request)?;

    // Validate and potentially transform the request
    let message = validate_and_transform_request(message, &state)?;

    // Forward request to backend
    let backend_response = forward_to_backend(&state, message).await?;

    // Create a channel for streaming the encrypted response
    let (channel_writer, channel_reader) = async_rw::create_channel_pair_with_size(1024);

    // ohttp server receives from the backend server
    // and encrypts the response streams
    let mut encrypted_writer = server_request_reader
        .response(channel_writer)
        .map_err(|e| GatewayError::InternalError(format!("Response build error: {e}")))?;

    // Spawn a task to write the backend response stream to the encrypted writer
    let backend_response_stream = backend_response.bytes_stream();
    tokio::spawn(async move {
        let mut stream = Box::pin(backend_response_stream);
        while let Some(chunk_result) = stream.next().await {
            match chunk_result {
                Ok(chunk) => {
                    use futures::AsyncWriteExt;
                    // ohttp encryption here
                    if let Err(e) = encrypted_writer.write_all(&chunk).await {
                        error!("Failed to write to encrypted response: {e}");
                        break;
                    }
                }
                Err(e) => {
                    error!("Failed to read from backend response stream: {e}");
                    break;
                }
            }
        }

        // Finalize the encrypted writer
        if let Err(e) = AsyncWriteExt::close(&mut encrypted_writer).await {
            error!("Failed to close encrypted writer: {e}");
        }
    });

    state.metrics.successful_requests_total.inc();

    let body_stream = futures::stream::unfold(channel_reader, |mut rx| async move {
        let mut buffer = vec![0; 1024];
        match AsyncReadExt::read(&mut rx, &mut buffer).await {
            Ok(0) => None, // EOF
            Ok(n) => Some((
                Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(&buffer[..n])),
                rx,
            )),
            Err(e) => {
                error!("Failed to read from channel: {}", e);
                None
            }
        }
    });

    // Build response with appropriate headers
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, OHTTP_RESPONSE_CONTENT_TYPE)
        .header(header::CACHE_CONTROL, "no-cache, no-store, must-revalidate")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "DENY")
        .body(Body::from_stream(body_stream))
        .map_err(|e| GatewayError::InternalError(format!("Response build error: {e}")))
}

/// Extract key ID from OHTTP request (first byte after version)
fn extract_key_id_from_request(body: &[u8]) -> Option<u8> {
    // OHTTP request format: version(1) + key_id(1) + kem_id(2) + kdf_id(2) + aead_id(2) + enc + ciphertext
    if body.len() > 1 { Some(body[1]) } else { None }
}

/// Validate the incoming OHTTP request
fn validate_ohttp_request(
    headers: &HeaderMap,
    body: &Bytes,
    state: &AppState,
) -> Result<(), GatewayError> {
    // Check content type
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| GatewayError::InvalidRequest("Missing content-type header".to_string()))?;

    if content_type != OHTTP_REQUEST_CONTENT_TYPE {
        return Err(GatewayError::InvalidRequest(format!(
            "Invalid content-type: expected '{OHTTP_REQUEST_CONTENT_TYPE}', got '{content_type}'"
        )));
    }

    // Check body size
    if body.is_empty() {
        return Err(GatewayError::InvalidRequest(
            "Empty request body".to_string(),
        ));
    }

    if body.len() > state.config.max_body_size {
        return Err(GatewayError::RequestTooLarge(format!(
            "Request body too large: {} bytes (max: {})",
            body.len(),
            state.config.max_body_size
        )));
    }

    // Minimum OHTTP request size check
    if body.len() < 10 {
        return Err(GatewayError::InvalidRequest(
            "Request too small to be valid OHTTP".to_string(),
        ));
    }

    Ok(())
}

/// Parse binary HTTP message with error handling
fn parse_bhttp_message(data: &[u8]) -> Result<Message, GatewayError> {
    let mut cursor = std::io::Cursor::new(data);
    Message::read_bhttp(&mut cursor)
        .map_err(|e| GatewayError::InvalidRequest(format!("Failed to parse binary HTTP: {e}")))
}

/// Validate and transform the request based on security policies
fn validate_and_transform_request(
    message: Message,
    state: &AppState,
) -> Result<Message, GatewayError> {
    let control = message.control();

    // Extract host from authority or Host header
    let host = control
        .authority()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .or_else(|| {
            message.header().fields().iter().find_map(|field| {
                if field.name().eq_ignore_ascii_case(b"host") {
                    Some(String::from_utf8_lossy(field.value()).into_owned())
                } else {
                    None
                }
            })
        })
        .ok_or_else(|| GatewayError::InvalidRequest("Missing host/authority".to_string()))?;

    // Extract and clean the path
    let raw_path = control.path().unwrap_or(b"/");
    let path_str = String::from_utf8_lossy(raw_path);

    // Clean up the path - remove any absolute URL components
    let clean_path = if path_str.starts_with("http://") || path_str.starts_with("https://") {
        // Extract just the path from absolute URL
        if let Some(idx) = path_str
            .find('/')
            .and_then(|i| path_str[i + 2..].find('/').map(|j| i + 2 + j))
        {
            path_str[idx..].as_bytes()
        } else {
            b"/"
        }
    } else if path_str.contains(':') && !path_str.starts_with('/') {
        // Path might contain host:port, clean it
        b"/"
    } else {
        raw_path
    };

    debug!(
        "Request details - host: {}, original_path: {}, clean_path: {}",
        host,
        path_str,
        String::from_utf8_lossy(clean_path)
    );

    // Check if origin is allowed
    if !state.config.is_origin_allowed(&host) {
        warn!("Blocked request to forbidden origin: {host}");
        return Err(GatewayError::InvalidRequest(format!(
            "Target origin not allowed: {host}"
        )));
    }

    // Apply any configured rewrites
    if let Some(rewrite) = state.config.get_rewrite(&host) {
        debug!(
            "Applying rewrite for host {}: {} -> {}",
            host, rewrite.scheme, rewrite.host
        );

        // Clone the message to modify it
        let mut new_message = Message::request(
            Vec::from(control.method().unwrap_or(b"GET")), // method
            Vec::from(rewrite.scheme.as_bytes()),          // scheme
            Vec::from(rewrite.host.as_bytes()),            // authority
            Vec::from(clean_path),                         // path
        );

        // Copy all headers except Host and Authority
        for field in message.header().fields() {
            let name = field.name();
            if !name.eq_ignore_ascii_case(b"host") && !name.eq_ignore_ascii_case(b"authority") {
                new_message.put_header(name, field.value());
            }
        }

        // Add the new Host header
        new_message.put_header(b"host", rewrite.host.as_bytes());

        // Copy body content
        if !message.content().is_empty() {
            new_message.write_content(message.content());
        }

        return Ok(new_message);
    }

    Ok(message)
}

async fn forward_to_backend(
    state: &AppState,
    bhttp_message: Message,
) -> Result<reqwest::Response, GatewayError> {
    let control = bhttp_message.control();
    let method = control.method().unwrap_or(b"GET");
    let path = control
        .path()
        .map(|p| String::from_utf8_lossy(p).into_owned())
        .unwrap_or_else(|| "/".to_string());

    // Extract host for URL construction
    let host = control
        .authority()
        .map(|a| String::from_utf8_lossy(a).into_owned())
        .or_else(|| {
            bhttp_message.header().fields().iter().find_map(|field| {
                if field.name().eq_ignore_ascii_case(b"host") {
                    Some(String::from_utf8_lossy(field.value()).into_owned())
                } else {
                    None
                }
            })
        });

    // Build the backend URI
    let uri = if let Some(host) = host {
        // Extract scheme, handling various formats
        let scheme = control
            .scheme()
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_else(|| "http".to_string());
        format!("{scheme}://{host}{path}")
    } else {
        build_backend_uri(&state.config.backend_url, &path)?
    };

    info!(
        "Forwarding {} request to {}",
        String::from_utf8_lossy(method),
        uri
    );

    let reqwest_method = convert_method_to_reqwest(method);
    let mut request_builder = state.http_client.request(reqwest_method, &uri);

    // Add headers from the binary HTTP message
    for field in bhttp_message.header().fields() {
        let name = String::from_utf8_lossy(field.name());
        let value = String::from_utf8_lossy(field.value());

        // Skip headers that should not be forwarded
        if should_forward_header(&name) {
            request_builder = request_builder.header(name.as_ref(), value.as_ref());
        }
    }

    // Add body if present
    let content = bhttp_message.content();
    if !content.is_empty() {
        request_builder = request_builder.body(content.to_vec());
    }

    // Send request with timeout
    let response = request_builder.send().await.map_err(|e| {
        error!("Backend request failed: {e}");
        GatewayError::BackendError(format!("Backend request failed: {e}"))
    })?;

    // Check for backend errors
    if !response.status().is_success() {
        return Err(GatewayError::BackendError(format!(
            "Backend returned error: {}",
            response.status()
        )));
    }

    Ok(response)
}

fn convert_method_to_reqwest(method: &[u8]) -> reqwest::Method {
    match method {
        b"GET" => reqwest::Method::GET,
        b"POST" => reqwest::Method::POST,
        b"PUT" => reqwest::Method::PUT,
        b"DELETE" => reqwest::Method::DELETE,
        b"HEAD" => reqwest::Method::HEAD,
        b"OPTIONS" => reqwest::Method::OPTIONS,
        b"PATCH" => reqwest::Method::PATCH,
        b"TRACE" => reqwest::Method::TRACE,
        _ => reqwest::Method::GET,
    }
}

fn build_backend_uri(backend_url: &str, path: &str) -> Result<String, GatewayError> {
    let base_url = backend_url.trim_end_matches('/');
    let clean_path = if path.starts_with('/') {
        path
    } else {
        &format!("/{path}")
    };

    // Validate path to prevent SSRF attacks
    if clean_path.contains("..") || clean_path.contains("//") {
        return Err(GatewayError::InvalidRequest(
            "Invalid path detected".to_string(),
        ));
    }

    // Additional validation for suspicious patterns
    if clean_path.contains('\0') || clean_path.contains('\r') || clean_path.contains('\n') {
        return Err(GatewayError::InvalidRequest(
            "Invalid characters in path".to_string(),
        ));
    }

    // Build the final URI with explicit formatting
    let final_uri = format!("{base_url}{clean_path}");
    debug!("build_backend_uri: final_uri = '{}'", final_uri);

    Ok(final_uri)
}

fn should_forward_header(name: &str) -> bool {
    const SKIP_HEADERS: &[&str] = &[
        "host",
        "connection",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
        "te",
        "trailers",
        "transfer-encoding",
        "keep-alive",
        "http2-settings",
        "upgrade-insecure-requests",
    ];

    !SKIP_HEADERS.contains(&name.to_lowercase().as_str())
}
