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

#[macro_use]
extern crate rocket;

mod auth;
mod resp;
mod server;

const STARTUP_RETRY_ATTEMPTS: usize = 10;
const STARTUP_RETRY_DELAY_SECS: u64 = 2;

use pvc_client_core::{IdTokenProvider, PvcClient, create_or_get_encryption_key};
use rocket::Request;
use rocket::fs::FileServer;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Duration, sleep};
use tracing::{info, warn};
use types::{ApiCode, utils::get_env_or_default};

async fn new_client_with_retry(
    identity_server_url: &str,
    gateway_url: &str,
    relay_url: &str,
    target_url: &str,
) -> PvcClient {
    for attempt in 1..=STARTUP_RETRY_ATTEMPTS {
        match PvcClient::new(
            identity_server_url.to_owned(),
            gateway_url.to_owned(),
            relay_url.to_owned(),
            target_url.to_owned(),
        )
        .await
        {
            Ok(client) => return client,
            Err(error) if attempt < STARTUP_RETRY_ATTEMPTS => {
                warn!(
                    attempt,
                    error = %error,
                    "failed to initialize pvc client during startup; retrying"
                );
                sleep(Duration::from_secs(STARTUP_RETRY_DELAY_SECS)).await;
            }
            Err(error) => panic!("failed to initialize pvc client after retries: {error}"),
        }
    }

    unreachable!()
}

async fn warm_client_if_possible(client: &mut PvcClient, key: &types::keys::ContextKey) {
    match client.handshake_with_attestation(None).await {
        Ok(_) => match client.upload_encryption_key(key).await {
            Ok(_) => info!("initialized pvc client encryption key at startup"),
            Err(error) => warn!(
                error = %error,
                "startup encryption-key upload failed; continuing without warmup"
            ),
        },
        Err(error) => warn!(
            error = %error,
            "startup handshake failed; continuing without warmup"
        ),
    }
}

/// Catcher for 400 responses from failed request/data guards. We render a
/// structured `ApiCode::InvalidRequestBody` envelope (JSON body with HTTP
/// 200) so the OHTTP gateway forwards it intact instead of swallowing it
/// behind a generic 502.
#[catch(400)]
fn invalid_request_catcher(req: &Request<'_>) -> ApiCode {
    tracing::warn!(
        method = %req.method(),
        path = %req.uri().path(),
        "returning structured InvalidRequestBody envelope for 400"
    );
    ApiCode::InvalidRequestBody
}

/// Catcher for 422 responses from JSON deserialization failures. Mirrors
/// [`invalid_request_catcher`] in shape so clients only have to handle one
/// structured failure code on the wire.
#[catch(422)]
fn invalid_entity_catcher(req: &Request<'_>) -> ApiCode {
    tracing::warn!(
        method = %req.method(),
        path = %req.uri().path(),
        "returning structured InvalidRequestBody envelope for 422"
    );
    ApiCode::InvalidRequestBody
}

#[launch]
async fn rocket() -> _ {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let key = create_or_get_encryption_key().unwrap();
    let identity_server_url = get_env_or_default("IDENTITY_SERVER_URL", "http://localhost:8000");
    let gateway_url = get_env_or_default("GATEWAY_URL", "http://localhost:8082");
    let relay_url = get_env_or_default("RELAY_URL", "http://localhost:8787");
    let target_url = get_env_or_default("TARGET_URL", "localhost:9000");
    let mut client =
        new_client_with_retry(&identity_server_url, &gateway_url, &relay_url, &target_url).await;

    // Wire the live OAuth token state into the recovery path BEFORE the
    // first handshake so that, after a tee-llm pod restart, `recover_session`
    // re-handshakes with whatever token is in `oauth_token` at that moment
    // (which is updated by `auth::login_with_oauth_token`) instead of a
    // stale cached copy of the token last used at startup.
    let oauth_token: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    client.set_id_token_provider(oauth_token.clone() as Arc<dyn IdTokenProvider>);

    if oauth::get_oauth_type() == oauth::OauthType::Disable {
        warm_client_if_possible(&mut client, &key).await;
    }

    let client_state = Arc::new(RwLock::new(client));
    rocket::build()
        .manage(client_state)
        .manage(key)
        .manage(oauth_token)
        .mount("/", routes![server::health])
        .register(
            "/",
            catchers![invalid_request_catcher, invalid_entity_catcher],
        )
        // OpenAI compatible
        .mount("/v1", routes![server::chat_completions])
        .mount(
            "/api",
            routes![
                server::attestation,
                auth::auth_config,
                auth::login_with_oauth_token,
                server::upload
            ],
        )
        .mount("/", routes![auth::google_oauth_callback])
        .mount("/", FileServer::from("static"))
}
