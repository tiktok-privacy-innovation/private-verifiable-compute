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
mod client;
mod key;
mod resp;
mod server;

use client::PvcClient;
use rocket::fs::FileServer;
use std::sync::Arc;
use tokio::sync::RwLock;
use types::utils::get_env_or_default;

#[launch]
async fn rocket() -> _ {
    use tracing_subscriber::EnvFilter;

    tracing_subscriber::fmt()
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let key = key::create_or_get_encryption_key().unwrap();
    let mut client = PvcClient::new(
        get_env_or_default("IDENTITY_SERVER_URL", "http://localhost:8000"),
        get_env_or_default("GATEWAY_URL", "http://localhost:8082"),
        get_env_or_default("RELAY_URL", "http://localhost:8787"),
        get_env_or_default("TARGET_URL", "localhost:9000"),
    )
    .await
    .unwrap();

    if oauth::get_oauth_type() == oauth::OauthType::Disable {
        client.handshake_with_attestation(None).await.unwrap();
        client.upload_encryption_key(&key).await.unwrap();
    }

    let client_state = Arc::new(RwLock::new(client));
    let oauth_token: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
    rocket::build()
        .manage(client_state)
        .manage(key)
        .manage(oauth_token)
        .mount("/", routes![server::health])
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
