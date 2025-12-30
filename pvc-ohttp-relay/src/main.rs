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

use std::str::FromStr;

use ohttp_relay::{DEFAULT_PORT, GatewayUri};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    init_tracing();
    let port_env = std::env::var("PORT");
    let unix_socket_env = std::env::var("UNIX_SOCKET");
    let gateway_origin_str = std::env::var("GATEWAY_ORIGIN").expect("GATEWAY_ORIGIN is required");
    let gateway_origin =
        GatewayUri::from_str(&gateway_origin_str).expect("Invalid GATEWAY_ORIGIN URI");

    match (port_env, unix_socket_env) {
        (Ok(_), Ok(_)) => panic!(
            "Both PORT and UNIX_SOCKET environment variables are set. Please specify only one."
        ),
        (Err(_), Ok(unix_socket_path)) => {
            ohttp_relay::listen_socket(&unix_socket_path, gateway_origin).await?
        }
        (Ok(port_str), Err(_)) => {
            let port: u16 = port_str.parse().expect("Invalid PORT");
            ohttp_relay::listen_tcp(port, gateway_origin).await?
        }
        (Err(_), Err(_)) => ohttp_relay::listen_tcp(DEFAULT_PORT, gateway_origin).await?,
    }
    .await?
}

fn init_tracing() {
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env())
        .with(fmt::layer().with_target(true)) // Log the target (usually the module path and function name)
        .init();
}
