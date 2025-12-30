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

#[macro_use]
extern crate rocket;

mod attestation;
mod cache;
mod cache_redis;
mod chat;
mod chunking;
mod embedding;
mod fairing;
#[cfg(feature = "attestation")]
mod gpu_attester;
mod inference;
mod noise;
mod rag;
mod session;

#[cfg(feature = "sqlite")]
mod sqlite_vector_store;
use fairing::HeaderLogger;
use p256::ecdsa::SigningKey;
use rand_core::OsRng;
use rocket::fairing::AdHoc;
use rocket::serde::{Deserialize, Serialize};
#[cfg(feature = "sqlite")]
use rusqlite::ffi::{sqlite3, sqlite3_api_routines, sqlite3_auto_extension};
#[cfg(feature = "sqlite")]
use sqlite_vec::sqlite3_vec_init;
use tokio::sync::Mutex;
use tracing_subscriber::filter::{EnvFilter, LevelFilter};

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct ServiceConfig {
    system_prompt: String,
    chat_template: String,
    llm_model: String,
    llm_endpoint: String,
    max_tokens: u32,
    embedding_model: String,
    emdedding_endpoint: String,
    redis_endpoint: String,
    ndims: usize,
    api_key: String,

    handshake: String,
    inference: String,
    health: String,
    attestation: String,
    attestation_with_nonce: String,
}

#[get("/")]
fn health() -> &'static str {
    ""
}

#[cfg(feature = "sqlite")]
type SqliteExtensionFn =
    unsafe extern "C" fn(*mut sqlite3, *mut *mut i8, *const sqlite3_api_routines) -> i32;

#[launch]
fn rocket() -> _ {
    let filter = EnvFilter::from_default_env()
        .add_directive(LevelFilter::INFO.into())
        .add_directive("rocket=warn".parse().unwrap());
    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(filter)
        .with_thread_ids(true)
        .with_thread_names(true)
        .init();
    let rocket = rocket::build();
    let figment = rocket.figment();

    // load the routing configuration
    let config: ServiceConfig = figment.extract().expect("llm config");

    #[cfg(feature = "sqlite")]
    unsafe {
        sqlite3_auto_extension(Some(std::mem::transmute::<*const (), SqliteExtensionFn>(
            sqlite3_vec_init as *const (),
        )));
    }

    rocket
        .attach(noise::stage())
        .attach(HeaderLogger)
        .attach(rag::stage())
        .attach(chat::stage(
            &config.redis_endpoint,
            &config.system_prompt,
            Some(config.max_tokens as usize),
            Some(&config.llm_model),
            Some(&config.llm_endpoint),
        ))
        .attach(AdHoc::config::<ServiceConfig>())
        .attach(AdHoc::on_ignite("Init signing key", |rocket| async {
            let signing_key = SigningKey::random(&mut OsRng);
            rocket.manage(Mutex::new(signing_key))
        }))
        .mount("/", routes![noise::upload_key, rag::upload_document])
        .mount(config.handshake, routes![noise::handshake])
        .mount(config.inference, routes![inference::inference])
        .mount(config.health, routes![health])
        .mount(config.attestation, routes![attestation::attestation])
        .mount(
            config.attestation_with_nonce,
            routes![attestation::attestation_with_nonce],
        )
}
