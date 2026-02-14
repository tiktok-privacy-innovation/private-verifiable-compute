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
mod chat;
mod chunking;
mod embedding;
mod fairing;
mod gpu_attester;
mod inference;
mod noise;
mod rag;
mod request;
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
use types::{ApiResult, utils::get_env_or_default};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
struct ServiceConfig {
    system_prompt: String,
    chat_template: String,
    llm_model: String,
    llm_endpoint: String,
    max_tokens: u32,
    embedding_model: String,
    emdedding_endpoint: String,
    ndims: usize,
    api_key: String,
    api: String,
    identity_server_url: String,
}

impl ServiceConfig {
    pub fn overwrite_from_env(&mut self) {
        self.llm_model = get_env_or_default("LLM_MODEL", &self.llm_model);
        self.llm_endpoint = get_env_or_default("LLM_ENDPOINT", &self.llm_endpoint);
        self.embedding_model = get_env_or_default("EMBEDDING_MODEL", &self.embedding_model);
        self.emdedding_endpoint =
            get_env_or_default("EMBEDDING_ENDPOINT", &self.emdedding_endpoint);
        self.ndims = get_env_or_default("EMBEDDING_NDIMS", self.ndims.to_string())
            .parse()
            .unwrap();
        self.max_tokens = get_env_or_default("LLM_MAX_TOKEN", self.max_tokens.to_string())
            .parse()
            .unwrap();
        self.identity_server_url =
            get_env_or_default("IDENTITY_SERVER_URL", &self.identity_server_url)
    }
}

#[get("/health")]
fn health() -> ApiResult<()> {
    ApiResult::Ok(())
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
    let mut config: ServiceConfig = figment.extract().expect("llm config");
    config.overwrite_from_env();

    #[cfg(feature = "sqlite")]
    unsafe {
        sqlite3_auto_extension(Some(std::mem::transmute::<*const (), SqliteExtensionFn>(
            sqlite3_vec_init as *const (),
        )));
    }

    rocket
        .manage(config.clone())
        .attach(session::stage())
        .attach(noise::stage(config.identity_server_url.clone()))
        .attach(HeaderLogger)
        .attach(rag::stage())
        .attach(chat::stage(
            &config.system_prompt,
            config.max_tokens as usize,
            &config.llm_endpoint,
            &config.llm_model,
        ))
        .attach(AdHoc::on_ignite("Init signing key", |rocket| async {
            let signing_key = SigningKey::random(&mut OsRng);
            rocket.manage(Mutex::new(signing_key))
        }))
        .mount(&config.api, routes![noise::upload_key, noise::establish])
        .mount(&config.api, routes![rag::upload_document])
        .mount(&config.api, routes![inference::chat_completions])
        .mount("/", routes![health])
        .mount(
            &config.api,
            routes![
                attestation::handshake_with_attestation,
                attestation::attestation
            ],
        )
}
