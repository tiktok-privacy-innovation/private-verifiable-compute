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

use super::ServiceConfig;
use crate::embedding::EmbeddingModel;
#[cfg(feature = "sqlite")]
use crate::sqlite_vector_store::SqliteVectorDb;
use crate::{
    chunking::{Chunking, SimpleChunk},
    noise::{Sessions, decrypt_with_noise},
    session::Sid,
};
use anyhow::Result;
use lru::LruCache;
use rig::Embed;
use rocket::State;
use rocket::fairing::AdHoc;
use rocket::serde::json::Json;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::RwLock;
use types::{
    ApiCode, ApiResponse, UploadDocumentReq, UploadDocumentResp, new_err, utils::get_env_or_default,
};

pub type VectorStores = Arc<RwLock<LruCache<Sid, Box<dyn VectorStore>>>>;

#[derive(Embed, Clone, Debug, Serialize, Deserialize)]
pub struct Document {
    pub id: String,
    #[embed]
    pub content: String,
}

#[async_trait]
pub trait VectorStore: Send + Sync + 'static {
    async fn insert_document(&self, documents: Vec<Document>) -> Result<()>;
    async fn query_top_n(&self, n: u64, user_query: String) -> Result<Vec<Document>>;
}

pub fn stage() -> AdHoc {
    let v: VectorStores = Arc::new(RwLock::new(LruCache::new(NonZeroUsize::new(10).unwrap())));
    AdHoc::on_ignite("VectorDb Connections", |rocket| async {
        let chunker: Arc<dyn Chunking> = Arc::new(SimpleChunk {});
        rocket.manage(v).manage(chunker)
    })
}

#[post("/document/upload", data = "<payload>")]
pub async fn upload_document(
    sessions: &State<Sessions>,
    chunk: &State<Arc<dyn Chunking>>,
    vector_stores: &State<VectorStores>,
    config: &State<ServiceConfig>,
    payload: Vec<u8>,
    sid: Sid,
) -> Result<Json<ApiResponse<UploadDocumentResp>>, ApiResponse<()>> {
    let user_uploaded = decrypt_with_noise(sessions, &sid, &payload)
        .await
        .map_err(|_| new_err(ApiCode::BadRequest, "failed to decrypt user uploaded"))?;

    let req: UploadDocumentReq = serde_json::from_slice(&user_uploaded).map_err(|_| {
        error!("failed to deserialize uploadDocument request");
        new_err(
            ApiCode::BadRequest,
            "failed to deserialize uploadDocument request",
        )
    })?;

    let documents = chunk
        .chunk(&req.filename, &req.content)
        .await
        .map_err(|e| {
            error!("failed to chunking the file {:?}", e);
            new_err(ApiCode::BadRequest, "failed to chunking the file")
        })?;

    let encryption_key = {
        let sessions = sessions.write().await;
        let session = sessions.get(&sid).unwrap();
        session.get_encryption_key().ok_or(new_err(
            ApiCode::InternalServerError,
            "encryption key is none for this session",
        ))?
    };

    let _hashed_key = encryption_key.hash();

    {
        let mut vector_stores = vector_stores.write().await;
        if let Some(vector_store) = vector_stores.get(&sid) {
            vector_store.insert_document(documents).await.map_err(|e| {
                error!(
                    "failed to insert document to sqlite vector store {}",
                    e.to_string()
                );
                new_err(
                    ApiCode::InternalServerError,
                    "failed to insert document to sqlite vector store",
                )
            })?;
        } else {
            #[allow(unused_variables)]
            let model = EmbeddingModel::new(
                &get_env_or_default("EMBEDDING_MODEL", &config.embedding_model),
                get_env_or_default("EMBEDDING_NDIMS", config.ndims.to_string())
                    .parse()
                    .unwrap(),
                &get_env_or_default("EMBEDDING_ENDPOINT", &config.emdedding_endpoint),
                &config.api_key,
            );

            #[cfg(feature = "sqlite")]
            {
                let db_name = format!("{}.db", _hashed_key);
                let vector_store =
                    SqliteVectorDb::new(&db_name, None, model)
                        .await
                        .map_err(|e| {
                            error!(
                                "failed to create vector store using sqlite {}",
                                e.to_string()
                            );
                            new_err(
                                ApiCode::InternalServerError,
                                "failed to create vector store using sqlite",
                            )
                        })?;

                vector_store.insert_document(documents).await.map_err(|e| {
                    error!(
                        "failed to insert document to sqlite vector store {}",
                        e.to_string()
                    );
                    new_err(
                        ApiCode::InternalServerError,
                        "failed to insert document to sqlite vector store",
                    )
                })?;

                vector_stores.put(sid, Box::new(vector_store));
            }
        }
    }
    Ok(Json(ApiResponse {
        code: ApiCode::Success as i32,
        message: String::new(),
        data: Some(UploadDocumentResp {}),
    }))
}
