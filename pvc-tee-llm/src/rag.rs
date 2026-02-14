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
use crate::request::CleartextPayload;
use crate::session::Sessions;
#[cfg(feature = "sqlite")]
use crate::sqlite_vector_store::SqliteVectorDb;
use crate::{
    chunking::{Chunking, SimpleChunk},
    session::Sid,
};
use anyhow::Result;
use lru::LruCache;
use rig::Embed;
use rocket::State;
use rocket::fairing::AdHoc;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::error;
use types::{ApiCode, ApiResult, UploadDocumentReq};

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

#[post("/documents", data = "<user_upload>")]
pub async fn upload_document(
    sessions: &State<Sessions>,
    chunk: &State<Arc<dyn Chunking>>,
    vector_stores: &State<VectorStores>,
    config: &State<ServiceConfig>,
    user_upload: CleartextPayload,
    sid: Sid,
) -> ApiResult<()> {
    let logic = async || -> Result<(), ApiCode> {
        let req: UploadDocumentReq =
            serde_json::from_slice(&user_upload.as_bytes()).map_err(|_| {
                error!("failed to deserialize uploadDocument request");
                ApiCode::InvalidRequestBody
            })?;

        let documents = chunk
            .chunk(&req.filename, &req.content)
            .await
            .map_err(|e| {
                error!("failed to chunking the file {:?}", e);
                ApiCode::UnSupportedDocumentFormat
            })?;

        let context_key = {
            let session = sessions
                .get(&sid)
                .await
                .map_err(|_| ApiCode::InvalidIdentityToken)?;
            session
                .lock()
                .await
                .get_context_key()
                .ok_or(ApiCode::UnkownContextEncryptionKey)?
        };

        #[allow(unused_variables)]
        let hashed_key = context_key.hash();

        {
            let mut vector_stores = vector_stores.write().await;

            if vector_stores.get(&sid).is_none() {
                #[allow(unused_variables)]
                let model = EmbeddingModel::new(
                    &config.embedding_model,
                    config.ndims,
                    &config.emdedding_endpoint,
                    &config.api_key,
                );

                #[cfg(feature = "sqlite")]
                {
                    let db_name = format!("{}.db", hashed_key);
                    let vector_store =
                        SqliteVectorDb::new(&db_name, None, model)
                            .await
                            .map_err(|e| {
                                error!(
                                    error = %e,
                                    "failed to create vector store using sqlite",
                                );
                                ApiCode::VectorStoreError
                            })?;
                    vector_stores.put(sid.clone(), Box::new(vector_store));
                }
            }

            if let Some(vector_store) = vector_stores.get(&sid) {
                #[cfg(feature = "sqlite")]
                {
                    vector_store.insert_document(documents).await.map_err(|e| {
                        error!(
                            error = %e,
                            "failed to insert document to sqlite vector store",
                        );
                        ApiCode::VectorStoreError
                    })?;
                }
            } else {
                return Err(ApiCode::VectorStoreError);
            }
        }

        Ok(())
    };

    logic().await.into()
}
