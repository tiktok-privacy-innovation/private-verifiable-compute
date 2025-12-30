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

use crate::embedding::EmbeddingModel;
use crate::rag::{Document, VectorStore};
use anyhow::{Result, anyhow};
use rig::embeddings::EmbeddingsBuilder;
use rig::vector_store::VectorStoreIndex;
use rig::vector_store::request::VectorSearchRequest;
use rig_sqlite::{
    Column, ColumnValue, SqliteVectorIndex, SqliteVectorStore, SqliteVectorStoreTable,
};
use tokio_rusqlite::Connection;

impl SqliteVectorStoreTable for Document {
    fn name() -> &'static str {
        "documents"
    }

    fn schema() -> Vec<Column> {
        vec![
            Column::new("id", "TEXT PRIMARY KEY"),
            Column::new("content", "TEXT"),
        ]
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    fn column_values(&self) -> Vec<(&'static str, Box<dyn ColumnValue>)> {
        vec![
            ("id", Box::new(self.id.clone())),
            ("content", Box::new(self.content.clone())),
        ]
    }
}

#[allow(dead_code)]
pub struct SqliteVectorDb {
    pub db_name: String,
    pub encryption_key: Option<String>,
    pub embedding_model: EmbeddingModel,
    pub index: SqliteVectorIndex<EmbeddingModel, Document>,
}

impl SqliteVectorDb {
    pub async fn new(
        db_name: &str,
        encryption_key: Option<String>, // TODO: enable user-specific encryption
        model: EmbeddingModel,
    ) -> Result<Self> {
        let conn = Connection::open(db_name).await?;
        let vector_store: SqliteVectorStore<EmbeddingModel, Document> =
            SqliteVectorStore::new(conn, &model)
                .await
                .map_err(|e| anyhow!("failed to create sqlite vector store {}", e))?;
        let index: rig_sqlite::SqliteVectorIndex<EmbeddingModel, Document> =
            vector_store.index(model.clone());
        Ok(Self {
            db_name: db_name.to_string(),
            encryption_key,
            embedding_model: model,
            index,
        })
    }
}

#[async_trait]
impl VectorStore for SqliteVectorDb {
    async fn insert_document(&self, documents: Vec<Document>) -> Result<()> {
        let conn = Connection::open(&self.db_name).await?;
        let vector_store: SqliteVectorStore<EmbeddingModel, Document> =
            SqliteVectorStore::new(conn, &self.embedding_model)
                .await
                .map_err(|e| anyhow!("failed to create sqlite vector store {}", e))?;

        let embeddings = EmbeddingsBuilder::new(self.embedding_model.clone())
            .documents(documents)?
            .build()
            .await?;
        vector_store.add_rows(embeddings).await?;
        return Ok(());
    }

    async fn query_top_n(&self, samples: u64, user_query: String) -> Result<Vec<Document>> {
        let req = VectorSearchRequest::builder()
            .samples(samples)
            .query(user_query)
            .build()?;
        let results = self
            .index
            .top_n::<Document>(req.clone())
            .await?
            .into_iter()
            .collect::<Vec<_>>()
            .into_iter()
            .filter(|r| {
                r.0 < 1.0 // all threhold to filter the result
            })
            .map(|r| r.2)
            .collect();
        return Ok(results);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::ffi::{sqlite3, sqlite3_api_routines, sqlite3_auto_extension};
    use sqlite_vec::sqlite3_vec_init;
    use std::vec;
    #[cfg(feature = "sqlite")]
    type SqliteExtensionFn =
        unsafe extern "C" fn(*mut sqlite3, *mut *mut i8, *const sqlite3_api_routines) -> i32;

    fn enable_vec0() {
        unsafe {
            sqlite3_auto_extension(Some(std::mem::transmute::<*const (), SqliteExtensionFn>(
                sqlite3_vec_init as *const (),
            )));
        }
    }

    fn get_documents() -> Vec<Document> {
        let documents = vec![
            Document {
                id: "doc0".to_string(),
                content: "Definition of a *flurbo*: A flurbo is a green alien that lives on cold planets".to_string(),
            },
            Document {
                id: "doc1".to_string(),
                content: "Definition of a *glarb-glarb*: A glarb-glarb is a ancient tool used by the ancestors of the inhabitants of planet Jiro to farm the land.".to_string(),
            },
            Document {
                id: "doc2".to_string(),
                content: "Definition of a *linglingdong*: A term used by inhabitants of the far side of the moon to describe humans.".to_string(),
            },
        ];
        documents
    }

    fn get_extra_documents() -> Vec<Document> {
        let documents = vec![
            Document {
            id: "doc3".to_string(),
            content: "Definition of a *zorbulator*: A zorbulator is a compact device that converts lunar dust into breathable air for short periods.".to_string(),
        },
        Document {
            id: "doc4".to_string(),
            content: "Definition of a *quimble*: A quimble is a ceremonial garment worn by travelers of the Nebulan caravans during sandstorms.".to_string(),
        },
        Document {
            id: "doc5".to_string(),
            content: "Definition of a *tinkerspark*: A tinkerspark is a rare crystal used to power ancient satellites orbiting the red dwarf Sera.".to_string(),
        },
        ];
        documents
    }

    fn create_embedding_model() -> EmbeddingModel {
        // TODO use environment variable
        EmbeddingModel::new(
            "Qwen/Qwen3-Embedding-8B",
            4096,
            "http://35.245.195.132:8000/v1",
            "e7c0f830ba4163cf4529c1ed04216e9663bd9ead3a42a6981c266f49b87df4f5",
        )
    }

    #[tokio::test]
    #[ignore = "embedding model for test is not ready"]
    async fn test_insert() {
        enable_vec0();
        let model = create_embedding_model();
        let vector_store = SqliteVectorDb::new("test.db", None, model).await.unwrap();
        let docs = get_documents();
        let docs_extra = get_documents();
        vector_store.insert_document(docs).await.unwrap();
        vector_store.insert_document(docs_extra).await.unwrap();
    }

    #[tokio::test]
    #[ignore = "embedding model for test is not ready"]
    async fn test_insert_and_query() {
        enable_vec0();
        let model = create_embedding_model();
        let vector_store = SqliteVectorDb::new("/tmp/test.db", None, model)
            .await
            .unwrap();
        let docs = get_documents();
        let docs_extra = get_extra_documents();
        vector_store.insert_document(docs).await.unwrap();

        let n = 2;
        let documents = vector_store
            .query_top_n(n, "what is flurbo?".to_string())
            .await
            .unwrap();

        assert_eq!(documents.len(), 1);
        assert_eq!(
            documents[0].content,
            "Definition of a *flurbo*: A flurbo is a green alien that lives on cold planets"
        );

        vector_store.insert_document(docs_extra).await.unwrap();

        let n = 2;
        let documents = vector_store
            .query_top_n(n, "what is quimble?".to_string())
            .await
            .unwrap();
        assert_eq!(documents.len(), 1);
        assert_eq!(
            documents[0].content,
            "Definition of a *quimble*: A quimble is a ceremonial garment worn by travelers of the Nebulan caravans during sandstorms."
        );
    }

    #[tokio::test]
    #[ignore = "embedding model for test is not ready"]
    async fn test_insert_and_non_releated_query() {
        enable_vec0();
        let model = create_embedding_model();
        let vector_store = SqliteVectorDb::new("test.db", None, model).await.unwrap();
        let docs = get_documents();
        let docs_extra = get_extra_documents();
        vector_store.insert_document(docs).await.unwrap();
        vector_store.insert_document(docs_extra).await.unwrap();

        let n = 1;
        let documents = vector_store
            .query_top_n(n, "can you tell me today's weather?".to_string())
            .await
            .unwrap();
        assert_eq!(documents.len(), 0);
    }
}
