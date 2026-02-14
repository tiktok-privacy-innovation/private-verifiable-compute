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

use rig::embeddings;
use rig::embeddings::EmbeddingError;
use rig::providers::openai::completion::Usage;
use serde::Deserialize;
use serde_json::json;

#[derive(Debug, Deserialize)]
pub struct EmbeddingResponse {
    #[serde(rename = "object")]
    pub _object: String,
    pub data: Vec<EmbeddingData>,
    #[serde(rename = "model")]
    pub _model: String,
    pub usage: Usage,
}

#[derive(Debug, Deserialize)]
pub struct EmbeddingData {
    #[serde(rename = "object")]
    pub _object: String,
    pub embedding: Vec<f64>,
    #[serde(rename = "index")]
    pub _index: usize,
}

#[derive(Clone)]
pub struct EmbeddingModel {
    base_url: String,
    api_key: String,
    client: reqwest::Client,
    pub model: String,
    ndims: usize,
}

impl embeddings::EmbeddingModel for EmbeddingModel {
    const MAX_DOCUMENTS: usize = 1024;

    type Client = reqwest::Client;

    fn make(client: &Self::Client, model: impl Into<String>, dims: Option<usize>) -> Self {
        Self {
            base_url: String::new(),
            api_key: String::new(),
            client: client.clone(),
            model: model.into(),
            ndims: dims.unwrap_or(4096),
        }
    }

    fn ndims(&self) -> usize {
        self.ndims
    }

    async fn embed_texts(
        &self,
        documents: impl IntoIterator<Item = String>,
    ) -> Result<Vec<embeddings::Embedding>, EmbeddingError> {
        let documents = documents.into_iter().collect::<Vec<_>>();

        let body = json!({
            "model": self.model,
            "input": documents,
        });

        let body = serde_json::to_vec(&body)?;

        let req = self
            .client
            .post(format!("{}/embeddings", self.base_url))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {}", self.api_key))
            .body(body)
            .build()
            .map_err(|e| EmbeddingError::ProviderError(e.to_string()))?;

        let response = self
            .client
            .execute(req)
            .await
            .map_err(|e| EmbeddingError::ProviderError(e.to_string()))?;

        if response.status().is_success() {
            let body = response
                .text()
                .await
                .map_err(|e| EmbeddingError::ProviderError(e.to_string()))?;
            let response: EmbeddingResponse = serde_json::from_str(&body)?;

            tracing::info!(target: "rig",
                "OpenAI embedding token usage: {:?}",
                response.usage
            );

            if response.data.len() != documents.len() {
                return Err(EmbeddingError::ResponseError(
                    "Response data length does not match input length".into(),
                ));
            }

            Ok(response
                .data
                .into_iter()
                .zip(documents.into_iter())
                .map(|(embedding, document)| embeddings::Embedding {
                    document,
                    vec: embedding.embedding,
                })
                .collect())
        } else {
            Err(EmbeddingError::ProviderError(format!(
                "response status is not success {}",
                response.status()
            )))
        }
    }
}

impl EmbeddingModel {
    pub fn new(model: &str, ndims: usize, base_url: &str, api_key: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            model: model.to_string(),
            ndims,
            base_url: base_url.to_string(),
            api_key: api_key.to_string(),
        }
    }
}
