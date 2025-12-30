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

use crate::rag::Document;
use anyhow::Result;
use regex::Regex;

#[async_trait]
pub trait Chunking: Send + Sync {
    async fn chunk(&self, doc_name: &str, content: &str) -> Result<Vec<Document>>;
}

pub struct SimpleChunk {}

#[async_trait]
impl Chunking for SimpleChunk {
    async fn chunk(&self, doc_name: &str, content: &str) -> Result<Vec<Document>> {
        let re_q = Regex::new(r"(?im)^\s*(?:Q|Question)\s*[:：]\s*").unwrap();
        let re_a = Regex::new(r"(?im)^\s*(?:A|Answer)\s*[:：]\s*").unwrap();
        let mut q_starts: Vec<usize> = re_q.find_iter(content).map(|m| m.start()).collect();
        if q_starts.is_empty() {
            return Ok(vec![Document {
                id: doc_name.to_string(),
                content: content.to_string(),
            }]);
        }

        let text_len = content.len();
        q_starts.push(text_len);
        let mut docs = Vec::new();
        let mut idx = 0;
        for w in q_starts.windows(2) {
            let start = w[0];
            let next_q = w[1];
            let slice = &content[start..next_q];
            if let Some(_a_m) = re_a.find(slice) {
                let end: usize = next_q;
                let block = &content[start..end];
                docs.push(Document {
                    id: format!("{}-{}", doc_name, idx),
                    content: block.trim().to_string(),
                });
                idx += 1;
            } else {
                continue;
            }
        }
        Ok(docs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn get_documents() -> String {
        let document = "
        Q: What is flurbo?
        A: Definition of a *flurbo*: A flurbo is a green alien that lives on cold planets

        Question: What is glarb-glarb?
        Answer: Definition of a *glarb-glarb*: A glarb-glarb is a ancient tool used by the ancestors of the inhabitants of planet Jiro to farm the land.

        Q: What is linglingdong?
        Answer: Definition of a *linglingdong*: A term used by inhabitants of the far side of the moon to describe humans.
        ";
        document.to_string()
    }

    #[tokio::test]
    async fn test_simple_chunk() {
        let document = get_documents();
        let simple_chunk = SimpleChunk {};
        let docs = simple_chunk.chunk("simple_doc", &document).await.unwrap();
        assert_eq!(docs.len(), 3);
        println!("{:?}", docs);
    }
}
