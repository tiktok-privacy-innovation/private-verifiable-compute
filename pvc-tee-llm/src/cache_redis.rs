// Copyright 2025 Tiktok Inc. and/or its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use redis::{Client, Commands, Connection, RedisError};
use std::sync::{Arc, Mutex};

use super::cache::Cache;

pub struct RedisCache {
    connection: Arc<Mutex<Connection>>,
    ttl_seconds: i64,
}

impl RedisCache {
    /// Creates a new RedisCache instance
    pub fn new(redis_url: &str, ttl_seconds: i64) -> Result<Self, RedisError> {
        let client = Client::open(redis_url)?;
        let connection = client.get_connection()?;

        Ok(RedisCache {
            connection: Arc::new(Mutex::new(connection)),
            ttl_seconds,
        })
    }
}

impl Cache for RedisCache {
    fn lrange(&self, key: &str) -> Option<Vec<String>> {
        let mut conn = self.connection.lock().unwrap();

        match conn.lrange::<&str, Vec<String>>(key, 0, -1) {
            Ok(result) => Some(result),
            Err(e) => {
                eprintln!("Redis lrange error for key {}: {:?}", key, e);
                None
            }
        }
    }

    fn rpush(&self, key: &str, value: &str) {
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .rpush(key, value)
            .ignore()
            .expire(key, self.ttl_seconds)
            .ignore();

        let mut conn = self.connection.lock().unwrap();
        if let Err(e) = pipeline.query::<Vec<()>>(&mut *conn) {
            eprintln!("Redis rpush_with_ttl error for key {}: {:?}", key, e);
        }
    }

    fn llen(&self, key: &str) -> usize {
        let mut conn = self.connection.lock().unwrap();

        match conn.llen::<&str, usize>(key) {
            Ok(len) => len,
            Err(e) => {
                eprintln!("Redis llen error for key {}: {:?}", key, e);
                0
            }
        }
    }

    fn clear(&self) {
        let mut conn = self.connection.lock().unwrap();

        // Clear all keys in the current database
        if let Err(e) = redis::cmd("FLUSHDB").query::<()>(&mut *conn) {
            eprintln!("Redis clear error: {:?}", e);
        }
    }

    fn reset_key(&self, key: &str, value: &str) {
        let mut pipeline = redis::pipe();
        pipeline
            .atomic()
            .del(key)
            .ignore()
            .rpush(key, value)
            .ignore()
            .expire(key, self.ttl_seconds)
            .ignore();

        let mut conn = self.connection.lock().unwrap();
        if let Err(e) = pipeline.query::<Vec<()>>(&mut *conn) {
            eprintln!("Redis reset_key error for key {}: {:?}", key, e);
        }
    }
}
