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

use dashmap::DashMap;
use std::fmt::Debug;
use std::sync::Arc;

/// Trait defining cache operations for session management
#[allow(dead_code)]
pub trait Cache: Send + Sync + 'static {
    /// Retrieves a cached value if it exists
    fn lrange(&self, key: &str) -> Option<Vec<String>>;

    /// Inserts or updates a value in the cache
    fn rpush(&self, key: &str, value: &str);

    /// Return list length
    fn llen(&self, key: &str) -> usize;

    /// del key and set a new value
    fn reset_key(&self, key: &str, value: &str);

    /// Clear all keys in the cache
    fn clear(&self);
}

/// Memory-based cache implementation using DashMap for concurrent access
#[derive(Debug, Clone)]
pub struct MemBasedCache {
    inner: Arc<DashMap<String, Vec<String>>>,
}

impl MemBasedCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }
}

impl Cache for MemBasedCache {
    fn lrange(&self, key: &str) -> Option<Vec<String>> {
        let read_view = self.inner.get(key)?;
        Some((*read_view).clone())
    }

    fn llen(&self, key: &str) -> usize {
        self.inner.get(key).map_or(0, |v| v.len())
    }

    fn rpush(&self, key: &str, value: &str) {
        let mut entry = self.inner.entry(key.to_string()).or_default();

        entry.push(value.to_string());
    }

    fn clear(&self) {
        self.inner.clear();
    }

    fn reset_key(&self, key: &str, value: &str) {
        let mut entry = self.inner.entry(key.to_string()).or_default();
        entry.clear();
        entry.push(value.to_string());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mem_based_cache() {
        let cache = MemBasedCache::new();

        cache.rpush("session_123", "user_id_456");
        cache.rpush("session_123", "token_789");

        assert_eq!(cache.llen("session_123"), 2);
        let values = cache.lrange("session_123").unwrap();
        assert!(values.contains(&"user_id_456".to_string()));
        assert!(values.contains(&"token_789".to_string()));

        assert!(cache.lrange("non_exist_key").is_none());
        cache.clear();
        assert_eq!(cache.llen("session_123"), 0);
    }

    #[test]
    fn test_concurrent_access() {
        use std::thread;

        let cache = MemBasedCache::new();
        let cache_clone = Arc::new(cache);

        let mut handles = Vec::new();
        for i in 0..4 {
            let cache = Arc::clone(&cache_clone);
            handles.push(thread::spawn(move || {
                cache.rpush("concurrent_key", &format!("value_{}", i));
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let values = cache_clone.lrange("concurrent_key").unwrap();
        assert_eq!(values.len(), 4);
        assert!(values.contains(&"value_0".to_string()));
        assert!(values.contains(&"value_1".to_string()));
        assert!(values.contains(&"value_2".to_string()));
        assert!(values.contains(&"value_3".to_string()));
    }
}
