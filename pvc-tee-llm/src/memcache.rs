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

use super::cache::{Cache, CacheValue};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use dashmap::DashMap;
use std::ops::Deref;
use std::sync::Arc;
use tokio::time::Duration;

/// Memory-based cache implementation using DashMap for concurrent access
#[derive(Debug, Clone)]
pub struct MemBasedCache {
    inner: Arc<DashMap<String, CacheValue>>,
}

impl MemBasedCache {
    /// Creates a new cache with a background cleanup task
    ///
    /// # Arguments
    /// * `cleanup_interval` - How often to run the cleanup task
    pub fn init_with_cleanup(cleanup_interval: Duration) -> Self {
        let cache = Self {
            inner: Arc::new(DashMap::new()),
        };

        // Spawn background cleanup task
        let cache_clone = cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);
            loop {
                interval.tick().await;
                cache_clone.cleanup_expired();
            }
        });

        cache
    }

    /// Creates a new cache without automatic cleanup
    pub fn new() -> Self {
        Self {
            inner: Arc::new(DashMap::new()),
        }
    }

    fn cleanup_expired(&self) {
        let now = Utc::now();
        self.inner
            .retain(|_, value| !Self::is_expired(value.last_active(), &now));
    }

    /// Checks if a cache entry has expired based on its last active timestamp
    fn is_expired(last_active: &DateTime<Utc>, now: &DateTime<Utc>) -> bool {
        (*now - *last_active) >= ChronoDuration::minutes(30)
    }
}

impl Default for MemBasedCache {
    fn default() -> Self {
        Self::new()
    }
}

impl Cache for MemBasedCache {
    fn get(&self, key: &str) -> Option<Box<dyn Deref<Target = CacheValue> + '_>> {
        let entry = self.inner.get(key)?;
        let now = Utc::now();

        if Self::is_expired(entry.last_active(), &now) {
            // Remove expired entry
            drop(entry); // Release the read lock before removing
            self.inner.remove(key);
            None
        } else {
            Some(Box::new(entry))
        }
    }

    fn add(&self, key: &str, mut entry: CacheValue) {
        entry.last_active = Utc::now();
        self.inner.insert(key.to_string(), entry);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_value_iteration() {
        let mut cache_value = CacheValue::new();
        cache_value.add_turn("Hello".to_string(), "Hi there!".to_string());
        cache_value.add_turn("How are you?".to_string(), "I'm good!".to_string());

        // Test borrowed iteration
        let mut iter = cache_value.iter();
        assert_eq!(iter.next(), Some(("Hello", "Hi there!")));
        assert_eq!(iter.next(), Some(("How are you?", "I'm good!")));
        assert_eq!(iter.next(), None);

        // Test for loop with borrowed iteration
        let mut count = 0;
        for (user, assistant) in &cache_value {
            assert!(!user.is_empty());
            assert!(!assistant.is_empty());
            count += 1;
        }
        assert_eq!(count, 2);

        // Test owned iteration
        let owned_iter = cache_value.clone().into_iter();
        assert_eq!(owned_iter.len(), 2);

        // Test utility methods
        assert_eq!(cache_value.len(), 2);
        assert!(!cache_value.is_empty());
        assert_eq!(cache_value.first(), Some(("Hello", "Hi there!")));
        assert_eq!(cache_value.last(), Some(("How are you?", "I'm good!")));
        assert_eq!(cache_value.get(1), Some(("How are you?", "I'm good!")));
        assert_eq!(cache_value.get(5), None);
    }
}
