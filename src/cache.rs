use crate::resolution::Resolution;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Simple cache entry with expiry time.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub resolution: Resolution,
    pub expires_at: Instant,
    pub is_override: bool, // If true, this is a Matrix resolution that should be refetched when expired
}

/// Result of a cache lookup.
#[derive(Debug)]
pub enum CacheLookup {
    /// Valid cached entry found
    Valid(Resolution),
    /// Expired Matrix override - should refetch via Matrix resolution
    ExpiredOverride(String), // Returns the hostname that needs refetching
    /// No entry found or expired non-override
    Miss,
}

/// Simple cache for Matrix server resolutions with TTL-based expiry.
#[derive(Clone)]
pub struct Cache {
    inner: Arc<RwLock<HashMap<String, CacheEntry>>>,
    hostname_map: Arc<RwLock<HashMap<String, String>>>, // hostname -> server_name
    pub(crate) ttl: Duration,
}

impl Cache {
    pub fn new(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
            hostname_map: Arc::new(RwLock::new(HashMap::new())),
            ttl,
        }
    }

    pub fn get(&self, server_name: &str) -> Option<Resolution> {
        // First try read lock to check if entry exists and is valid
        if let cache = self.inner.read()
            && let Some(entry) = cache.get(server_name)
            && Instant::now() < entry.expires_at
        {
            return Some(entry.resolution.clone());
        }

        // If expired or not found, acquire write lock to remove expired entry
        if let mut cache = self.inner.upgradable_read()
            && let Some(entry) = cache.get(server_name)
            && Instant::now() >= entry.expires_at
        {
            cache.with_upgraded(|c| c.remove(server_name));
        }
        None
    }

    pub fn lookup(&self, hostname: &str) -> CacheLookup {
        let mut cache = self.inner.upgradable_read();
        if let Some(entry) = cache.get(hostname) {
            if Instant::now() < entry.expires_at {
                return CacheLookup::Valid(entry.resolution.clone());
            }

            let ec = entry.clone(); // Clone and then remove to prevent mutable borrow error
            cache.with_upgraded(|c| c.remove(hostname));

            return if ec.is_override {
                CacheLookup::ExpiredOverride(hostname.to_string())
            } else {
                CacheLookup::Miss
            };
        }

        // Try hostname mapping
        if let hostname_map = self.hostname_map.read()
            && let Some(server_name) = hostname_map.get(hostname)
        {
            if let Some(resolution) = self.get(server_name) {
                return CacheLookup::Valid(resolution);
            }
            // If the mapping exists but the server_name entry is expired/missing,
            // treat it as an expired override
            return CacheLookup::ExpiredOverride(server_name.to_string());
        }

        CacheLookup::Miss
    }

    pub fn set(&self, server_name: String, resolution: &Resolution) {
        let mut cache = self.inner.write();
        cache.insert(
            server_name.clone(),
            CacheEntry {
                resolution: resolution.clone(),
                expires_at: Instant::now() + self.ttl,
                is_override: true, // All Matrix resolutions are overrides
            },
        );

        // Add hostname mapping for DNS lookups
        let mut hostname_map = self.hostname_map.write();
        let sni_hostname = resolution.sni_hostname();
        if sni_hostname != server_name {
            hostname_map.insert(sni_hostname, server_name);
        }
    }

    /// Remove a single entry from the cache, returning the previously existing entry if there was one
    pub fn remove_entry(&self, server_name: &str) -> Option<CacheEntry> {
        let mut cache = self.inner.write();
        cache.remove(server_name)
    }

    /// Clear all cache entries. Returns nothing.
    pub fn clear(&self) {
        let mut cache = self.inner.write();
        cache.clear();
    }
}

#[cfg(test)]
mod tests {
    use crate::resolution::ResolvedDestination;
    use crate::server::tests::init_tracing;
    use assertables::{assert_none, assert_some};
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[tokio::test]
    async fn remove_entry() {
        init_tracing();

        // Setup code
        let cache = Cache::new(Duration::from_secs(300));

        let server1_name = "matrix.org";
        let server1_resolution = Resolution {
            destination: ResolvedDestination::Named("matrix.org".to_string(), "8448".to_string()),
            host: String::from(server1_name),
        };

        let server2_name = "example.com";
        let server2_resolution = Resolution {
            destination: ResolvedDestination::Named("example.com".to_string(), "8448".to_string()),
            host: String::from(server2_name),
        };

        cache.set(String::from(server1_name), &server1_resolution);
        cache.set(String::from(server2_name), &server2_resolution);

        // Actual test
        let server1_removed = cache.remove_entry(server1_name);
        assert_some!(&server1_removed);

        // Ensure data of removed object matches what was put in originally
        let server1_removed_unwrapped = server1_removed.unwrap();
        assert_eq!(
            server1_removed_unwrapped.resolution.host,
            server1_resolution.host
        );
        assert_eq!(
            server1_removed_unwrapped.resolution.base_url(),
            server1_resolution.base_url()
        );

        // Check that trying to access the removed cache entry gives us None
        let server1_check_actually_removed = cache.remove_entry(server1_name);
        assert_none!(server1_check_actually_removed);

        // Query server2 to ensure it still exists
        let server2_queried = cache.get(server2_name);
        assert_some!(server2_queried);
    }

    #[rstest]
    #[tokio::test]
    async fn clear_cache() {
        crate::server::tests::init_tracing();

        // Setup code
        let cache = Cache::new(Duration::from_secs(300));

        let server1_name = "matrix.org";
        let server1_resolution = Resolution {
            destination: ResolvedDestination::Named("matrix.org".to_string(), "8448".to_string()),
            host: String::from(server1_name),
        };

        let server2_name = "example.com";
        let server2_resolution = Resolution {
            destination: ResolvedDestination::Named("example.com".to_string(), "8448".to_string()),
            host: String::from(server2_name),
        };

        cache.set(String::from(server1_name), &server1_resolution);
        cache.set(String::from(server2_name), &server2_resolution);

        // Actual test
        cache.clear();

        // Query servers to ensure they are actually gone
        let server1_queried = cache.get(server1_name);
        let server2_queried = cache.get(server2_name);
        assert_none!(server1_queried);
        assert_none!(server2_queried);
    }
}
