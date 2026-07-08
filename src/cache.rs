use crate::resolution::Resolution;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tracing::trace;

/// Simple cache entry with expiry time.
#[derive(Clone, Debug)]
pub struct CacheEntry {
    pub resolution: Resolution,
    pub expires_at: SystemTime,
    pub is_override: bool,
}

/// Result of a cache lookup.
#[derive(Debug, PartialEq)]
pub enum CacheLookup {
    /// Valid cached entry found
    Valid(Resolution),
    /// Expired Matrix override - should refetch via Matrix resolution
    ExpiredOverride(String), // Returns the hostname that needs refetching
    /// No entry found or expired non-override
    Miss,
}

/// Simple cache for Matrix server resolutions with TTL-based expiry.
#[derive(Clone, Debug)]
pub struct Cache {
    pub(crate) inner: Arc<RwLock<HashMap<String, CacheEntry>>>,
    pub(crate) hostname_map: Arc<RwLock<HashMap<String, String>>>, // hostname -> server_name
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

    /// Get a cache resolution entry if it exists and is valid, otherwise remove possibly expired entry
    /// and return None
    pub fn get(&self, server_name: &str) -> Option<Resolution> {
        // First try read lock to check if entry exists and is valid
        if let cache = self.inner.read()
            && let Some(entry) = cache.get(server_name)
            && SystemTime::now() < entry.expires_at
        {
            return Some(entry.resolution.clone());
        }

        // If expired or not found, acquire write lock to remove expired entry
        if let mut cache = self.inner.upgradable_read()
            && let Some(entry) = cache.get(server_name)
            && SystemTime::now() >= entry.expires_at
        {
            cache.with_upgraded(|c| c.remove(server_name));
            {
                // Remove hostname mapping along with cache entry
                let mut hostname_map = self.hostname_map.write();
                hostname_map.remove(server_name);
            };
        }
        None
    }

    /// Lookup a cache entry, and attempt to use hostname mapping if it cannot be found by the provided
    /// name.
    pub fn lookup(&self, hostname: &str) -> CacheLookup {
        let mut cache = self.inner.upgradable_read();
        if let Some(entry) = cache.get(hostname) {
            if SystemTime::now() < entry.expires_at {
                return CacheLookup::Valid(entry.resolution.clone());
            }

            let is_override = entry.is_override;
            cache.with_upgraded(|c| c.remove(hostname));

            return if is_override {
                CacheLookup::ExpiredOverride(hostname.to_string())
            } else {
                CacheLookup::Miss
            };
        }

        // Try hostname mapping
        let mapped_server_name = {
            let hostname_map = self.hostname_map.read();
            hostname_map.get(hostname).cloned()
        };

        if let Some(server_name) = mapped_server_name
            && let Some(resolution) = self.get(&server_name)
        {
            return CacheLookup::Valid(resolution);
        }

        CacheLookup::Miss
    }

    /// Set a new resolution entry, saving the hostname map if the SNI hostname and server name do
    /// not match
    pub fn set(&self, server_name: String, resolution: &Resolution) {
        let sni_hostname = resolution.sni_hostname();
        let is_override = resolution.is_override;

        {
            let mut cache = self.inner.write();
            cache.insert(
                server_name.clone(),
                CacheEntry {
                    resolution: resolution.clone(),
                    expires_at: SystemTime::now() + self.ttl,
                    is_override,
                },
            );
        }
        trace!(%server_name, %sni_hostname, resolution = %resolution.destination.hostname(), ?is_override, "setting entry ");

        debug_assert!(is_override || (sni_hostname == resolution.destination.hostname()));

        // Add hostname mapping for DNS lookups
        let mut hostname_map = self.hostname_map.write();
        if sni_hostname != server_name {
            hostname_map.insert(sni_hostname, server_name);
        }
    }

    /// Remove a single entry from the cache, returning the previously existing entry if there was one
    pub fn remove_entry(&self, server_name: &str) -> Option<CacheEntry> {
        let removed = {
            let mut cache = self.inner.write();
            cache.remove(server_name)
        };

        if removed.is_some() {
            let mut hostname_map = self.hostname_map.write();
            hostname_map.retain(|_, mapped_server_name| mapped_server_name != server_name);
        }

        removed
    }

    /// Clear all cache entries. Returns nothing.
    pub fn clear(&self) {
        {
            let mut cache = self.inner.write();
            cache.clear();
        }

        let mut hostname_map = self.hostname_map.write();
        hostname_map.clear();
    }

    /// Return a Vec of every current cache entry
    pub fn get_all(&self) -> Vec<(String, CacheEntry)> {
        self.inner.read().clone().into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use crate::resolution::{ResolutionStep, ResolvedDestination};
    use crate::server::tests::init_tracing;
    use assertables::{assert_none, assert_some};
    use rstest::rstest;

    use super::*;

    #[rstest]
    fn test_set_item() {
        init_tracing();

        let cache = Cache::new(Duration::from_secs(300));

        let server_name = "matrix.org";
        let resolved_hostname = "matrix-federation.matrix.org";
        let port = "448";

        let resolution = Resolution {
            destination: ResolvedDestination::Named(
                resolved_hostname.to_string(),
                port.to_string(),
            ),
            host: format!("{resolved_hostname}:{port}"),
            is_override: false,
            resolution_step: ResolutionStep::WellKnownHostPort,
        };

        cache.set(server_name.to_string(), &resolution);
        dbg!(&cache);

        assert_eq!(dbg!(cache.inner.read().values().count()), 1);
        assert_eq!(dbg!(cache.hostname_map.read().values().count()), 1);

        let cache_get = dbg!(cache.get(server_name));
        let hostname_read = cache.hostname_map.read();
        let hostname_get = dbg!(hostname_read.get(resolved_hostname));

        assert_some!(&cache_get);
        assert_some!(&hostname_get);

        assert_eq!(cache_get.unwrap(), resolution);
        assert_eq!(hostname_get.unwrap(), server_name);
    }

    #[rstest]
    fn test_lookup() {
        init_tracing();

        let cache = Cache::new(Duration::from_secs(1));

        let server_name = "matrix.org";
        let resolution = Resolution {
            destination: ResolvedDestination::Named(
                "matrix-federation.matrix.org".to_string(),
                "8448".to_string(),
            ),
            host: "matrix-federation.matrix.org".to_string(),
            is_override: true,
            resolution_step: ResolutionStep::WellKnownHostPort,
        };

        assert_eq!(cache.lookup("doesn't exist"), CacheLookup::Miss);

        cache.set(server_name.to_string(), &resolution);
        assert_eq!(
            dbg!(cache.lookup(server_name)),
            CacheLookup::Valid(resolution.clone())
        );

        std::thread::sleep(Duration::from_secs(2));
        assert_eq!(
            dbg!(cache.lookup(server_name)),
            CacheLookup::ExpiredOverride(server_name.to_string())
        );
    }

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
            is_override: false,
            resolution_step: ResolutionStep::HostPort,
        };

        let server2_name = "example.com";
        let server2_resolution = Resolution {
            destination: ResolvedDestination::Named("example.com".to_string(), "8448".to_string()),
            host: String::from(server2_name),
            is_override: false,
            resolution_step: ResolutionStep::HostPort,
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
        init_tracing();

        // Setup code
        let cache = Cache::new(Duration::from_secs(300));

        let server1_name = "matrix.org";
        let server1_resolution = Resolution {
            destination: ResolvedDestination::Named("matrix.org".to_string(), "8448".to_string()),
            host: String::from(server1_name),
            is_override: false,
            resolution_step: ResolutionStep::HostPort,
        };

        let server2_name = "example.com";
        let server2_resolution = Resolution {
            destination: ResolvedDestination::Named("example.com".to_string(), "8448".to_string()),
            host: String::from(server2_name),
            is_override: false,
            resolution_step: ResolutionStep::HostPort,
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

    #[rstest]
    #[tokio::test]
    async fn expired_lookup_returns_override() {
        init_tracing();

        let cache = Cache::new(Duration::from_secs(0));

        let server_name = "example.com";
        let resolution = Resolution {
            destination: ResolvedDestination::Named(
                "example-federation.example.com".to_string(),
                "8448".to_string(),
            ),
            host: String::from("example-federation.example.com"),
            is_override: true,
            resolution_step: ResolutionStep::SrvMatrix,
        };

        cache.set(String::from(server_name), &resolution);

        match cache.lookup(server_name) {
            CacheLookup::ExpiredOverride(expired_name) => {
                assert_eq!(expired_name, server_name);
            }
            other => panic!("expected ExpiredOverride, got {other:?}"),
        }
    }

    #[rstest]
    #[tokio::test]
    async fn expired_lookup_without_override_is_miss() {
        init_tracing();

        let cache = Cache::new(Duration::from_secs(0));

        let server_name = "matrix.org";
        let resolution = Resolution {
            destination: ResolvedDestination::Named("matrix.org".to_string(), "8448".to_string()),
            host: String::from(server_name),
            is_override: false,
            resolution_step: ResolutionStep::HostPort,
        };

        cache.set(String::from(server_name), &resolution);

        match cache.lookup(server_name) {
            CacheLookup::Miss => {}
            other => panic!("expected Miss, got {other:?}"),
        }
    }

    #[rstest]
    #[tokio::test]
    async fn remove_entry_clears_hostname_mapping() {
        init_tracing();

        let cache = Cache::new(Duration::from_secs(300));

        let server_name = "matrix.org";
        let resolution = Resolution {
            destination: ResolvedDestination::Named(
                "matrix.example.org".to_string(),
                "8448".to_string(),
            ),
            host: String::from("matrix.example.org"),
            is_override: true,
            resolution_step: ResolutionStep::HostPort,
        };

        cache.set(String::from(server_name), &resolution);

        assert!(matches!(
            cache.lookup("matrix.example.org"),
            CacheLookup::Valid(_)
        ));

        let removed = cache.remove_entry(server_name);
        assert_some!(removed);

        assert!(matches!(
            cache.lookup("matrix.example.org"),
            CacheLookup::Miss
        ));
    }

    #[rstest]
    #[tokio::test]
    async fn test_get_all() {
        // Setup code
        let cache = Cache::new(Duration::from_secs(300));

        let server1_name = "matrix.org";
        let server1_resolution = Resolution {
            destination: ResolvedDestination::Named("matrix.org".to_string(), "8448".to_string()),
            host: String::from(server1_name),
            is_override: false,
            resolution_step: ResolutionStep::HostPort,
        };

        let server2_name = "example.com";
        let server2_resolution = Resolution {
            destination: ResolvedDestination::Named("example.com".to_string(), "8448".to_string()),
            host: String::from(server2_name),
            is_override: false,
            resolution_step: ResolutionStep::HostPort,
        };

        cache.set(String::from(server1_name), &server1_resolution);
        cache.set(String::from(server2_name), &server2_resolution);

        // Actual test
        let servers = dbg!(cache.get_all());
        assert_eq!(servers.len(), 2);
    }

    #[rstest]
    fn get_expired() {
        init_tracing();

        let cache = Cache::new(Duration::from_secs(0));

        let server_name = "matrix.org";
        let resolution = Resolution {
            destination: ResolvedDestination::Named(
                "matrix-federation.matrix.org".to_string(),
                "8448".to_string(),
            ),
            host: "matrix-federation.matrix.org".to_string(),
            is_override: true,
            resolution_step: ResolutionStep::WellKnownHostPort,
        };

        cache.set(server_name.to_string(), &resolution);
        std::thread::sleep(Duration::from_secs(1));

        assert_none!(cache.get(server_name));
    }

    #[rstest]
    fn lookup_not_found() {
        init_tracing();

        let cache = Cache::new(Duration::from_secs(0));

        let server_name = "matrix.org";
        let resolution = Resolution {
            destination: ResolvedDestination::Named(
                "matrix-federation.matrix.org".to_string(),
                "8448".to_string(),
            ),
            host: "matrix-federation.matrix.org".to_string(),
            is_override: true,
            resolution_step: ResolutionStep::WellKnownHostPort,
        };

        cache.set(server_name.to_string(), &resolution);
        std::thread::sleep(Duration::from_secs(1));

        // First lookup deletes the cache but leaves the hostname mapping
        cache.get(server_name);

        cache.lookup(server_name);
    }
}
