use hickory_resolver::TokioResolver;
use std::net::{IpAddr, SocketAddr};

/// Result of a Matrix server resolution.
///
/// Contains the resolved destination (IP/Port or Hostname/Port) and the
/// hostname to use for SNI/Host headers.
#[derive(Debug, Clone)]
pub struct Resolution {
    /// The actual destination to connect to.
    pub destination: ResolvedDestination,
    /// The hostname to use for TLS SNI and HTTP Host header. May contain a port if the target
    /// has one (e.g. from looking up the resolution for `example.com:9090`).
    pub host: String,
}

impl Resolution {
    /// Get the base URL for making requests to this resolution.
    /// Uses the host field for proper SNI.
    #[must_use]
    pub fn base_url(&self) -> String {
        match &self.destination {
            ResolvedDestination::Literal(addr) => format!("https://{addr}"),
            ResolvedDestination::Named(_dest_host, dest_port) => {
                let port: u16 = dest_port.parse().unwrap_or(8448);
                if self.host.contains(':') {
                    format!("https://{}", self.host)
                } else {
                    format!("https://{}:{}", self.host, port)
                }
            }
        }
    }

    /// Get the hostname (without port) from the host field for DNS mapping.
    pub(crate) fn sni_hostname(&self) -> String {
        if let Some(colon_pos) = self.host.find(':') {
            self.host[..colon_pos].to_string()
        } else {
            self.host.clone()
        }
    }

    /// Get the destination address for DNS resolution mapping.
    pub(crate) async fn destination_addr(&self, resolver: &TokioResolver) -> Option<SocketAddr> {
        match &self.destination {
            ResolvedDestination::Literal(addr) => Some(*addr),
            ResolvedDestination::Named(dest_host, dest_port) => {
                let port: u16 = dest_port.parse().ok()?;

                // Try to parse as IP first
                if let Ok(ip) = dest_host.parse::<IpAddr>() {
                    return Some(SocketAddr::new(ip, port));
                }

                // Resolve via DNS
                match resolver.lookup_ip(dest_host.as_str()).await {
                    Ok(lookup) => {
                        let ip = lookup.iter().next()?;
                        Some(SocketAddr::new(ip, port))
                    }
                    Err(_) => None,
                }
            }
        }
    }
}

/// Represents the resolved destination for a Matrix server.
#[derive(Debug, Clone)]
pub enum ResolvedDestination {
    /// A literal IP address and port (e.g., 1.2.3.4:8448)
    Literal(SocketAddr),
    /// A named host and port (e.g., "matrix.org", "8448")
    Named(String, String),
}

impl ResolvedDestination {
    /// Get the destination hostname
    pub fn hostname(&self) -> String {
        match &self {
            ResolvedDestination::Literal(addr) => addr.ip().to_string(),
            ResolvedDestination::Named(dest_host, _dest_port) => dest_host.clone(),
        }
    }

    /// Get the destination port
    pub fn port(&self) -> u16 {
        match &self {
            ResolvedDestination::Literal(addr) => addr.port(),
            ResolvedDestination::Named(_dest_host, dest_port) => {
                dest_port.parse::<u16>().unwrap_or(8448)
            }
        }
    }

    /// Return the host:port formatted string of the resolved destination server (not SNI host)
    pub fn host_port(&self) -> String {
        match &self {
            ResolvedDestination::Literal(addr) => addr.to_string(),
            ResolvedDestination::Named(host, port) => format!("{host}:{port}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[tokio::test]
    async fn test_resolution() {
        let resolver = hickory_resolver::Resolver::builder_tokio().unwrap().build();
        let socketaddr = SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 8448);

        let literal_ip = Resolution {
            destination: ResolvedDestination::Literal(socketaddr),
            host: "127.0.0.1".to_string(),
        };
        assert_eq!(
            literal_ip.destination_addr(&resolver).await,
            Some(socketaddr)
        );
        assert_eq!(literal_ip.base_url(), "https://127.0.0.1:8448");
        assert_eq!(literal_ip.sni_hostname(), "127.0.0.1");

        let named_ip = Resolution {
            destination: ResolvedDestination::Named(
                socketaddr.ip().to_string(),
                socketaddr.port().to_string(),
            ),
            host: "127.0.0.1".to_string(),
        };
        assert_eq!(named_ip.destination_addr(&resolver).await, Some(socketaddr));
        assert_eq!(named_ip.base_url(), "https://127.0.0.1:8448");
        assert_eq!(named_ip.sni_hostname(), "127.0.0.1");

        let named_with_port_in_host = Resolution {
            destination: ResolvedDestination::Named("example.com".to_string(), "9090".to_string()),
            host: "example.com:9090".to_string(),
        };
        assert_eq!(
            named_with_port_in_host.base_url(),
            "https://example.com:9090"
        );
        assert_eq!(named_with_port_in_host.sni_hostname(), "example.com");

        let invalid_dns_address = Resolution {
            destination: ResolvedDestination::Named(
                "testdomain.invalid".to_string(),
                "9090".to_string(),
            ),
            host: "testdomain.invalid:9090".to_string(),
        };
        assert_eq!(invalid_dns_address.destination_addr(&resolver).await, None);
    }

    #[rstest]
    fn test_resolved_destination() {
        let literal =
            ResolvedDestination::Literal(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 8448));
        assert_eq!(literal.hostname(), "127.0.0.1");
        assert_eq!(literal.port(), 8448);
        assert_eq!(literal.host_port(), "127.0.0.1:8448");

        let named = ResolvedDestination::Named("example.com".to_string(), "8448".to_string());
        assert_eq!(named.hostname(), "example.com");
        assert_eq!(named.port(), 8448);
        assert_eq!(named.host_port(), "example.com:8448");
    }
}
