use thiserror::Error;

/// Error type for Matrix server resolution.
#[derive(Debug, Error)]
pub enum ResolveServerError {
    #[error("Failed to parse address: {0}")]
    AddrParse(#[from] std::net::AddrParseError),

    #[error("HTTP client error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("DNS resolution error: {0}")]
    Dns(#[from] hickory_resolver::ResolveError),

    #[error("Invalid port number: {0}")]
    InvalidPort(#[from] std::num::ParseIntError),

    #[error("Unexpected error: {0}")]
    Other(String),
}
