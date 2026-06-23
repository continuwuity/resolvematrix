use resolvematrix::server::MatrixResolverBuilder;
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Optionally initialize tracing to see internal library logs.
    // tracing_subscriber::fmt::init();

    // Create a new resolver with a custom TTL for cache entries
    let resolver = MatrixResolverBuilder::new()
        .cache_ttl(Duration::from_secs(1500))
        .build()?;

    match resolver.resolve_server("matrix.org").await {
        Ok(resolution) => {
            println!("Base URL: {}", resolution.base_url());
            println!("Host SNI: {}", resolution.host);
            println!("Destination: {:?}", resolution.destination);
        }
        Err(e) => {
            println!("Failed: {e:?}");
        }
    }

    Ok(())
}
