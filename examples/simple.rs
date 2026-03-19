use resolvematrix::server::MatrixResolver;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Optionally initialize tracing to see internal library logs.
    // tracing_subscriber::fmt::init();

    // Create a new resolver with default configuration
    let resolver = MatrixResolver::new().await?;

    // List of matrix servers to try resolving to demonstrate different discovery paths
    let servers = vec![
        "matrix.org",     // Usually uses .well-known delegation
        "127.0.0.1",      // IP literal
        "timedout.uk:69", // Explicit port
        "maunium.net",    // SRV
    ];

    for server_name in servers {
        println!("Server: {server_name}");

        match resolver.resolve_server(server_name).await {
            Ok(resolution) => {
                println!("Base URL: {}", resolution.base_url());
                println!("Host SNI: {}", resolution.host);
                println!("Destination: {:?}", resolution.destination);
            }
            Err(e) => {
                println!("Failed: {e:?}");
            }
        }
        println!();
    }

    Ok(())
}
