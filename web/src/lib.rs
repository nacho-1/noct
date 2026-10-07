use noct_config::ServerConfig;
use noct_db::PacketEvent;
use tokio::{net::TcpListener, sync::{broadcast, mpsc::UnboundedReceiver}};

/// The application's controllers that implement request handlers.
pub mod controllers;
/// Contains the web server error type.
pub mod error;
/// Contains the application's route definitions.
pub mod routes;
/// Contains the application's state definitions and functionality.
pub mod state;

/// Runs the web server.
///
/// This function does all the work to initialize and run the web server:
///
/// 1. Initialize the application's state (see [state::init_app_state]).
/// 2. Initialize the application's routes (see [routes::init_routes]).
/// 3. Start listening for requests on the configured interface and port.
pub async fn run(
    config: ServerConfig,
    ingress_stats_rx: UnboundedReceiver<PacketEvent>,
    egress_stats_rx: UnboundedReceiver<PacketEvent>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let app_state = state::init_app_state(ingress_stats_rx, egress_stats_rx).await?;
    let app = routes::init_routes(app_state);

    let addr = config.addr();
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("server listening on {}", &addr);

    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(async move {
            if let Err(e) = shutdown.recv().await {
                tracing::error!("server shutdown signal failed: {e}");
            }
            tracing::info!("shutting down server");
        })
        .await?;

    Ok(())
}

/// Helpers that simplify writing server tests.
#[cfg(feature = "web-test")]
pub mod test_helpers;
