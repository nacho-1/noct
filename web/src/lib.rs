use noct_config::ServerConfig;
use tokio::{net::TcpListener, sync::broadcast};

/// The application's controllers that implement request handlers.
pub mod controllers;
/// Contains the application's route definitions.
pub mod routes;

pub async fn run(
    config: ServerConfig,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let app = routes::init_routes();

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

