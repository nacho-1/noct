use std::sync::Arc;

use axum::{Router, routing};
use tower_http::trace::TraceLayer;

use crate::{controllers::{health, metrics}, state::AppState};

/// Initializes the application's routes.
///
/// This function maps paths and HTTP methods to functions.
/// Also includes middleware into the routing layer (see [axum::Router]).
pub fn init_routes(app_state: AppState) -> Router {
    let shared_state = Arc::new(app_state);

    Router::new()
        .route("/health", routing::get(health::health))
        .route("/metrics", routing::get(metrics::get_metrics))
        .with_state(shared_state)
        .layer(TraceLayer::new_for_http())
}
