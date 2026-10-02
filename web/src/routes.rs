use axum::{Router, routing};

use crate::controllers::health;

pub fn init_routes() -> Router {
    Router::new()
        .route("/health", routing::get(health::health))
}
