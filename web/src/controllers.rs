use axum::http::{StatusCode, Uri};
use problemdetails::Problem;

pub mod health;
pub mod metrics;

/// Handler for requests that fail to match to any other route.
pub async fn fallback_handler(uri: Uri) -> Problem {
    problemdetails::new(StatusCode::NOT_FOUND)
        .with_type("about:blank")
        .with_title(format!("No route {uri}"))
        .with_detail(format!("Couldn't find the route {uri}"))
}
