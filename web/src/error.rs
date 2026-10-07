use std::fmt::{Debug, Display};

use axum::{http::StatusCode, response::{IntoResponse, Response}};

/// Error type that encapsulates anything that can go wrong
/// in the web server. Implements [IntoResponse],
/// so that it can be returned directly from request handlers.
#[derive(thiserror::Error, Debug)]
pub enum WebError {
    /// Any other error. Handled as an Internal Server Error.
    #[error("error: {0}")]
    Other(#[from] anyhow::Error),
}

impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        match self {
            WebError::Other(e) => internal_error(e).into_response(),
        }
    }
}

/// Helper function to create an internal error response while
/// taking care to log the error itself.
fn internal_error<E>(e: E) -> StatusCode
where
    // Some "error-like" types (e.g. `anyhow::Error`) don't implement the error trait, therefore
    // we "downgrade" to simply requiring `Debug` and `Display`, the traits
    // we actually need for logging purposes.
    E: Debug + Display,
{
    tracing::error!(err.msg = %e, err.details = ?e, "Internal server error");
    // We don't want to leak internal implementation details to the client
    // via the error response, so we just return an opaque internal server.
    StatusCode::INTERNAL_SERVER_ERROR
}
