use axum::extract::State;
use prometheus::{Encoder, TextEncoder};

use crate::{error::WebError, state::SharedAppState};

pub async fn get_metrics(
    State(app_state): State<SharedAppState>,
) -> Result<String, WebError> {
    let encoder = TextEncoder::new();
    let mut buffer = vec![];

    let metric_families = app_state.gather_metrics();
    encoder.encode(&metric_families, &mut buffer)
        .map_err(anyhow::Error::from)?;

    let res = String::from_utf8(buffer)
        .map_err(anyhow::Error::from)
        .map_err(WebError::from)?;

    tracing::debug!("metrics response: {res}");
    Ok(res)
}
