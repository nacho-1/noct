use std::sync::Arc;

use noct_db::PacketEvent;
use prometheus::{IntCounterVec, Opts, Registry, proto::MetricFamily};
use tokio::sync::mpsc::UnboundedReceiver;

/// The application's state that is available in [crate::controllers].
pub struct AppState {
    registry: Registry,
}

impl AppState {
    /// Gathers the collected metrics.
    pub fn gather_metrics(&self) -> Vec<MetricFamily> {
        self.registry.gather()
    }
}

/// The application's state as it is shared across the application,
/// e.g. in controllers and middlewares.
///
/// This is the [`AppState`] struct wrappend in an [`std::sync::Arc`].
pub type SharedAppState = Arc<AppState>;

/// Initializes the application state.
pub async fn init_app_state(
    ingress_stats_rx: UnboundedReceiver<PacketEvent>,
    egress_stats_rx: UnboundedReceiver<PacketEvent>,
) -> anyhow::Result<AppState> {
    let registry = Registry::new();

    let in_traffic = IntCounterVec::new(
        Opts::new(
            "incoming_traffic_bytes",
            "Total amount of incoming traffic"
        ),
        &["protocol"],
    )?;

    let out_traffic = IntCounterVec::new(
        Opts::new(
            "outgoing_traffic_bytes",
            "Total amount of outgoing traffic"
        ),
        &["protocol"],
    )?;

    registry.register(Box::new(in_traffic.clone()))?;
    registry.register(Box::new(out_traffic.clone()))?;

    tokio::spawn(read_traffic_events(ingress_stats_rx, in_traffic));
    tokio::spawn(read_traffic_events(egress_stats_rx, out_traffic));

    Ok(
        AppState {
            registry,
        }
    )

}

/// Updates the metric counters.
async fn read_traffic_events(
    mut rx: UnboundedReceiver<PacketEvent>,
    counter: IntCounterVec,
) {
    while let Some(event) = rx.recv().await {
        let protocol = event.protocol.to_string();
        counter
            .with_label_values(&[&protocol])
            .inc_by(u64::from(event.pkt_len));
    }
}
