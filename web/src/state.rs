use std::sync::Arc;

use noct_db::{ConnectionCount, EventMsg, IpProto, PacketEvent};
use prometheus::{IntCounterVec, IntGaugeVec, Opts, Registry, proto::MetricFamily};
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
/// This is the [AppState] struct wrappend in an [std::sync::Arc].
pub type SharedAppState = Arc<AppState>;

/// Initializes the application state.
pub async fn init_app_state(
    ingress_stats_rx: UnboundedReceiver<EventMsg<PacketEvent>>,
    egress_stats_rx: UnboundedReceiver<EventMsg<PacketEvent>>,
    conn_count_rx: UnboundedReceiver<EventMsg<ConnectionCount>>,
) -> anyhow::Result<AppState> {
    let registry = Registry::new();

    let in_traffic =
        init_traffic_counter("incoming_traffic_bytes", "Total amount of incoming traffic")?;
    let out_traffic =
        init_traffic_counter("outgoing_traffic_bytes", "Total amount of outgoing traffic")?;
    let active_conns =
        init_connections_gauge("active_connections", "Number of active connections")?;

    registry.register(Box::new(in_traffic.clone()))?;
    registry.register(Box::new(out_traffic.clone()))?;
    registry.register(Box::new(active_conns.clone()))?;

    tokio::spawn(read_traffic_events(ingress_stats_rx, in_traffic));
    tokio::spawn(read_traffic_events(egress_stats_rx, out_traffic));
    tokio::spawn(read_active_connections(conn_count_rx, active_conns));

    Ok(AppState { registry })
}

/// Updates the metric counters.
async fn read_traffic_events(
    mut rx: UnboundedReceiver<EventMsg<PacketEvent>>,
    counter: IntCounterVec,
) {
    while let Some(msg) = rx.recv().await {
        let protocol = msg.event.protocol.to_string();
        counter
            .with_label_values(&[&protocol])
            .inc_by(u64::from(msg.event.pkt_len));

        // Feature to be able to sync tests.
        // Basically wait till the counters are updated to perform checks.
        #[cfg(feature = "test-helpers")]
        if let Some(ack) = msg.ack {
            let _ = ack.send(());
        }
    }
}

/// Updates the active connection gauge.
async fn read_active_connections(
    mut rx: UnboundedReceiver<EventMsg<ConnectionCount>>,
    gauge: IntGaugeVec,
) {
    while let Some(msg) = rx.recv().await {
        let addr_type = msg.event.addr_type.to_string();
        gauge
            .with_label_values(&[&addr_type])
            .set(i64::from(msg.event.count));

        // Same as read_traffic_events
        #[cfg(feature = "test-helpers")]
        if let Some(ack) = msg.ack {
            let _ = ack.send(());
        }
    }
}

/// Initializes a counter for traffic bytes.
///
/// Needed so that it already starts with the protocol values on 0,
/// otherwise it'll have no protocol values until they are increased,
/// and therefore the no metric.
fn init_traffic_counter(name: &str, help: &str) -> anyhow::Result<IntCounterVec> {
    let counter =
        IntCounterVec::new(Opts::new(name, help), &["protocol"])?;

    // TODO: implement better way to iterate through enum.
    for proto in [
        IpProto::TCP.to_string(),
        IpProto::UDP.to_string(),
        IpProto::Other.to_string(),
    ] {
        counter.with_label_values(&[proto]);
    }

    Ok(counter)
}

/// Initializes a gauge for active connections.
fn init_connections_gauge(name: &str, help: &str) -> anyhow::Result<IntGaugeVec> {
    let gauge =
        IntGaugeVec::new(Opts::new(name, help), &["addressing"])?;

    for addr_type in ["IPv4", "IPv6"] {
        gauge.with_label_values(&[addr_type]);
    }

    Ok(gauge)
}
