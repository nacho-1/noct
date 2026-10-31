use anyhow::Context;
use aya::{Ebpf, maps::{Array, PerfEventArray}};
use futures::{StreamExt, stream::FuturesUnordered};
use noct_config::Config;
use tokio::{
    signal::{self, unix::SignalKind}, sync::{broadcast, mpsc}, task::JoinHandle,
};
use tracing_panic::panic_hook;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Helpers for managing eBPF logic.
mod ebpf_helpers;

pub use ebpf_helpers::{read_event_array, watch_conn_count};

/// Initializes tracing.
///
/// This function
///
/// * registers a [`tracing_subscriber::fmt::Subscriber`]
/// * registers a [`tracing_panic::panic_hook`]
///
/// The function respects the `RUST_LOG` if set,
/// or defaults to filtering spans and events with level
/// [`tracing_subscriber::filter::LevelFilter::INFO`] or higher.
/// Handles [`log`] crate logging as well.
pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new("info"))
        .unwrap();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(filter)
        .init();

    std::panic::set_hook(Box::new(panic_hook));
}

/// Runs the application.
///
/// This function does all the work to initialize and run the application:
///
/// 1. Load the eBPF programs into kernel.
/// 2. Spawn the different tasks of the application.
/// 3. Wait for shutdown signal.
/// 4. Perform final cleanup.
pub async fn run() -> anyhow::Result<()> {
    let env = noct_config::get_env().context("cannot get environment")?;
    let config: Config = noct_config::load_config(&env).context("cannot load config")?;

    // This will include the eBPF object file as raw bytes at compile-time
    // and load it at runtime.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    // Get the maps for communication with kernel.
    let ingress_stats_map = PerfEventArray::try_from(ebpf.take_map("RX_STATS").unwrap())?;
    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let srtt_updates_map = PerfEventArray::try_from(ebpf.take_map("SRTT_UPDATES").unwrap())?;
    let retransmissions_map = PerfEventArray::try_from(ebpf.take_map("RETRANSMISSIONS").unwrap())?;
    let conn_counter: Array<_, u32> = Array::try_from(ebpf.take_map("CONN_COUNT").unwrap())?;

    // Load the eBPF programs into the kernel at this point.
    ebpf_helpers::init_ebpf(&mut ebpf, config.cgroup_path)?;

    // Channel used for graceful shutdown of the different tasks of the application.
    let (shutdown_tx, _) = broadcast::channel(1);

    // Vector for all the tasks of the application.
    // Later used for cleanup on close.
    let mut tasks = FuturesUnordered::new();

    // Start spawning the different tasks of the application.

    match ebpf_helpers::init_ebpf_logger(&mut ebpf, shutdown_tx.subscribe()) {
        Ok(handle) => {
            tasks.push(join_task(handle, "eBPF logger"));
        }
        Err(e) => {
            tracing::warn!("failed to initialize eBPF logger: {e}");
        }
    };

    // Spawn the different eBPF event consumers.
    // They read the data sent by the eBPF programs an output it as data to be used
    // in userspace.
    let (ingress_stats_tx, ingress_stats_rx) = mpsc::unbounded_channel();
    let (egress_stats_tx, egress_stats_rx) = mpsc::unbounded_channel();
    let (srtt_updates_tx, mut srtt_updates_rx) = mpsc::unbounded_channel();
    let (retrans_tx, mut retrans_rx) = mpsc::unbounded_channel();
    let (conn_count_tx, conn_count_rx) = mpsc::unbounded_channel();
    tasks.extend(
        read_event_array::<noct_common::PacketEvent, noct_db::PacketEvent>(
            ingress_stats_map,
            ingress_stats_tx,
            shutdown_tx.subscribe(),
        )?
            .into_iter()
            .map(|handle| join_task(handle, "ingress traffic reader"))
    );
    tasks.extend(
        read_event_array::<noct_common::PacketEvent, noct_db::PacketEvent>(
            egress_stats_map,
            egress_stats_tx,
            shutdown_tx.subscribe(),
        )?
            .into_iter()
            .map(|handle| join_task(handle, "egress traffic reader"))
    );
    tasks.extend(
        read_event_array::<noct_common::ConnectionSRTT, noct_db::ConnectionSRTT>(
            srtt_updates_map,
            srtt_updates_tx,
            shutdown_tx.subscribe(),
        )?
            .into_iter()
            .map(|handle| join_task(handle, "srtt reader"))
    );
    tasks.extend(
        read_event_array::<noct_common::ConnectionRetrans, noct_db::ConnectionRetrans>(
            retransmissions_map,
            retrans_tx,
            shutdown_tx.subscribe(),
        )?
            .into_iter()
            .map(|handle| join_task(handle, "retransmissions reader"))
    );
    tasks.push(join_task(
        tokio::spawn(
            watch_conn_count(conn_counter, conn_count_tx, shutdown_tx.subscribe())
        ),
        "connection count watcher"
    ));
    tasks.push(join_task(
        tokio::spawn(noct_web::run(
            config.server,
            ingress_stats_rx,
            egress_stats_rx,
            conn_count_rx,
            shutdown_tx.subscribe(),
        )),
        "web server"
    ));
    tokio::spawn(async move {
        while let Some(msg) = srtt_updates_rx.recv().await {
            tracing::debug!("srtt update: {:?}", msg.event);
        }
    });
    tokio::spawn(async move {
        while let Some(msg) = retrans_rx.recv().await {
            tracing::debug!("retransmission: {:?}", msg.event);
        }
    });

    // Wait for application shutdown.
    shutdown_handler(shutdown_tx).await;

    // Await all tasks.
    while tasks.next().await.is_some() {}

    tracing::info!("shutdown successful");
    Ok(())
}

/// Handles shutdown of the application. Sends a shutdown broadcast.
///
/// Will await for either a Ctrl-C (SIGINT)
/// or a SIGTERM (usually sent by `docker stop`).
async fn shutdown_handler(shutdown_tx: broadcast::Sender<()>) {
    // Handle Ctrl-C (SIGINT)
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Ctrl-C handler must be installed")
    };

    // Handle SIGTERM (sent by `docker stop`)
    let mut terminate =
        signal::unix::signal(SignalKind::terminate()).expect("SIGTERM handler must be installed");

    tracing::info!("awaiting shutdown signal...");
    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate.recv() => {},
    }

    tracing::info!("shutdown signal received");
    let _ = shutdown_tx.send(());
}

async fn join_task(handle: JoinHandle<anyhow::Result<()>>, name: &str) {
    match handle.await {
        Ok(res) => {
            if let Err(e) = res {
                tracing::error!("{} error: {}", name, e);
            }
        }
        Err(e) => {
            tracing::error!("failed to join {}: {}", name, e);
        }
    }
}
