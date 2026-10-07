use anyhow::Context;
use aya::{
    Ebpf,
    maps::PerfEventArray,
};
use clap::Parser;
use noct_config::Config;
use tokio::{
    signal::{self, unix::SignalKind},
    sync::{broadcast, mpsc},
};
use tracing_panic::panic_hook;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Helpers for managing eBPF logic.
mod ebpf_helpers;

pub use ebpf_helpers::read_event_array;

/// Application options passed by arguments.
#[derive(Debug, Parser)]
pub struct Opts {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: std::path::PathBuf,
}

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
pub async fn run(opts: Opts) -> anyhow::Result<()> {
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

    let Opts { cgroup_path } = opts;
    // Load the eBPF programs into the kernel at this point.
    ebpf_helpers::init_ebpf(&mut ebpf, cgroup_path)?;

    // Channel used for graceful shutdown of the different tasks of the application.
    let (shutdown_tx, _) = broadcast::channel(1);

    // Start spawning the different tasks of the application.

    let ebpf_logger = match ebpf_helpers::init_ebpf_logger(&mut ebpf, shutdown_tx.subscribe()) {
        Ok(handler) => Some(handler),
        Err(e) => {
            tracing::warn!("failed to initialize eBPF logger: {e}");
            None
        }
    };

    // Spawn the different eBPF event consumers.
    // They read the data sent by the eBPF programs an output it as data to be used
    // in userspace.
    let (ingress_stats_tx, ingress_stats_rx) = mpsc::unbounded_channel();
    let (egress_stats_tx, egress_stats_rx) = mpsc::unbounded_channel();
    let ingress_readers = read_event_array(ingress_stats_map, ingress_stats_tx, shutdown_tx.subscribe())?;
    let egress_readers = read_event_array(egress_stats_map, egress_stats_tx, shutdown_tx.subscribe())?;

    let server = tokio::spawn(
        noct_web::run(
            config.server,
            ingress_stats_rx,
            egress_stats_rx,
            shutdown_tx.subscribe(),
        ));

    // Wait for application shutdown.
    shutdown_handler(shutdown_tx).await;

    // Perform shutdown cleanups.
    // TODO: Refactor

    if let Some(handler) = ebpf_logger {
        match handler.await {
            Ok(res) => {
                if let Err(e) = res {
                    tracing::error!("eBPF logger error: {e}");
                }
            }
            Err(e) => {
                tracing::error!("failed to join eBPF logger: {e}");
            }
        }
    }

    tracing::info!("shutting down eBPF event readers...");
    for handler in ingress_readers {
        match handler.await {
            Ok(res) => {
                if let Err(e) = res {
                    tracing::error!("ingress stats reader error: {e}");
                }
            }
            Err(e) => {
                tracing::error!("failed to join ingress stats reader: {e}");
            }
        }
    }
    for handler in egress_readers {
        match handler.await {
            Ok(res) => {
                if let Err(e) = res {
                    tracing::error!("egress stats reader error: {e}");
                }
            }
            Err(e) => {
                tracing::error!("failed to join egress stats reader: {e}");
            }
        }
    }

    match server.await {
        Ok(handle) => {
            if let Err(e) = handle {
                tracing::error!("server error: {e}");
            }
        }
        Err(e) => {
            tracing::error!("failed to join server: {e}");
        }
    }

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
