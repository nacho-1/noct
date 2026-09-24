use std::{fs::File, mem::MaybeUninit};

use anyhow::Context as _;
use aya::{Ebpf, maps::{MapData, PerfEventArray, perf::PerfEvent}, programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType}};
use aya_log::EbpfLogger;
use clap::Parser;
use log::{info, warn};
use noct_common::PacketEvent;
use tokio::{io::{Interest, unix::AsyncFd}, signal::{self, unix::SignalKind}, sync::mpsc::{self, UnboundedReceiver, UnboundedSender}, task::JoinHandle};
use tracing_panic::panic_hook;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

/// Application options passed by arguments.
#[derive(Debug, Parser)]
pub struct Opts {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: std::path::PathBuf,
}

/// Converts an uninitialized instance of [T] into a slice of uninitialized bytes.
// TODO(https://github.com/rust-lang/rust/issues/93092): replace with `MaybeUninit::as_bytes_mut`
// once stable.
fn as_bytes_mut<T>(slot: &mut MaybeUninit<T>) -> &mut [MaybeUninit<u8>] {
    // SAFETY: MaybeUninit<u8> imposes no validity invariants on its memory.
    // Means can contain any pattern of bits.
    unsafe {
        std::slice::from_raw_parts_mut(
            slot.as_mut_ptr().cast::<MaybeUninit<u8>>(),
            size_of::<T>(),
        )
    }
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
pub async fn run(opts: Opts) -> anyhow::Result<()> {
    // This will include the eBPF object file as raw bytes at compile-time
    // and load it at runtime.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;

    match EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if all log statements are removed from the eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    let Opts { cgroup_path } = opts;
    let cgroup = File::open(&cgroup_path).with_context(|| format!("{}", cgroup_path.display()))?;
    let ingress_program: &mut CgroupSkb = ebpf.program_mut("ingress").unwrap().try_into()?;
    ingress_program.load()?;
    ingress_program.attach(
        cgroup.try_clone()?,
        CgroupSkbAttachType::Ingress,
        CgroupAttachMode::default(),
    )?;
    let egress_program: &mut CgroupSkb = ebpf.program_mut("egress").unwrap().try_into()?;
    egress_program.load()?;
    egress_program.attach(
        cgroup,
        CgroupSkbAttachType::Egress,
        CgroupAttachMode::default(),
    )?;

    let ingress_stats_map = PerfEventArray::try_from(ebpf.take_map("RX_STATS").unwrap())?;
    let egress_stats_map = PerfEventArray::try_from(ebpf.take_map("TX_STATS").unwrap())?;
    let (ingress_stats_tx, ingress_stats_rx) = mpsc::unbounded_channel();
    let (egress_stats_tx, egress_stats_rx) = mpsc::unbounded_channel();
    read_event_array(ingress_stats_map, ingress_stats_tx)?;
    read_event_array(egress_stats_map, egress_stats_tx)?;
    log_events(ingress_stats_rx);
    log_events(egress_stats_rx);

    println!("Waiting for Ctrl-C...");
    shutdown_handler().await;
    println!("Exiting...");

    Ok(())
}

/// Reads the event array and pushes the events into a channel.
///
/// The functions spawns a task for each online CPU to read the array,
/// since there's one per CPU.
/// Returns the handles to the tasks.
/// The tasks will exit normally if the receiving side of the channel
/// is closed, but may panic under exceptional circumstances.
pub fn read_event_array(
    mut array: PerfEventArray<MapData>,
    sender: UnboundedSender<PacketEvent>,
) -> anyhow::Result<Vec<JoinHandle<()>>> {
    let mut handles = Vec::new();

    for cpu_id in aya::util::online_cpus().map_err(|(_, error)| error)? {
        let buf = array.open(cpu_id, None)?;
        let mut buf = AsyncFd::with_interest(buf, Interest::READABLE)?;
        let tx = sender.clone();

        let handle = tokio::spawn(async move {
            loop {
                let mut guard = buf.readable_mut().await.unwrap();
                guard.get_inner_mut().for_each(|event| match event {
                    PerfEvent::Sample { head, tail } => {
                        let mut data = MaybeUninit::<PacketEvent>::uninit();
                        let bytes = as_bytes_mut(&mut data);
                        for (dst, src) in bytes.iter_mut().zip(head.iter().chain(tail)) {
                            dst.write(*src);
                        }
                        let data = unsafe {
                            data.assume_init()
                        };
                        if let Err(_) = tx.send(data) {
                            return;
                        }
                    }
                    PerfEvent::Lost { count } => {
                        warn!("DROPPED {count} SAMPLES")
                    }
                });
                guard.clear_ready();
            }
        });

        handles.push(handle);
    }

    Ok(handles)
}

fn log_events(mut rx: UnboundedReceiver<PacketEvent>) {
    tokio::spawn(async move {
        while let Some(event) = rx.recv().await {
            info!("USERSPACE STATS: {:?}", event);
        }
    });
}

/// Handles shutdown of the application.
///
/// Will await for either a Ctrl-C (SIGINT)
/// or a SIGTERM (usually sent by `docker stop`).
async fn shutdown_handler() {
    // Handle Ctrl-C (SIGINT)
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("Ctrl-C handler must be installed")
    };

    // Handle SIGTERM (sent by `docker stop`)
    let mut terminate = signal::unix::signal(SignalKind::terminate())
        .expect("SIGTERM handler must be installed");

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate.recv() => {},
    }

    tracing::info!("Shutdown signal received");
}
