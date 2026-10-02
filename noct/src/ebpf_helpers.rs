use std::{fs::File, mem::MaybeUninit, path::PathBuf};

use anyhow::Context as _;
use aya::{Ebpf, maps::{MapData, PerfEventArray, perf::{PerfEvent, PerfEventArrayBuffer}}, programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType}};
use aya_log::EbpfLogger;
use noct_common::PacketEvent;
use tokio::{io::{Interest, unix::{AsyncFd, AsyncFdReadyMutGuard}}, sync::{broadcast, mpsc::UnboundedSender}, task::JoinHandle};

/// Converts an uninitialized instance of [T] into a slice of uninitialized bytes.
// TODO(https://github.com/rust-lang/rust/issues/93092): replace with `MaybeUninit::as_bytes_mut`
// once stable.
fn as_bytes_mut<T>(slot: &mut MaybeUninit<T>) -> &mut [MaybeUninit<u8>] {
    // SAFETY: MaybeUninit<u8> imposes no validity invariants on its memory.
    // Means can contain any pattern of bits.
    unsafe {
        std::slice::from_raw_parts_mut(slot.as_mut_ptr().cast::<MaybeUninit<u8>>(), size_of::<T>())
    }
}

/// Loads the eBPF programs into the kernel.
pub fn init_ebpf(ebpf: &mut Ebpf, cgroup_path: PathBuf) -> anyhow::Result<()> {
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

    Ok(())
}

/// Reads the event array and pushes the events into a channel.
///
/// The function spawns a task for each online CPU to read the array,
/// since there's one per CPU.
/// Returns the handles to the tasks.
/// The tasks will exit normally if the receiving side of the channel
/// is closed or if a shutdown broadcast is received.
pub fn read_event_array(
    mut array: PerfEventArray<MapData>,
    sender: UnboundedSender<PacketEvent>,
    shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<Vec<JoinHandle<anyhow::Result<()>>>> {
    let mut handles = Vec::new();

    for cpu_id in aya::util::online_cpus().map_err(|(_, error)| error)? {
        let buf = array.open(cpu_id, None)?;
        let mut buf = AsyncFd::with_interest(buf, Interest::READABLE)?;
        let tx = sender.clone();
        let mut shdn = shutdown.resubscribe();

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    guard = buf.readable_mut() => {
                        let guard = guard?;
                        let events = read_event_buffer(guard);
                        for event in events {
                            if let Err(_) = tx.send(event) {
                                return Ok(());
                            }
                        }
                    }

                    res = shdn.recv() => {
                        match res {
                            Ok(()) => {
                                tracing::info!("shutting down eBPF event reader");
                                return Ok(());
                            }
                            Err(e) => {
                                return Err(e.into())
                            }
                        }
                    }
                }
            }
        });

        handles.push(handle);
    }

    Ok(handles)
}

/// Reads the event array buffer and initializes each event.
fn read_event_buffer(
    mut guard: AsyncFdReadyMutGuard<'_, PerfEventArrayBuffer<MapData>>
) -> Vec<PacketEvent> {
    let mut events = Vec::new();

    guard.get_inner_mut().for_each(|event| match event {
        PerfEvent::Sample { head, tail } => {
            let mut data = MaybeUninit::<PacketEvent>::uninit();
            let bytes = as_bytes_mut(&mut data);
            for (dst, src) in bytes.iter_mut().zip(head.iter().chain(tail)) {
                dst.write(*src);
            }
            let data = unsafe { data.assume_init() };
            events.push(data);
        }
        PerfEvent::Lost { count } => {
            tracing::warn!("eBPF samples dropped: {count}");
        }
    });
    guard.clear_ready();

    events
}

/// Initializes the eBPF logger.
///
/// aya's implementation of the logger read logs from the eBPF program.
/// Can fail if all log statements are removed from the eBPF program.
pub fn init_ebpf_logger(
    ebpf: &mut Ebpf,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<JoinHandle<anyhow::Result<()>>> {
    let logger = EbpfLogger::init(ebpf)?;
    let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;
    let handler = tokio::task::spawn(async move {
        loop {
            tokio::select! {
                guard = logger.readable_mut() => {
                    let mut guard = guard?;
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }

                res = shutdown.recv() => {
                    match res {
                        Ok(()) => {
                            tracing::info!("shutting down ebpf logger");
                            return Ok(());
                        }
                        Err(e) => {
                            return Err(e.into());
                        }
                    }
                }
            }
        }
    });

    Ok(handler)
}
