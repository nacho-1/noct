use std::{fs::File, mem::MaybeUninit, path::PathBuf, time::Duration};

use anyhow::Context as _;
use aya::{
    Ebpf,
    maps::{
        Array, MapData, PerfEventArray,
        perf::{PerfEvent, PerfEventArrayBuffer},
    },
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, SockOps},
};
use aya_log::EbpfLogger;
use noct_db::EventMsg;
use tokio::{
    io::{
        Interest,
        unix::{AsyncFd, AsyncFdReadyMutGuard},
    },
    sync::{broadcast, mpsc::UnboundedSender},
    task::JoinHandle,
};

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
        cgroup.try_clone()?,
        CgroupSkbAttachType::Egress,
        CgroupAttachMode::default(),
    )?;
    let socks_program: &mut SockOps = ebpf.program_mut("socket_ops").unwrap().try_into()?;
    socks_program.load()?;
    socks_program.attach(cgroup, CgroupAttachMode::default())?;

    Ok(())
}

/// Reads the event array and pushes the events into a channel.
///
/// Expects events of type [T] and outputs events of type [U].
/// The function spawns a task for each online CPU to read the array,
/// since there's one per CPU.
/// Returns the handles to the tasks.
/// The tasks will exit normally if the receiving side of the channel
/// is closed or if a shutdown broadcast is received.
pub fn read_event_array<T, U>(
    mut array: PerfEventArray<MapData>,
    sender: UnboundedSender<EventMsg<U>>,
    shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<Vec<JoinHandle<anyhow::Result<()>>>>
where
    T: aya::Pod,
    U: From<T> + Send + 'static,
{
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
                            let event = U::from(event);
                            if let Err(_) = tx.send(EventMsg::new(event)) {
                                return Ok(());
                            }
                        }
                    }

                    res = shdn.recv() => {
                        match res {
                            Ok(_) => {
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

        handles.push(handle);
    }

    Ok(handles)
}

/// Reads the event array buffer and initializes each event.
fn read_event_buffer<T>(
    mut guard: AsyncFdReadyMutGuard<'_, PerfEventArrayBuffer<MapData>>,
) -> Vec<T>
where
    T: aya::Pod,
{
    let mut events = Vec::new();

    guard.get_inner_mut().for_each(|event| match event {
        PerfEvent::Sample { head, tail } => {
            let mut data = MaybeUninit::<T>::uninit();
            let bytes = as_bytes_mut(&mut data);
            for (dst, src) in bytes.iter_mut().zip(head.iter().chain(tail)) {
                dst.write(*src);
            }
            // SAFETY: The loop above wrote every byte of `data`. Type is Pod.
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

/// Watches the current connection counter from the eBPF program.
pub async fn watch_conn_count(
    array: Array<MapData, u32>,
    sender: UnboundedSender<EventMsg<u32>>,
    mut shutdown: broadcast::Receiver<()>,
) -> anyhow::Result<()> {
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let active_conns = array.get(&0, 0)?;
                if let Err(_) = sender.send(EventMsg::new(active_conns)) {
                    return Ok(());
                }
            }
            res = shutdown.recv() => {
                match res {
                    Ok(_) => {
                        return Ok(());
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        }
    }
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
                        Ok(_) => {
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
