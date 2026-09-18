use std::fs::File;

use anyhow::Context as _;
use aya::{
    Ebpf,
    programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode},
};
use aya_log::EbpfLogger;
use clap::Parser;
#[rustfmt::skip]
use log::warn;
use tokio::{
    io::{Interest, unix::AsyncFd},
    signal, task,
};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "/sys/fs/cgroup")]
    cgroup_path: std::path::PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

    env_logger::init();

    // This will include your eBPF object file as raw bytes at compile-time
    // and load it at runtime.
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/noct"
    )))?;
    match EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            // This can happen if you remove all log statements from your eBPF program.
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger = AsyncFd::with_interest(logger, Interest::READABLE)?;
            task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }
    let Opt { cgroup_path } = opt;
    let cgroup = File::open(&cgroup_path).with_context(|| format!("{}", cgroup_path.display()))?;
    let program: &mut CgroupSkb = ebpf.program_mut("noct").unwrap().try_into()?;
    program.load()?;
    program.attach(
        cgroup,
        CgroupSkbAttachType::Ingress,
        CgroupAttachMode::default(),
    )?;

    let ctrl_c = signal::ctrl_c();
    println!("Waiting for Ctrl-C...");
    ctrl_c.await?;
    println!("Exiting...");

    Ok(())
}
