#![no_std]
#![no_main]

use aya_ebpf::{macros::cgroup_skb, programs::SkBuffContext};
use aya_log_ebpf::info;

#[cgroup_skb]
pub fn noct(ctx: SkBuffContext) -> i32 {
    match try_noct(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_noct(ctx: SkBuffContext) -> Result<i32, i32> {
    info!(&ctx, "received a packet");
    Ok(1)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
