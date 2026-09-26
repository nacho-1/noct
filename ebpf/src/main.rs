#![no_std]
#![no_main]

use aya_ebpf::{macros::{cgroup_skb, map}, maps::PerfEventArray, programs::SkBuffContext};
use aya_log_ebpf::{error, info};
use network_types::{eth::EtherType, ip::{IpError, IpProto, Ipv4Hdr}, tcp::TcpHdr, udp::UdpHdr};
use noct_common::PacketEvent;

/// Return value to let package pass.
const PASS_PKT: i32 = 1;

/// Array for transmitting ingress packet stats.
#[map]
static RX_STATS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

/// Array for transmitting egress packet stats.
#[map]
static TX_STATS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

#[cgroup_skb]
pub fn ingress(ctx: SkBuffContext) -> i32 {
    process_skb(ctx, &RX_STATS)
}

fn _try_ingress(ctx: SkBuffContext) -> Result<i32, i32> {
    info!(&ctx, "packet ingress");
    Ok(PASS_PKT)
}

#[cgroup_skb]
pub fn egress(ctx: SkBuffContext) -> i32 {
    process_skb(ctx, &TX_STATS)
}

/// Builds [PacketEvent] from context and outputs it to the array.
fn process_skb(ctx: SkBuffContext, map: &PerfEventArray<PacketEvent>) -> i32 {
    if ctx.skb.protocol() != u32::from(u16::from(EtherType::Ipv4)) {
        return PASS_PKT;
    }

    let ip4hdr = match ctx.load::<Ipv4Hdr>(0) {
        Ok(ret) => ret,
        Err(e) => {
            error!(&ctx, "failed to load IPv4 header: code {}", e);
            return PASS_PKT;
        }
    };
    let protocol = match ip4hdr.proto() {
        Ok(ret) => ret,
        Err(IpError::InvalidProto(n)) => {
            error!(&ctx, "invalid protocol: {}", n);
            return PASS_PKT;
        }
    };
    match protocol {
        IpProto::Tcp => {
            let tcphdr = match ctx.load::<TcpHdr>(usize::from(ip4hdr.ihl())) {
                Ok(ret) => ret,
                Err(e) => {
                    error!(&ctx, "failed to load TCP header: code {}", e);
                    return PASS_PKT;
                }
            };
            let stats = PacketEvent {
                src_addr: ip4hdr.src_addr(),
                dst_addr: ip4hdr.dst_addr(),
                src_port: u16::from_be_bytes(tcphdr.source),
                dst_port: u16::from_be_bytes(tcphdr.dest),
                pkt_len: ip4hdr.tot_len(),
                payload_len: ip_datagram_len(&ip4hdr) - tcphdr.doff() * 4,
                protocol: u8::from(protocol),
                _pad: [0; 3],
            };
            map.output(&ctx, &stats, 0);
        }
        IpProto::Udp => {
            let udphdr = match ctx.load::<UdpHdr>(usize::from(ip4hdr.ihl())) {
                Ok(ret) => ret,
                Err(e) => {
                    error!(&ctx, "failed to load UDP header: code {}", e);
                    return PASS_PKT;
                }
            };
            let stats = PacketEvent {
                src_addr: ip4hdr.src_addr(),
                dst_addr: ip4hdr.dst_addr(),
                src_port: udphdr.src_port(),
                dst_port: udphdr.dst_port(),
                pkt_len: ip4hdr.tot_len(),
                payload_len: udphdr.len() - 8,
                protocol: u8::from(protocol),
                _pad: [0; 3],
            };
            map.output(&ctx, &stats, 0);
        }
        _ => {}
    }

    PASS_PKT
}

/// Returns the length of the datagram inside an IPv4 packet.
///
/// This is total length - header length (required fields + options).
fn ip_datagram_len(ip4hdr: &Ipv4Hdr) -> u16 {
    ip4hdr.tot_len() - u16::from(ip4hdr.ihl())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
