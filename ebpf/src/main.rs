#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        BPF_SOCK_OPS_RETRANS_CB, BPF_SOCK_OPS_RETRANS_CB_FLAG, BPF_SOCK_OPS_RTT_CB,
        BPF_SOCK_OPS_RTT_CB_FLAG, BPF_SOCK_OPS_STATE_CB, BPF_SOCK_OPS_STATE_CB_FLAG,
        BPF_TCP_ESTABLISHED,
    },
    helpers::generated::bpf_sock_ops_cb_flags_set,
    macros::{cgroup_skb, map, sock_ops},
    maps::PerfEventArray,
    programs::{SkBuffContext, SockOpsContext},
};
use aya_log_ebpf::{debug, error};
use network_types::{
    eth::EtherType,
    ip::{IpError, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use noct_common::PacketEvent;

/// Return value to let package pass.
const PASS_PKT: i32 = 1;
/// Return value for successful `sock_ops` program.
const SOCK_OPS_SUCCESS: u32 = 1;

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

#[cgroup_skb]
pub fn egress(ctx: SkBuffContext) -> i32 {
    process_skb(ctx, &TX_STATS)
}

#[sock_ops]
pub fn socket_ops(ctx: SockOpsContext) -> u32 {
    let op = ctx.op();

    match op {
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB | BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            debug!(&ctx, "connection established");
            let flags = (BPF_SOCK_OPS_RTT_CB_FLAG
                | BPF_SOCK_OPS_RETRANS_CB_FLAG
                | BPF_SOCK_OPS_STATE_CB_FLAG) as i32;
            // SAFETY: Just an external call to bpf helper.
            let ret = unsafe { bpf_sock_ops_cb_flags_set(ctx.ops, flags) };
            if ret != 0 {
                error!(&ctx, "failed to set sock_ops flags: {}", ret);
            }
        }
        BPF_SOCK_OPS_RTT_CB => {
            let srtt = unsafe { (*ctx.ops).srtt_us >> 3 };
            debug!(&ctx, "recalculated RTT: {} us", srtt);
        }
        BPF_SOCK_OPS_RETRANS_CB => {
            debug!(&ctx, "retransmission");
        }
        BPF_SOCK_OPS_STATE_CB => {
            if ctx.arg(0) == BPF_TCP_ESTABLISHED && ctx.arg(1) != BPF_TCP_ESTABLISHED {
                debug!(&ctx, "connection ended");
            }
        }
        _ => {}
    }

    SOCK_OPS_SUCCESS
}

/// Builds [PacketEvent] from context and outputs it to the array.
///
/// Determines L3 protocol: IPv4 or IPv6 and delegates.
#[inline(always)]
fn process_skb(ctx: SkBuffContext, map: &PerfEventArray<PacketEvent>) -> i32 {
    let proto = ctx.skb.protocol();
    if proto == u32::from(u16::from(EtherType::Ipv4)) {
        let ip4hdr = match ctx.load::<Ipv4Hdr>(0) {
            Ok(ret) => ret,
            Err(e) => {
                error!(&ctx, "failed to load IPv4 header: code {}", e);
                return PASS_PKT;
            }
        };

        process_skb_ip4(ctx, ip4hdr, map)
    } else if proto == u32::from(u16::from(EtherType::Ipv6)) {
        let ip6hdr = match ctx.load::<Ipv6Hdr>(0) {
            Ok(ret) => ret,
            Err(e) => {
                error!(&ctx, "failed to load IPv6 header: code {}", e);
                return PASS_PKT;
            }
        };

        process_skb_ip6(ctx, ip6hdr, map)
    } else {
        PASS_PKT
    }
}

/// Builds [PacketEvent] from context and IPv4 header, and outputs it to the array.
fn process_skb_ip4(ctx: SkBuffContext, ip4hdr: Ipv4Hdr, map: &PerfEventArray<PacketEvent>) -> i32 {
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
                src_addr: noct_common::encode_ip4_addr(ip4hdr.src_addr()),
                dst_addr: noct_common::encode_ip4_addr(ip4hdr.dst_addr()),
                src_port: u16::from_be_bytes(tcphdr.source),
                dst_port: u16::from_be_bytes(tcphdr.dest),
                pkt_len: ip4hdr.tot_len(),
                payload_len: ip_datagram_len(&ip4hdr) - tcphdr.doff() * 4,
                addr_type: noct_common::IP4_ADDR_TYPE,
                protocol: u8::from(protocol),
                _pad: [0; 2],
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
                src_addr: noct_common::encode_ip4_addr(ip4hdr.src_addr()),
                dst_addr: noct_common::encode_ip4_addr(ip4hdr.dst_addr()),
                src_port: udphdr.src_port(),
                dst_port: udphdr.dst_port(),
                pkt_len: ip4hdr.tot_len(),
                payload_len: udphdr.len() - 8,
                addr_type: noct_common::IP4_ADDR_TYPE,
                protocol: u8::from(protocol),
                _pad: [0; 2],
            };
            map.output(&ctx, &stats, 0);
        }
        _ => {}
    }

    PASS_PKT
}

/// Builds [PacketEvent] from context and IPv6 header, and outputs it to the array.
fn process_skb_ip6(ctx: SkBuffContext, ip6hdr: Ipv6Hdr, map: &PerfEventArray<PacketEvent>) -> i32 {
    let protocol = match ip6hdr.next_hdr() {
        Ok(ret) => ret,
        Err(IpError::InvalidProto(n)) => {
            error!(&ctx, "invalid protocol: {}", n);
            return PASS_PKT;
        }
    };
    match protocol {
        IpProto::Tcp => {
            let tcphdr = match ctx.load::<TcpHdr>(Ipv6Hdr::LEN) {
                Ok(ret) => ret,
                Err(e) => {
                    error!(&ctx, "failed to load TCP header: code {}", e);
                    return PASS_PKT;
                }
            };
            let stats = PacketEvent {
                src_addr: ip6hdr.src_addr().to_bits().to_be_bytes(),
                dst_addr: ip6hdr.dst_addr().to_bits().to_be_bytes(),
                src_port: u16::from_be_bytes(tcphdr.source),
                dst_port: u16::from_be_bytes(tcphdr.dest),
                pkt_len: Ipv6Hdr::LEN as u16 + ip6hdr.payload_len(),
                payload_len: ip6hdr.payload_len() - tcphdr.doff() * 4,
                addr_type: noct_common::IP6_ADDR_TYPE,
                protocol: u8::from(protocol),
                _pad: [0; 2],
            };
            map.output(&ctx, &stats, 0);
        }
        IpProto::Udp => {
            let udphdr = match ctx.load::<UdpHdr>(Ipv6Hdr::LEN) {
                Ok(ret) => ret,
                Err(e) => {
                    error!(&ctx, "failed to load UDP header: code {}", e);
                    return PASS_PKT;
                }
            };
            let stats = PacketEvent {
                src_addr: ip6hdr.src_addr().to_bits().to_be_bytes(),
                dst_addr: ip6hdr.dst_addr().to_bits().to_be_bytes(),
                src_port: udphdr.src_port(),
                dst_port: udphdr.dst_port(),
                pkt_len: Ipv6Hdr::LEN as u16 + ip6hdr.payload_len(),
                payload_len: udphdr.len() - 8,
                addr_type: noct_common::IP6_ADDR_TYPE,
                protocol: u8::from(protocol),
                _pad: [0; 2],
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
