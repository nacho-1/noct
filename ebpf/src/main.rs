#![no_std]
#![no_main]
#![allow(internal_features)]
#![feature(core_intrinsics)]

use core::{array, intrinsics::{self, AtomicOrdering}, net::Ipv4Addr};

use aya_ebpf::{
    bindings::{
        BPF_NOEXIST, BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        BPF_SOCK_OPS_RETRANS_CB, BPF_SOCK_OPS_RETRANS_CB_FLAG, BPF_SOCK_OPS_RTT_CB,
        BPF_SOCK_OPS_RTT_CB_FLAG, BPF_SOCK_OPS_STATE_CB, BPF_SOCK_OPS_STATE_CB_FLAG,
        BPF_TCP_ESTABLISHED,
    },
    helpers::generated::{bpf_get_socket_cookie, bpf_sock_ops_cb_flags_set},
    macros::{cgroup_skb, map, sock_ops},
    maps::{Array, HashMap, PerfEventArray},
    programs::{SkBuffContext, SockOpsContext},
};
use aya_log_ebpf::{debug, error};
use network_types::{
    eth::EtherType,
    ip::{IpError, IpProto, Ipv4Hdr, Ipv6Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};
use noct_common::{ConnectionRetrans, ConnectionSRTT, IP4_ADDR_TYPE, IP4_CONN_POS, IP6_ADDR_TYPE, IP6_CONN_POS, PacketEvent};

/// Return value to let package pass.
const PASS_PKT: i32 = 1;
/// Return value for successful `sock_ops` program.
const SOCK_OPS_SUCCESS: u32 = 1;
/// Socket value for IPv4 addresses.
const AF_INET: u32 = 2;
/// Socket value for IPv6 addresses.
const AF_INET6: u32 = 10;

/// Array for transmitting ingress packet stats.
#[map]
static RX_STATS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

/// Array for transmitting egress packet stats.
#[map]
static TX_STATS: PerfEventArray<PacketEvent> = PerfEventArray::new(0);

/// Array for transmitting connection SRTT values.
#[map]
static SRTT_UPDATES: PerfEventArray<ConnectionSRTT> = PerfEventArray::new(0);

/// Array for transmitting connection TCP retransmissions.
#[map]
static RETRANSMISSIONS: PerfEventArray<ConnectionRetrans> = PerfEventArray::new(0);

/// Map for tracking active connections.
///
/// Mainly used for cases when the program is started
/// on systems that already have established connections,
/// as to not operate on un-tracked connections.
#[map]
static ACTIVE_CONNS: HashMap<u64, u8> = HashMap::with_max_entries(65535, 0);

/// Counter of active connections.
///
/// Used to determine number of connections in O(1).
#[map]
static CONN_COUNT: Array<u32> = Array::with_max_entries(2, 0);

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
            process_conn_established(ctx);
        }
        BPF_SOCK_OPS_RTT_CB => {
            process_rtt_update(ctx);
        }
        BPF_SOCK_OPS_RETRANS_CB => {
            debug!(&ctx, "retransmission");
        }
        BPF_SOCK_OPS_STATE_CB => {
            process_conn_state_change(ctx);
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
#[inline(always)]
fn process_skb_ip4(ctx: SkBuffContext, ip4hdr: Ipv4Hdr, map: &PerfEventArray<PacketEvent>) -> i32 {
    let protocol = match ip4hdr.proto() {
        Ok(ret) => ret,
        Err(IpError::InvalidProto(n)) => {
            error!(&ctx, "invalid protocol: {}", n);
            return PASS_PKT;
        }
    };
    let stats = match protocol {
        IpProto::Tcp => {
            let tcphdr = match ctx.load::<TcpHdr>(usize::from(ip4hdr.ihl())) {
                Ok(ret) => ret,
                Err(e) => {
                    error!(&ctx, "failed to load TCP header: code {}", e);
                    return PASS_PKT;
                }
            };
            PacketEvent {
                src_addr: noct_common::encode_ip4_addr(ip4hdr.src_addr()),
                dst_addr: noct_common::encode_ip4_addr(ip4hdr.dst_addr()),
                src_port: u16::from_be_bytes(tcphdr.source),
                dst_port: u16::from_be_bytes(tcphdr.dest),
                pkt_len: ip4hdr.tot_len(),
                payload_len: ip_datagram_len(&ip4hdr) - tcphdr.doff() * 4,
                addr_type: noct_common::IP4_ADDR_TYPE,
                protocol: u8::from(protocol),
                _pad: [0; 2],
            }
        }
        IpProto::Udp => {
            let udphdr = match ctx.load::<UdpHdr>(usize::from(ip4hdr.ihl())) {
                Ok(ret) => ret,
                Err(e) => {
                    error!(&ctx, "failed to load UDP header: code {}", e);
                    return PASS_PKT;
                }
            };
            PacketEvent {
                src_addr: noct_common::encode_ip4_addr(ip4hdr.src_addr()),
                dst_addr: noct_common::encode_ip4_addr(ip4hdr.dst_addr()),
                src_port: udphdr.src_port(),
                dst_port: udphdr.dst_port(),
                pkt_len: ip4hdr.tot_len(),
                payload_len: udphdr.len() - 8,
                addr_type: noct_common::IP4_ADDR_TYPE,
                protocol: u8::from(protocol),
                _pad: [0; 2],
            }
        }
        _ => {
            return PASS_PKT;
        }
    };

    map.output(&ctx, stats, 0);
    PASS_PKT
}

/// Builds [PacketEvent] from context and IPv6 header, and outputs it to the array.
#[inline(always)]
fn process_skb_ip6(ctx: SkBuffContext, ip6hdr: Ipv6Hdr, map: &PerfEventArray<PacketEvent>) -> i32 {
    let protocol = match ip6hdr.next_hdr() {
        Ok(ret) => ret,
        Err(IpError::InvalidProto(n)) => {
            error!(&ctx, "invalid protocol: {}", n);
            return PASS_PKT;
        }
    };
    let stats = match protocol {
        IpProto::Tcp => {
            let tcphdr = match ctx.load::<TcpHdr>(Ipv6Hdr::LEN) {
                Ok(ret) => ret,
                Err(e) => {
                    error!(&ctx, "failed to load TCP header: code {}", e);
                    return PASS_PKT;
                }
            };
            PacketEvent {
                src_addr: ip6hdr.src_addr().to_bits().to_be_bytes(),
                dst_addr: ip6hdr.dst_addr().to_bits().to_be_bytes(),
                src_port: u16::from_be_bytes(tcphdr.source),
                dst_port: u16::from_be_bytes(tcphdr.dest),
                pkt_len: Ipv6Hdr::LEN as u16 + ip6hdr.payload_len(),
                payload_len: ip6hdr.payload_len() - tcphdr.doff() * 4,
                addr_type: noct_common::IP6_ADDR_TYPE,
                protocol: u8::from(protocol),
                _pad: [0; 2],
            }
        }
        IpProto::Udp => {
            let udphdr = match ctx.load::<UdpHdr>(Ipv6Hdr::LEN) {
                Ok(ret) => ret,
                Err(e) => {
                    error!(&ctx, "failed to load UDP header: code {}", e);
                    return PASS_PKT;
                }
            };
            PacketEvent {
                src_addr: ip6hdr.src_addr().to_bits().to_be_bytes(),
                dst_addr: ip6hdr.dst_addr().to_bits().to_be_bytes(),
                src_port: udphdr.src_port(),
                dst_port: udphdr.dst_port(),
                pkt_len: Ipv6Hdr::LEN as u16 + ip6hdr.payload_len(),
                payload_len: udphdr.len() - 8,
                addr_type: noct_common::IP6_ADDR_TYPE,
                protocol: u8::from(protocol),
                _pad: [0; 2],
            }
        }
        _ => {
            return PASS_PKT;
        }
    };

    map.output(&ctx, stats, 0);
    PASS_PKT
}

/// Process a new connection.
///
/// Sets the necessary flags to get specific callbacks
/// throughout the socket's lifetime.
/// Adds the socket cookie to the connection-tracker
/// and adds 1 to the connection-counter.
#[inline(always)]
fn process_conn_established(ctx: SockOpsContext) {
    // Check for IPv4 or IPv6. Otherwise don't track.
    let array_pos = match ctx.family() {
        AF_INET => IP4_CONN_POS,
        AF_INET6 => IP6_CONN_POS,
        _ => {
            return;
        }
    };

    let flags = (BPF_SOCK_OPS_RTT_CB_FLAG
        | BPF_SOCK_OPS_RETRANS_CB_FLAG
        | BPF_SOCK_OPS_STATE_CB_FLAG) as i32;
    // SAFETY: `ctx.ops` is a valid, non-null pointer to `bpf_sock_ops` structure
    // provided by the kernel eBPF runtime for this execution context.
    // `bpf_sock_ops_cb_flags_set` is a valid helper for `sock_ops` contexts.
    let ret = unsafe { bpf_sock_ops_cb_flags_set(ctx.ops, flags) };
    if ret != 0 {
        error!(&ctx, "failed to set sock_ops flags: {}", ret);
    }

    // SAFETY: `ctx.ops` is a valid, non-null pointer to `bpf_sock_ops` structure
    // provided by the kernel eBPF runtime for this execution context,
    // which is acceptable as the context pointer (`*mut c_void`)
    // for `bpf_get_socket_cookie`.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as *mut _) };

    if ACTIVE_CONNS.insert(cookie, 1, BPF_NOEXIST as u64).is_ok() {
        if let Some(counter) = CONN_COUNT.get_ptr_mut(array_pos) {
            // From what I could find this is the main way of doing atomic addition
            // see aya/test/integration-ebpf/src/kprobe.rs.
 

            // SAFETY: `get_ptr_mut` guarantees `counter` is non-null, aligned and
            // valid map memory. The atomic intrinsic prevents data races across CPU cores.
            unsafe {
                intrinsics::atomic_xadd::<u32, u32, {AtomicOrdering::Relaxed}>(
                    counter,
                    1
                );
            }
        }
    }
}

/// Process a connection state change.
///
/// Checks if the connection ended by checking if the connection state
/// transitioned from `established` to something else.
/// Removes the connection from the connection-tracker
/// and substracts 1 from the connection counter.
#[inline(always)]
fn process_conn_state_change(ctx: SockOpsContext) {
    if ctx.arg(0) != BPF_TCP_ESTABLISHED || ctx.arg(1) == BPF_TCP_ESTABLISHED {
        return;
    }

    // SAFETY: `ctx.ops` is a valid, non-null pointer to `bpf_sock_ops` structure
    // provided by the kernel eBPF runtime for this execution context,
    // which is acceptable as the context pointer (`*mut c_void`)
    // for `bpf_get_socket_cookie`.
    let cookie = unsafe { bpf_get_socket_cookie(ctx.ops as *mut _) };

    if ACTIVE_CONNS.remove(cookie).is_ok() {
        let array_pos = match ctx.family() {
            AF_INET => IP4_CONN_POS,
            AF_INET6 => IP6_CONN_POS,
            _ => {
                return;
            }
        };

        if let Some(counter) = CONN_COUNT.get_ptr_mut(array_pos) {
            // Don't like this but it appears atomic_xsub
            // has no corresponding BPF operation for LLVM/bpf_linker or something.

            // SAFETY: `get_ptr_mut` guarantees `counter` is non-null, aligned and
            // valid map memory. The atomic intrinsic prevents data races across CPU cores.
            unsafe {
                intrinsics::atomic_xadd::<u32, u32, {AtomicOrdering::Relaxed}>(
                    counter,
                    u32::MAX
                );
            }
        }
    }
}

/// Process an RTT update.
///
/// When the kernel updates de srtt of a connection,
/// send the value to userspace.
#[inline(always)]
fn process_rtt_update(ctx: SockOpsContext) {
    // Context has srtt stored 3 bits shifted left in microseconds.

    // SAFETY: `ctx.ops` is a valid, non-null pointer to `bpf_sock_ops` structure
    // provided by the kernel eBPF runtime for this execution context.
    let srtt = unsafe { (*ctx.ops).srtt_us >> 3 };

    let conn_srtt = match ctx.family() {
        AF_INET => ConnectionSRTT {
            src_addr: noct_common::encode_ip4_addr(Ipv4Addr::from_bits(ctx.local_ip4().to_be())),
            dst_addr: noct_common::encode_ip4_addr(Ipv4Addr::from_bits(ctx.remote_ip4().to_be())),
            src_port: ctx.local_port() as u16,
            dst_port: u32::from_be(ctx.remote_port()) as u16,
            srtt,
            addr_type: IP4_ADDR_TYPE,
            _pad: [0; 3],
        },
        AF_INET6 => ConnectionSRTT {
            src_addr: get_local_ip6(&ctx),
            dst_addr: get_remote_ip6(&ctx),
            src_port: ctx.local_port() as u16,
            dst_port: u32::from_be(ctx.remote_port()) as u16,
            srtt,
            addr_type: IP6_ADDR_TYPE,
            _pad: [0; 3],
        },
        _ => {
            return;
        }
    };

    SRTT_UPDATES.output(&ctx, conn_srtt, 0);
}

/// Process connection TCP retransmissions.
#[inline(always)]
fn process_retransmission(ctx: SockOpsContext) {
    // Only process if retransmission was successful.
    if ctx.arg(2) != 0 {
        return;
    }

    let retrans = match ctx.family() {
        AF_INET => ConnectionRetrans {
            src_addr: noct_common::encode_ip4_addr(Ipv4Addr::from_bits(ctx.local_ip4().to_be())),
            dst_addr: noct_common::encode_ip4_addr(Ipv4Addr::from_bits(ctx.remote_ip4().to_be())),
            src_port: ctx.local_port() as u16,
            dst_port: u32::from_be(ctx.remote_port()) as u16,
            segments: ctx.arg(1),
            addr_type: IP4_ADDR_TYPE,
            _pad: [0; 3],
        },
        AF_INET6 => ConnectionRetrans {
            src_addr: get_local_ip6(&ctx),
            dst_addr: get_remote_ip6(&ctx),
            src_port: ctx.local_port() as u16,
            dst_port: u32::from_be(ctx.remote_port()) as u16,
            segments: ctx.arg(1),
            addr_type: IP6_ADDR_TYPE,
            _pad: [0; 3],
        },
        _ => {
            return;
        }
    };

    RETRANSMISSIONS.output(&ctx, retrans, 0);
}

/// Return the length of the datagram inside an IPv4 packet.
///
/// This is total length - header length (required fields + options).
#[inline(always)]
fn ip_datagram_len(ip4hdr: &Ipv4Hdr) -> u16 {
    ip4hdr.tot_len() - u16::from(ip4hdr.ihl())
}

/// Parse IPv6 address from 4 sets of 32 bits to the raw 16 bytes.
#[inline(always)]
fn ipv6_addr_bytes(addr: [u32; 4]) -> [u8; 16] {
    array::from_fn(|i| {
        addr[i / 4].to_ne_bytes()[i % 4]
    })
}

/// Read local IPv6 address from sock_ops context.
///
/// Explicitly make it do 4 byte reads.
/// Was running into a problem where it was doing 8 byte reads
/// and the BPF verifier didn't like that.
/// See https://hechao.li/posts/An-Invalid-bpf_context-Access-Bug/
#[inline(always)]
fn get_local_ip6(ctx: &SockOpsContext) -> [u8; 16] {
    // SAFETY: `ctx.ops` is a valid, non-null pointer to `bpf_sock_ops` structure
    // provided by the kernel eBPF runtime for this execution context.
    let p = unsafe {
        &raw const (*ctx.ops).local_ip6 as *const u32
    };
    // SAFETY: `p` points to the `local_ip6` field, which is a `[u32;4]` aligned to 4 bytes
    // inside valid kernel context memory. Reading 4 contiguous `u32` elements
    // stays strictly within bounds.
    let addr = unsafe {
        [
            core::ptr::read_volatile(p),
            core::ptr::read_volatile(p.add(1)),
            core::ptr::read_volatile(p.add(2)),
            core::ptr::read_volatile(p.add(3)),
        ]
    };
    ipv6_addr_bytes(addr)
}

/// Read remote IPv6 address from sock_ops context.
///
/// Same as for local IPv6.
#[inline(always)]
fn get_remote_ip6(ctx: &SockOpsContext) -> [u8; 16] {
    // SAFETY: `ctx.ops` is a valid, non-null pointer to `bpf_sock_ops` structure
    // provided by the kernel eBPF runtime for this execution context.
    let p = unsafe {
        &raw const (*ctx.ops).remote_ip6 as *const u32
    };
    // SAFETY: `p` points to the `remote_ip6` field, which is a `[u32;4]` aligned to 4 bytes
    // inside valid kernel context memory. Reading 4 contiguous `u32` elements
    // stays strictly within bounds.
    let addr = unsafe {
        [
            core::ptr::read_volatile(p),
            core::ptr::read_volatile(p.add(1)),
            core::ptr::read_volatile(p.add(2)),
            core::ptr::read_volatile(p.add(3)),
        ]
    };
    ipv6_addr_bytes(addr)
}


#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 4] = *b"GPL\0";
