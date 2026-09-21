#![no_std]

use core::net::Ipv4Addr;

/// Packet events passed from cgroup_skb programs to userspace via a PerfEventArray.
///
/// Direction (ingress or egress) is determined by the array used
/// (there's one for ingress and another for egress).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEvent {
    /// Source IP address. Only IPv4.
    pub src_addr: Ipv4Addr,
    /// Destination IP address. Only IPv4.
    pub dst_addr: Ipv4Addr,
    /// Source port. Host endianness.
    pub src_port: u16,
    /// Destination port. Host endianness.
    pub dst_port: u16,
    /// Total packet length (including L3 and L4 headers).
    pub pkt_len: u16,
    /// Payload length (L4 specified length).
    pub payload_len: u16,
    /// Protocol declared by IP header.
    pub protocol: u8,
    /// Padding. See below.
    pub _pad: [u8; 3],
}

/// Program sets `PERF_SAMPLE_RAW` which adds a 32-bit value indicating size of the data.
/// It then is padded with 0 to have 64-bit alignment.
/// Manual padding is added so that no additional padding is required after adding
/// the size value.
/// See man pages for `perf_event_open`.
const _: () = assert!(
    // Make sure that after adding 4 bytes it'll be aligned to 8 bytes.
    core::mem::size_of::<PacketEvent>() % 8 == 4,
    "PacketEvent isn't properly aligned!"
);

#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketEvent {}
