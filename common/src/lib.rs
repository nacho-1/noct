#![no_std]

use core::net::Ipv4Addr;

/// Value for IPv4 addresses.
pub const IP4_ADDR_TYPE: u8 = 0;
/// Value for IPv6 addresses.
pub const IP6_ADDR_TYPE: u8 = 1;

/// Packet events passed from cgroup_skb programs to userspace via a PerfEventArray.
///
/// IPv4 addresses are stored as IPv4-mapped-IPv6: `::FFFF:<IPv4-address>`
/// IPv6 addresses are stored as the raw 128 bit address.
/// Direction (ingress or egress) is determined by the array used
/// (there's one for ingress and another for egress).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PacketEvent {
    /// Source IP address.
    pub src_addr: [u8; 16],
    /// Destination IP address.
    pub dst_addr: [u8; 16],
    /// Source port. Host endianness.
    pub src_port: u16,
    /// Destination port. Host endianness.
    pub dst_port: u16,
    /// Total packet length (including L3 and L4 headers).
    pub pkt_len: u16,
    /// Payload length (L4 specified length).
    pub payload_len: u16,
    /// Address family. 0 = IPv4, 1 = IPv6
    pub addr_type: u8,
    /// Protocol declared by IP header.
    pub protocol: u8,
    /// Padding. See below.
    pub _pad: [u8; 2],
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

/// Encodes IPv4 address to be used in [PacketEvent].
#[inline(always)]
pub fn encode_ip4_addr(addr: Ipv4Addr) -> [u8; 16] {
    let addr = addr.to_bits().to_be_bytes();
    let mut ret = [0u8; 16];
    ret[10] = 0xff;
    ret[11] = 0xff;
    ret[12..].copy_from_slice(&addr);
    ret
}

