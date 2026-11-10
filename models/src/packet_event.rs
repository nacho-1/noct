use std::net::IpAddr;

use crate::{IpProto, utils};

/// Packet event structure for userspace use.
///
/// Distintion from [noct_common::PacketEvent] to not get tied to that one's restrictions.
#[cfg_attr(feature = "test-helpers", derive(Clone))]
pub struct PacketEvent {
    /// Source IP address.
    pub src_addr: IpAddr,
    /// Destination IP address.
    pub dst_addr: IpAddr,
    /// Source port. Host endianness.
    pub src_port: u16,
    /// Destination port. Host endianness.
    pub dst_port: u16,
    /// Total packet length (including L3 and L4 headers).
    pub pkt_len: u16,
    /// Payload length (L4 specified length).
    pub payload_len: u16,
    /// L4 protocol.
    pub protocol: IpProto,
}

impl From<noct_common::PacketEvent> for PacketEvent {
    fn from(value: noct_common::PacketEvent) -> Self {
        PacketEvent {
            src_addr: utils::parse_addr(value.src_addr, value.addr_type),
            dst_addr: utils::parse_addr(value.dst_addr, value.addr_type),
            src_port: value.src_port,
            dst_port: value.dst_port,
            pkt_len: value.pkt_len,
            payload_len: value.payload_len,
            protocol: IpProto::from(value.protocol),
        }
    }
}
