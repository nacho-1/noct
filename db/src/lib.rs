use core::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

use either::Either;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Packet event structure for userspace use.
///
/// Distintion from [noct_common::PacketEvent] to not get tied to that one's restrictions.
pub struct PacketEvent {
    /// Source IP address.
    pub src_addr: Either<Ipv4Addr, Ipv6Addr>,
    /// Destination IP address.
    pub dst_addr: Either<Ipv4Addr, Ipv6Addr>,
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
            src_addr: Either::Left(value.src_addr),
            dst_addr: Either::Left(value.dst_addr),
            src_port: value.src_port,
            dst_port: value.dst_port,
            pkt_len: value.pkt_len,
            payload_len: value.payload_len,
            protocol: IpProto::from(value.protocol),
        }
    }
}

/// Layer 4 protocol.
pub enum IpProto {
    TCP,
    UDP,
    Other,
}

impl From<u8> for IpProto {
    fn from(value: u8) -> Self {
        match value {
            IPPROTO_TCP => IpProto::TCP,
            IPPROTO_UDP => IpProto::UDP,
            _ => IpProto::Other,
        }
    }
}

impl fmt::Display for IpProto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpProto::TCP => write!(f, "TCP"),
            IpProto::UDP => write!(f, "UDP"),
            IpProto::Other => write!(f, "Other"),
        }
    }
}
