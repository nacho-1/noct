use std::net::IpAddr;

use crate::utils;

/// Connection Smooth RTT value.
#[derive(Debug)]
#[cfg_attr(feature = "test-helpers", derive(Clone))]
pub struct ConnectionSRTT {
    /// Source IP address.
    pub src_addr: IpAddr,
    /// Destination IP address.
    pub dst_addr: IpAddr,
    /// Source port. Host endianness.
    pub src_port: u16,
    /// Destination port. Host endianness.
    pub dst_port: u16,
    /// Updated smooth round-time-trip.
    pub srtt: u32,
}

impl From<noct_common::ConnectionSRTT> for ConnectionSRTT {
    fn from(value: noct_common::ConnectionSRTT) -> Self {
        ConnectionSRTT {
            src_addr: utils::parse_addr(value.src_addr, value.addr_type),
            dst_addr: utils::parse_addr(value.dst_addr, value.addr_type),
            src_port: value.src_port,
            dst_port: value.dst_port,
            srtt: value.srtt,
        }
    }
}
