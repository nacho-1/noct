use std::net::IpAddr;

use crate::utils;

/// Connection Smooth RTT value.
#[derive(Debug)]
#[cfg_attr(feature = "test-helpers", derive(Clone))]
pub struct ConnectionRetrans {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub segments: u32,
}

impl From<noct_common::ConnectionRetrans> for ConnectionRetrans {
    fn from(value: noct_common::ConnectionRetrans) -> Self {
        ConnectionRetrans {
            src_addr: utils::parse_addr(value.src_addr, value.addr_type),
            dst_addr: utils::parse_addr(value.dst_addr, value.addr_type),
            src_port: value.src_port,
            dst_port: value.dst_port,
            segments: value.segments,
        }
    }
}
