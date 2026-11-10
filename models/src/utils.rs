use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub mod event_msg;

pub fn parse_addr(raw_addr: [u8; 16], addr_type: u8) -> IpAddr {
    match addr_type {
        noct_common::IP4_ADDR_TYPE => {
            IpAddr::V4(Ipv4Addr::from_octets(raw_addr[12..16].try_into().unwrap()))
        }
        noct_common::IP6_ADDR_TYPE => IpAddr::V6(Ipv6Addr::from_octets(raw_addr)),
        _ => panic!("bad addr type: {addr_type}"),
    }
}
