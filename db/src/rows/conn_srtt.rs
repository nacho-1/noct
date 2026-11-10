use std::net::IpAddr;

/// Connection Smooth RTT value.
#[derive(Debug)]
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

impl From<noct_models::ConnectionSRTT> for ConnectionSRTT {
    fn from(value: noct_models::ConnectionSRTT) -> Self {
        ConnectionSRTT {
            src_addr: value.src_addr,
            dst_addr: value.dst_addr,
            src_port: value.src_port,
            dst_port: value.dst_port,
            srtt: value.srtt,
        }
    }
}
