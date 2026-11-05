use std::net::IpAddr;

/// Connection retransmissions.
#[derive(Debug)]
pub struct ConnectionRetrans {
    /// Source IP address.
    pub src_addr: IpAddr,
    /// Destination IP address.
    pub dst_addr: IpAddr,
    /// Source port. Host endianness.
    pub src_port: u16,
    /// Destination port. Host endianness.
    pub dst_port: u16,
    /// Number of TCP segments retransmitted.
    pub segments: u32,
}

impl From<noct_models::ConnectionRetrans> for ConnectionRetrans {
    fn from(value: noct_models::ConnectionRetrans) -> Self {
        ConnectionRetrans {
            src_addr: value.src_addr,
            dst_addr: value.dst_addr,
            src_port: value.src_port,
            dst_port: value.dst_port,
            segments: value.segments,
        }
    }
}
