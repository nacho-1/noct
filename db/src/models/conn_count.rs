use crate::AddrType;

/// Structure for communicating number of active connections in userspace.
#[cfg_attr(feature = "test-helpers", derive(Clone))]
pub struct ConnectionCount {
    /// L3 protocol for the connections.
    pub addr_type: AddrType,
    /// Number of connections.
    pub count: u32,
}

