use crate::AddrType;

#[cfg_attr(feature = "test-helpers", derive(Clone))]
pub struct ConnectionCount {
    pub addr_type: AddrType,
    pub count: u32,
}

