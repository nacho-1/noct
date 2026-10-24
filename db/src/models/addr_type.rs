use core::fmt;

#[cfg_attr(feature = "test-helpers", derive(Clone))]
pub enum AddrType {
    IPv4,
    IPv6,
}

impl fmt::Display for AddrType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddrType::IPv4 => write!(f, "IPv4"),
            AddrType::IPv6 => write!(f, "IPv6"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_ipv4() {
        let addr = AddrType::IPv4;

        assert_eq!(&addr.to_string(), "IPv4");
    }

    #[test]
    fn test_display_ipv6() {
        let addr = AddrType::IPv6;

        assert_eq!(&addr.to_string(), "IPv6");
    }

}
