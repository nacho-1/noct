use core::fmt;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

/// Layer 4 protocol.
#[cfg_attr(feature = "test-helpers", derive(Clone, Debug, PartialEq))]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_tcp() {
        let proto = IpProto::TCP;

        assert_eq!(&proto.to_string(), "TCP");
    }

    #[test]
    fn test_display_udp() {
        let proto = IpProto::UDP;

        assert_eq!(&proto.to_string(), "UDP");
    }

    #[test]
    fn test_display_other() {
        let proto = IpProto::Other;

        assert_eq!(&proto.to_string(), "Other");
    }

    #[test]
    fn test_proto_from_tcp() {
        let proto = IpProto::from(IPPROTO_TCP);

        assert_eq!(proto, IpProto::TCP);
    }

    #[test]
    fn test_proto_from_udp() {
        let proto = IpProto::from(IPPROTO_UDP);

        assert_eq!(proto, IpProto::UDP);
    }

    #[test]
    fn test_proto_from_other() {
        let proto = IpProto::from(20);

        assert_eq!(proto, IpProto::Other);
    }
}
