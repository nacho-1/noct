use std::net::{IpAddr, Ipv4Addr};

use noct_db::{EventMsg, IpProto, PacketEvent};
use tokio::sync::{mpsc::UnboundedSender, oneshot};

/// Template simple packet event.
///
/// IPv4 + UDP packet.
#[allow(dead_code)] // giving me the warning even tho I'm using it.
pub const TEMPLATE_PACKET_EVENT: PacketEvent = PacketEvent {
    src_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
    dst_addr: IpAddr::V4(Ipv4Addr::new(192, 168, 0, 2)),
    src_port: 12345,
    dst_port: 54321,
    pkt_len: 30,
    payload_len: 2,
    protocol: IpProto::UDP,
};

/// Sends event down the channel and awaits the ACK.
pub async fn send_event<T>(event: T, tx: &UnboundedSender<EventMsg<T>>) {
    let (ack_rx, ack_tx) = oneshot::channel();
    let msg = EventMsg::with_ack(event, ack_rx);
    tx.send(msg).unwrap();
    ack_tx.await.expect("must receive ACK");
}

