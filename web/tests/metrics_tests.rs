use std::net::Ipv4Addr;

use either::Either;
use hyper::StatusCode;
use noct_db::{EventMsg, IpProto, PacketEvent};
use noct_web::test_helpers::{BodyExt, RouterExt, TestContext};
use tokio::sync::oneshot;

const TEMPLATE_PACKET_EVENT: PacketEvent =
    PacketEvent {
        src_addr: Either::Left(Ipv4Addr::new(192, 168, 0, 1)),
        dst_addr: Either::Left(Ipv4Addr::new(192, 168, 0, 2)),
        src_port: 12345,
        dst_port: 54321,
        pkt_len: 30,
        payload_len: 2,
        protocol: IpProto::UDP,
    };

#[noct_macros::test]
async fn test_empty_metrics(context: &TestContext) {
    let response = context
        .app
        .request("/metrics")
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"TCP\"} 0"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"UDP\"} 0"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"Other\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"TCP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"UDP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"Other\"} 0"));
}

#[noct_macros::test]
async fn test_incoming_tcp(context: &TestContext) {
    let event = PacketEvent {
        pkt_len: 42,
        payload_len: 2,
        protocol: IpProto::TCP,
        ..TEMPLATE_PACKET_EVENT
    };
    let (ack_rx, ack_tx) = oneshot::channel();
    let msg = EventMsg::with_ack(event, ack_rx);

    context.ingress_stats_tx.send(msg).unwrap();
    ack_tx.await.expect("must receive ACK");

    let response = context
        .app
        .request("/metrics")
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"TCP\"} 42"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"UDP\"} 0"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"Other\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"TCP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"UDP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"Other\"} 0"));
}
