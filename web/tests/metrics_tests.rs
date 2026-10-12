use std::net::Ipv4Addr;

use either::Either;
use hyper::StatusCode;
use noct_db::{EventMsg, IpProto, PacketEvent};
use noct_web::test_helpers::{BodyExt, RouterExt, TestContext};
use tokio::sync::{mpsc::UnboundedSender, oneshot};

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

async fn send_event(event: PacketEvent, tx: &UnboundedSender<EventMsg<PacketEvent>>) {
    let (ack_rx, ack_tx) = oneshot::channel();
    let msg = EventMsg::with_ack(event, ack_rx);
    tx.send(msg).unwrap();
    ack_tx.await.expect("must receive ACK");
}

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
    send_event(event, &context.ingress_stats_tx).await;

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

#[noct_macros::test]
async fn test_outgoing_tcp(context: &TestContext) {
    let event = PacketEvent {
        pkt_len: 42,
        payload_len: 2,
        protocol: IpProto::TCP,
        ..TEMPLATE_PACKET_EVENT
    };
    send_event(event, &context.egress_stats_tx).await;

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
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"TCP\"} 42"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"UDP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"Other\"} 0"));
}

#[noct_macros::test]
async fn test_tcp_handshake(context: &TestContext) {
    let syn = PacketEvent {
        pkt_len: 60,
        payload_len: 0,
        protocol: IpProto::TCP,
        ..TEMPLATE_PACKET_EVENT
    };
    let syn_ack = PacketEvent {
        pkt_len: 60,
        payload_len: 0,
        protocol: IpProto::TCP,
        ..TEMPLATE_PACKET_EVENT
    };
    let ack = PacketEvent {
        pkt_len: 52,
        payload_len: 0,
        protocol: IpProto::TCP,
        ..TEMPLATE_PACKET_EVENT
    };
    tokio::join!(
        send_event(syn, &context.ingress_stats_tx),
        send_event(syn_ack, &context.egress_stats_tx),
        send_event(ack, &context.ingress_stats_tx),
    );

    let response = context
        .app
        .request("/metrics")
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"TCP\"} 112"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"UDP\"} 0"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"Other\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"TCP\"} 60"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"UDP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"Other\"} 0"));
}

#[noct_macros::test]
async fn test_metrics_udp(context: &TestContext) {
    send_event(TEMPLATE_PACKET_EVENT, &context.ingress_stats_tx).await;
    send_event(TEMPLATE_PACKET_EVENT, &context.egress_stats_tx).await;

    let response = context
        .app
        .request("/metrics")
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"TCP\"} 0"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"UDP\"} 30"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"Other\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"TCP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"UDP\"} 30"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"Other\"} 0"));
}

#[noct_macros::test]
async fn test_metrics_other_protocol(context: &TestContext) {
    let event = PacketEvent {
        protocol: IpProto::Other,
        ..TEMPLATE_PACKET_EVENT
    };
    send_event(event.clone(), &context.ingress_stats_tx).await;
    send_event(event.clone(), &context.egress_stats_tx).await;

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
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"Other\"} 30"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"TCP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"UDP\"} 0"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"Other\"} 30"));
}

#[noct_macros::test]
async fn test_multiple_protocols(context: &TestContext) {
    let tcp_event = PacketEvent {
        pkt_len: 42,
        payload_len: 2,
        protocol: IpProto::TCP,
        ..TEMPLATE_PACKET_EVENT
    };
    let other_proto_event = PacketEvent {
        protocol: IpProto::Other,
        ..TEMPLATE_PACKET_EVENT
    };
    tokio::join!(
        send_event(TEMPLATE_PACKET_EVENT, &context.ingress_stats_tx),
        send_event(TEMPLATE_PACKET_EVENT, &context.egress_stats_tx),
        send_event(tcp_event.clone(), &context.ingress_stats_tx),
        send_event(tcp_event, &context.egress_stats_tx),
        send_event(other_proto_event.clone(), &context.ingress_stats_tx),
        send_event(other_proto_event, &context.egress_stats_tx),
    );

    let response = context
        .app
        .request("/metrics")
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"TCP\"} 42"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"UDP\"} 30"));
    assert!(metrics.contains("incoming_traffic_bytes{protocol=\"Other\"} 30"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"TCP\"} 42"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"UDP\"} 30"));
    assert!(metrics.contains("outgoing_traffic_bytes{protocol=\"Other\"} 30"));
}

