use hyper::StatusCode;
use noct_db::ConnectionCount;
use noct_web::test_helpers::{BodyExt, RouterExt, TestContext};

use crate::common::send_event;

mod common;

#[noct_macros::test]
async fn test_single_connection_ip4(context: &TestContext) {
    let event = ConnectionCount {
        addr_type: noct_db::AddrType::IPv4,
        count: 1,
    };
    send_event(event, &context.conn_count_tx).await;

    let response = context.app.request("/metrics").send().await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("active_connections{addressing=\"IPv4\"} 1"));
    assert!(metrics.contains("active_connections{addressing=\"IPv6\"} 0"));
}

#[noct_macros::test]
async fn test_single_connection_ip6(context: &TestContext) {
    let event = ConnectionCount {
        addr_type: noct_db::AddrType::IPv6,
        count: 1,
    };
    send_event(event, &context.conn_count_tx).await;

    let response = context.app.request("/metrics").send().await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("active_connections{addressing=\"IPv4\"} 0"));
    assert!(metrics.contains("active_connections{addressing=\"IPv6\"} 1"));
}

#[noct_macros::test]
async fn test_multiple_connections(context: &TestContext) {
    let event1 = ConnectionCount {
        addr_type: noct_db::AddrType::IPv4,
        count: 3,
    };
    let event2 = ConnectionCount {
        addr_type: noct_db::AddrType::IPv6,
        count: 2,
    };
    send_event(event1, &context.conn_count_tx).await;
    send_event(event2, &context.conn_count_tx).await;

    let response = context.app.request("/metrics").send().await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("active_connections{addressing=\"IPv4\"} 3"));
    assert!(metrics.contains("active_connections{addressing=\"IPv6\"} 2"));
}

#[noct_macros::test]
async fn test_connections_ending(context: &TestContext) {
    let event1 = ConnectionCount {
        addr_type: noct_db::AddrType::IPv4,
        count: 1,
    };
    let event2 = ConnectionCount {
        addr_type: noct_db::AddrType::IPv6,
        count: 1,
    };
    send_event(event1, &context.conn_count_tx).await;
    send_event(event2, &context.conn_count_tx).await;

    let response = context.app.request("/metrics").send().await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("active_connections{addressing=\"IPv4\"} 1"));
    assert!(metrics.contains("active_connections{addressing=\"IPv6\"} 1"));

    let event1 = ConnectionCount {
        addr_type: noct_db::AddrType::IPv4,
        count: 0,
    };
    let event2 = ConnectionCount {
        addr_type: noct_db::AddrType::IPv6,
        count: 0,
    };
    send_event(event1, &context.conn_count_tx).await;
    send_event(event2, &context.conn_count_tx).await;

    let response = context.app.request("/metrics").send().await;

    assert_eq!(response.status(), StatusCode::OK);

    let metrics = response.into_body().into_bytes().await;
    let metrics = String::from_utf8(metrics.to_vec()).unwrap();

    assert!(metrics.contains("active_connections{addressing=\"IPv4\"} 0"));
    assert!(metrics.contains("active_connections{addressing=\"IPv6\"} 0"));
}

