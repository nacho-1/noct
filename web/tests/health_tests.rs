use hyper::StatusCode;
use noct_web::test_helpers::{BodyExt, RouterExt, TestContext};
use serde_json::Value;

#[noct_macros::test]
async fn test_ok_health(context: &TestContext) {
    let response = context.app.request("/health").send().await;

    assert_eq!(response.status(), StatusCode::OK);
}

#[noct_macros::test]
async fn test_fallback(context: &TestContext) {
    let response = context.app.request("/unknown").send().await;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    let body_bytes = response.into_body().into_bytes().await;
    let json: Value = serde_json::from_slice(&body_bytes).unwrap();

    let expected = serde_json::json!({
        "type": "about:blank",
        "title": "No route /unknown",
        "detail": "Couldn't find the route /unknown",
    });

    assert_eq!(json, expected);
}
