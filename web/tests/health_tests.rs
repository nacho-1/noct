use hyper::StatusCode;
use noct_web::test_helpers::{RouterExt, TestContext};

#[noct_macros::test]
async fn test_ok_health(context: &TestContext) {
    let response = context
        .app
        .request("/health")
        .send()
        .await;

    assert_eq!(response.status(), StatusCode::OK);
}
