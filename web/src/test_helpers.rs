use axum::{Router, body::{Body, Bytes}, http::{HeaderName, Request}, response::Response};
use hyper::{HeaderMap, Method};
use tower::ServiceExt;

use crate::routes;

/// A request that a test sends to the application.
///
/// The requests are constructed via the test context (see [TestContext]).
pub struct TestRequest {
    router: Router,
    uri: String,
    method: Method,
    headers: HeaderMap,
    body: Body,
}

impl TestRequest {
    fn new(router: Router, uri: &str) -> Self {
        Self {
            router,
            uri: String::from(uri),
            headers: HeaderMap::new(),
            body: Body::empty(),
            method: Method::GET,
        }
    }

    /// Sets the HTTP method for the request. See [axum::http::Method].
    #[allow(unused)]
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Adds an HTTP header to the request.
    ///
    /// Header names must be passed as [axum::http::HeaderName]
    /// while values can be passed as [&str].
    #[allow(unused)]
    pub fn header(mut self, name: HeaderName, value: &str) -> Self {
        self.headers.insert(name, value.parse().unwrap());
        self
    }

    /// Sets the body for the request.
    #[allow(unused)]
    pub fn body(mut self, body: Body) -> Self {
        self.body = body;
        self
    }

    /// Sends the request to the application under test.
    #[allow(unused)]
    pub async fn send(self) -> Response {
        let mut request_builder = Request::builder().uri(&self.uri);

        for (key, value) in &self.headers {
            request_builder = request_builder.header(key, value);
        }

        request_builder = request_builder.method(&self.method);

        let request = request_builder.body(self.body);

        self.router.oneshot(request.unwrap()).await.unwrap()
    }
}

/// Testing convenience for [axum::Router].
pub trait RouterExt {
    /// Creates a [TestRequest] pointed at the application under test.
    #[allow(unused)]
    fn request(&self, uri: &str) -> TestRequest;
}

impl RouterExt for Router {
    #[allow(unused)]
    fn request(&self, uri: &str) -> TestRequest {
        TestRequest::new(self.clone(), uri)
    }
}

/// Testing convenience for [axum::body::Body].
pub trait BodyExt {
    /// Returns the body as raw bytes.
    #[allow(unused, async_fn_in_trait)]
    async fn into_bytes(self) -> Bytes;

    /// Returns the body parsed as JSON.
    #[allow(unused, async_fn_in_trait)]
    async fn into_json<T>(self) -> T
    where
        T: serde::de::DeserializeOwned;
}

impl BodyExt for Body {
    #[allow(unused)]
    async fn into_bytes(self) -> Bytes {
        // Don't care about the size limit in tests.
        axum::body::to_bytes(self, usize::MAX)
            .await
            .expect("failed to read response body")
    }

    #[allow(unused)]
    async fn into_json<T>(self) -> T
    where
        T: serde::de::DeserializeOwned
    {
        let body = self.into_bytes().await;
        serde_json::from_slice::<T>(&body).expect("failed to deserialize JSON body")
    }
}

/// Provides context information for application tests.
///
/// A [TestContext] is passed as an argument to tests marked with the [noct_macros::test] attribute
/// macro. It is used to access the application under test.
pub struct TestContext {
    /// The application that is being tested.
    pub app: Router,
}

/// Sets up a test and returns a [TestContext].
///
/// This function initializes a new instance of the application.
///
/// This function is not invoked directly but used inside of the [noct_macros::test] attribute
/// macro. The test context is automatically passed to test cases marked with that macro.
pub async fn setup() -> TestContext {
    let app = routes::init_routes();

    TestContext { app }
}
