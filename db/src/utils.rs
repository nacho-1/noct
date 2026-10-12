#[cfg(feature = "test-helpers")]
use tokio::sync::oneshot;

/// Wraper for communicating events through channels.
///
/// Necessary to be able to sync via acknowledgements.
pub struct EventMsg<T> {
    /// The event to communicate.
    pub event: T,
    /// One shot for responding with acknowledgements.
    /// Only available when compiling for tests.
    #[cfg(feature = "test-helpers")]
    pub ack: Option<oneshot::Sender<()>>,
}

impl<T> EventMsg<T> {
    /// Create a new message.
    ///
    /// Meant to be used by the application.
    pub fn new(event: T) -> Self {
        Self {
            event,
            #[cfg(feature = "test-helpers")]
            ack: None,
        }
    }

    /// Create a new message with a channel for the response.
    ///
    /// Meant to be used by tests.
    #[cfg(feature = "test-helpers")]
    pub fn with_ack(event: T, ack: oneshot::Sender<()>) -> Self {
        Self {
            event,
            ack: Some(ack),
        }
    }
}
