use tokio::sync::mpsc::Sender;
use tokio::sync::oneshot;

use super::WindowSizeRef;
use crate::ChannelMsg;

/// A handle to the [`super::Channel`]'s to be able to transmit messages
/// to it and update it's `window_size`.
#[derive(Debug)]
pub struct ChannelRef {
    pub(super) sender: Sender<ChannelMsg>,
    pub(super) window_size: WindowSizeRef,
    // Populated by the `Handle` side when it creates a ChannelRef for an
    // outgoing open request. The session task fires the dedicated per-channel
    // tracing span through it when CHANNEL_OPEN_CONFIRMATION arrives, so the
    // receiving `Channel` ends up with a span created under the correct
    // `ssh.session` parent — not whatever span the Handle caller happened to
    // be in.
    pub(crate) span_tx: Option<oneshot::Sender<tracing::Span>>,
}

impl ChannelRef {
    pub fn new(sender: Sender<ChannelMsg>) -> Self {
        Self {
            sender,
            window_size: WindowSizeRef::new(0),
            span_tx: None,
        }
    }

    /// Create a ChannelRef and a oneshot receiver that will resolve to the
    /// channel's tracing span once the session task confirms the open.
    pub(crate) fn with_span_tx(sender: Sender<ChannelMsg>) -> (Self, oneshot::Receiver<tracing::Span>) {
        let (span_tx, span_rx) = oneshot::channel();
        (
            Self {
                sender,
                window_size: WindowSizeRef::new(0),
                span_tx: Some(span_tx),
            },
            span_rx,
        )
    }

    pub(crate) fn window_size(&self) -> &WindowSizeRef {
        &self.window_size
    }
}

impl std::ops::Deref for ChannelRef {
    type Target = Sender<ChannelMsg>;

    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}
