use std::{fmt, sync::Arc, time::Duration};

use ckb_network::{CKBProtocolContext, PeerIndex};
use log::{debug, error, trace, warn};

use super::BAD_MESSAGE_BAN_TIME;

/// StatusCodes indicate whether a specific operation has been successfully completed.
///
/// The StatusCode element is a 3-digit integer.
///
/// The first digest of the StatusCode defines the class of result:
///   - 1xx: Informational response – the request was received, continuing process.
///   - 2xx: Success - The action requested by the client was received, understood, and accepted.
///   - 4xx: Remote errors - The error seems to have been caused by the remote (the server).
///   - 5xx: Local errors - The client failed to process a response.
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum StatusCode {
    /// OK
    OK = 200,
    /// Require re-check.
    RequireRecheck = 201,

    /// Malformed protocol message.
    MalformedProtocolMessage = 400,
    /// Unexpected light-client protocol message.
    UnexpectedProtocolMessage = 401,

    /// The peer is not found.
    PeerIsNotFound = 411,
    /// The last state sent from server is invalid.
    InvalidLastState = 412,
    /// The peer state is not correct for transition.
    IncorrectLastState = 413,
    /// The peer is still in initial block download with a very high probability.
    PeerIsInIBD = 414,

    /// Receives a response but the peer isn't waiting for a response.
    PeerIsNotOnProcess = 421,
    /// The response is not match our request.
    UnexpectedResponse = 422,

    // Common errors for all verifications.
    /// Failed to verify chain root.
    InvalidChainRoot = 431,
    /// Failed to verify the pow.
    InvalidNonce = 432,
    /// Failed to verify the compact target.
    InvalidCompactTarget = 433,
    /// Failed to verify the total difficulty.
    InvalidTotalDifficulty = 434,
    /// Failed to verify the parent block.
    InvalidParentBlock = 435,
    /// Failed to verify the proof.
    InvalidProof = 439,

    // Specific errors for specific messages.
    /// Samples for a last state proof is invalid.
    InvalidSamples = 451,
    /// Reorg headers for a last state proof is invalid.
    InvalidReorgHeaders = 452,

    // Errors for block filter protocol.
    /// Check points is empty.
    CheckPointsIsEmpty = 471,
    /// Check points is unaligned.
    CheckPointsIsUnaligned = 472,
    /// Check points is unexpected.
    CheckPointsIsUnexpected = 473,
    /// Block filter hashes is empty.
    BlockFilterHashesIsEmpty = 481,
    /// Block filter hashes is unexpected.
    BlockFilterHashesIsUnexpected = 482,
    /// Block filter data is unexpected.
    BlockFilterDataIsUnexpected = 483,

    /// Throws an internal error.
    InternalError = 500,
    /// Throws an error from the network.
    Network = 501,

    /// Throws an error that could be ignored.
    Ignore = 599,
}

/// Process message status.
#[derive(Clone, Debug, Eq)]
pub struct Status {
    code: StatusCode,
    context: Option<String>,
}

macro_rules! return_if_failed {
    ($result:expr) => {
        match $result {
            Ok(data) => data,
            Err(status) => return status,
        }
    };
}

#[cfg(test)]
impl Default for StatusCode {
    fn default() -> Self {
        StatusCode::OK
    }
}

impl PartialEq for Status {
    fn eq(&self, other: &Self) -> bool {
        self.code == other.code
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.context {
            Some(ref context) => write!(f, "{:?}({}): {}", self.code, self.code as u16, context),
            None => write!(f, "{:?}({})", self.code, self.code as u16),
        }
    }
}

impl From<StatusCode> for Status {
    fn from(code: StatusCode) -> Self {
        Self::new::<&str>(code, None)
    }
}

impl StatusCode {
    /// Convert a status code into a status which has a context.
    pub fn with_context<S: ToString>(self, context: S) -> Status {
        Status::new(self, Some(context))
    }
}

impl Status {
    /// Creates a new status.
    pub fn new<T: ToString>(code: StatusCode, context: Option<T>) -> Self {
        Self {
            code,
            context: context.map(|c| c.to_string()),
        }
    }

    /// Returns a `OK` status.
    pub fn ok() -> Self {
        Self::new::<&str>(StatusCode::OK, None)
    }

    /// Whether the code is `OK` or not.
    pub fn is_ok(&self) -> bool {
        let code = self.code();
        code == StatusCode::OK || code == StatusCode::RequireRecheck
    }

    /// Whether the session should be banned.
    pub fn should_ban(&self) -> Option<Duration> {
        let code = self.code() as u16;
        if (400..500).contains(&code) {
            Some(BAD_MESSAGE_BAN_TIME)
        } else {
            None
        }
    }

    /// Whether a warning log should be output.
    pub fn should_warn(&self) -> bool {
        let code = self.code() as u16;
        (500..600).contains(&code)
    }

    /// Returns the status code.
    pub fn code(&self) -> StatusCode {
        self.code
    }

    pub fn process(
        &self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        index: PeerIndex,
        protocol: &str,
        message: &str,
    ) {
        if let Some(ban_time) = self.should_ban() {
            error!(
                "{}Protocol.received {} from {}, result {}, ban {:?}",
                protocol, message, index, self, ban_time
            );
            nc.ban_peer(index, ban_time, self.to_string());
        } else if self.should_warn() {
            warn!(
                "{}Protocol.received {} from {}, result {}",
                protocol, message, index, self
            );
        } else if self.is_ok() {
            trace!(
                "{}Protocol.received {} from {}, result {}",
                protocol,
                message,
                index,
                self
            );
        } else {
            debug!(
                "{}Protocol.received {} from {}, result {}",
                protocol, message, index, self
            );
        }
    }
}
