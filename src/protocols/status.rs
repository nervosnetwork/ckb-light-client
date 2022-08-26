#![allow(dead_code)]
use std::{fmt, time::Duration};

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
pub enum StatusCode {
    /// OK
    OK = 200,

    /// Malformed protocol message.
    MalformedProtocolMessage = 400,
    /// Unexpected light-client protocol message.
    UnexpectedProtocolMessage = 401,

    /// The peer state is not found.
    PeerStateIsNotFound = 411,
    /// The last state sent from server is invalid.
    InvalidLastState = 412,

    /// Receives a proof but the peer isn't waiting for a proof.
    PeerIsNotOnProcess = 421,
    /// Failed to verify chain roots for samples.
    InvalidChainRootForSamples = 422,
    /// Failed to verify total difficulty for samples.
    InvalidTotalDifficultyForSamples = 423,
    /// Failed to verify the compact target.
    InvalidCompactTarget = 424,
    /// Failed to verify the total difficulty.
    InvalidTotalDifficulty = 425,
    /// Failed to verify the pow.
    InvalidNonce = 426,
    /// The last header number in reorg_last_n_headers is wrong
    InvalidReorgHeaders = 427,
    /// Failed to verify the parent hash.
    InvalidParentHash = 428,
    /// Failed to verify the proof.
    FailedToVerifyTheProof = 429,
    /// Invalid SendBlocksProof response (not match the GetBlocksProof request)
    InvalidSendBlocksProof = 430,

    /// Throws an internal error.
    InternalError = 500,
    /// Throws an error from the network.
    Network = 501,
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
        self.code == StatusCode::OK
    }

    /// Whether the session should be banned.
    pub fn should_ban(&self) -> Option<Duration> {
        let code = self.code as u16;
        if (400..500).contains(&code) {
            Some(BAD_MESSAGE_BAN_TIME)
        } else {
            None
        }
    }

    /// Whether a warning log should be output.
    pub fn should_warn(&self) -> bool {
        let code = self.code as u16;
        (500..600).contains(&code)
    }

    /// Returns the status code.
    pub fn code(&self) -> StatusCode {
        self.code
    }
}
