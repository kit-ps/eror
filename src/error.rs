//! Error definitions.

/// Enum for all possible errors that can arise during onion forming and processing.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The given path is too long.
    ///
    /// Either construct the format with a bigger allowed path length, or reduce the number of hops
    /// you wish to encode.
    #[error("Path too long")]
    PathTooLong,

    /// The public key for a hop cannot be found in the given PKI.
    #[error("Requested public key not found")]
    KeyNotFound,

    /// The MAC of the onion does not match.
    #[error("MAC mismatch")]
    MacMismatch,

    /// You try to form a reply onion for an onion that you're not the recipient of.
    ///
    /// This fails because the necessary key material is not embedded.
    #[error("The handling node is not the receiver node")]
    NotTheReceiver,

    /// You try to access the backwards payload, but you're not the original sender of the onion.
    ///
    /// This fails because the necessary key material is not embedded.
    #[error("The handling node is not the original sender")]
    NotTheSender,

    /// The sender has received a reply for an onion for which it was not expecting a reply.
    #[error("The reply comes from an unknown onion")]
    UnexpectedReply,

    /// An error occurred while (de)serializing some underlying data.
    #[error("(De)serialization error")]
    SerializationError(#[from] bincode::Error),

    /// The authenticated decryption failed, likely because the payload has been tampered with.
    ///
    /// The contained value is an opaque error type.
    #[error("Authenticated Encryption error")]
    AeError,
}
