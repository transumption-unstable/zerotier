use crate::{InternalError, SecretKey};

use arrayref::array_ref;
use failure::Error;
use std::convert::TryFrom;

/// [`PublicKey`](struct.PublicKey.html) length in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 64;

/// Concatenation of X25519 public key (first 32 bytes) and Ed25519 public key (last 32 bytes).
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// Ed25519 public key (last 32 bytes)
    pub ed: ed25519_dalek::VerifyingKey,
    /// X25519 public key (first 32 bytes)
    pub dh: x25519_dalek::PublicKey,
}

/// Derive public key from secret key.
impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        Self {
            ed: ed25519_dalek::VerifyingKey::from(&secret_key.ed),
            dh: x25519_dalek::PublicKey::from(&secret_key.dh),
        }
    }
}

/// Construct a public key from a slice of bytes, fails if `len(bytes) != 64`.
impl TryFrom<&[u8]> for PublicKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != PUBLIC_KEY_LENGTH {
            Err(InternalError::BytesLengthError.into())
        } else {
            Ok(Self {
                ed: ed25519_dalek::VerifyingKey::from_bytes(array_ref![bytes, 32, 32])?,
                dh: x25519_dalek::PublicKey::from(array_ref![bytes, 0, 32].clone()),
            })
        }
    }
}

/// Convert this public key into a byte array.
impl Into<[u8; PUBLIC_KEY_LENGTH]> for &PublicKey {
    fn into(self) -> [u8; PUBLIC_KEY_LENGTH] {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH];

        buf[..32].copy_from_slice(self.dh.as_bytes());
        buf[32..].copy_from_slice(self.ed.as_bytes());
        buf
    }
}
