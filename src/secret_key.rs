use crate::InternalError;

use arrayref::array_ref;
use failure::Error;
use std::convert::TryFrom;

/// [`SecretKey`](struct.SecretKey.html) length in bytes.
pub const SECRET_KEY_LENGTH: usize = 64;

/// Concatenation of X25519 static secret (first 32 bytes) and Ed25519 secret key (last 32 bytes).
pub struct SecretKey {
    pub ed: ed25519_dalek::SigningKey,
    pub dh: x25519_dalek::StaticSecret,
}

impl From<[u8; SECRET_KEY_LENGTH]> for SecretKey {
    fn from(bytes: [u8; SECRET_KEY_LENGTH]) -> Self {
        Self {
            ed: ed25519_dalek::SigningKey::from_bytes(array_ref![bytes, 32, 32]),
            dh: x25519_dalek::StaticSecret::from(array_ref![bytes, 0, 32].clone()),
        }
    }
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != SECRET_KEY_LENGTH {
            Err(InternalError::BytesLengthError.into())
        } else {
            Ok(Self {
                ed: ed25519_dalek::SigningKey::from_bytes(array_ref![bytes, 32, 32]),
                dh: x25519_dalek::StaticSecret::from(array_ref![bytes, 0, 32].clone()),
            })
        }
    }
}
