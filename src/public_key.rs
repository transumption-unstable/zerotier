use arrayref::array_ref;
use hex::{FromHex, FromHexError};

use std::convert::TryFrom;
use std::str::FromStr;

use crate::SecretKey;

/// [`PublicKey`](struct.PublicKey.html) length in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 64;

/// Concatenation of an X25519 public key and an Ed25519 public key.
#[derive(Clone, Debug)]
pub struct PublicKey {
    /// X25519 public key (the first 32 bytes)
    pub x25519: x25519_dalek::PublicKey,
    /// Ed25519 public key (the last 32 bytes)
    pub ed25519: ed25519_dalek::VerifyingKey,
}

/// Error in [`PublicKey`](struct.PublicKey.html).
pub type PublicKeyError = ed25519_dalek::SignatureError;

/// Derives [`PublicKey`](struct.PublicKey.html) from
/// [`SecretKey`](struct.SecretKey.html).
impl From<&SecretKey> for PublicKey {
    fn from(secret_key: &SecretKey) -> Self {
        Self {
            x25519: x25519_dalek::PublicKey::from(&secret_key.x25519),
            ed25519: ed25519_dalek::VerifyingKey::from(&secret_key.ed25519),
        }
    }
}

/// Converts [`PublicKey`](struct.PublicKey.html) key into a byte array.
impl Into<[u8; PUBLIC_KEY_LENGTH]> for &PublicKey {
    fn into(self) -> [u8; PUBLIC_KEY_LENGTH] {
        let mut buf = [0u8; PUBLIC_KEY_LENGTH];

        buf[..32].copy_from_slice(self.x25519.as_bytes());
        buf[32..].copy_from_slice(self.ed25519.as_bytes());
        buf
    }
}

impl TryFrom<&[u8; PUBLIC_KEY_LENGTH]> for PublicKey {
    type Error = PublicKeyError;

    fn try_from(bytes: &[u8; PUBLIC_KEY_LENGTH]) -> Result<Self, Self::Error> {
        let x25519_bytes = array_ref![bytes, 0, 32];
        let ed25519_bytes = array_ref![bytes, 32, 32];

        Ok(Self {
            x25519: x25519_dalek::PublicKey::from(x25519_bytes.clone()),
            ed25519: ed25519_dalek::VerifyingKey::from_bytes(ed25519_bytes)?,
        })
    }
}

/// Error while reading [`PublicKey`](struct.PublicKey.html) from a byte slice.
#[derive(Debug)]
pub enum FromSlicePublicKeyError {
    /// Expected the slice to be [`PUBLIC_KEY_LENGTH`](constant.PUBLIC_KEY_LENGTH.html)
    /// bytes long, got this length instead.
    InvalidLength(usize),
    /// Error in [`PublicKey`](struct.PublicKey.html).
    PublicKeyError(PublicKeyError),
}

impl From<PublicKeyError> for FromSlicePublicKeyError {
    fn from(err: PublicKeyError) -> Self {
        Self::PublicKeyError(err)
    }
}

impl TryFrom<&[u8]> for PublicKey {
    type Error = FromSlicePublicKeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let length = bytes.len();

        if length == PUBLIC_KEY_LENGTH {
            Ok(Self::try_from(array_ref![bytes, 0, PUBLIC_KEY_LENGTH])?)
        } else {
            Err(Self::Error::InvalidLength(length))
        }
    }
}

/// Error while parsing [`PublicKey`](struct.PublicKey.html) from a string.
#[derive(Debug)]
pub enum FromStrPublicKeyError {
    /// Error while decoding the string.
    DecodeError(FromHexError),
    /// Expected the string to encode [`PUBLIC_KEY_LENGTH`](constant.PUBLIC_KEY_LENGTH.html)
    /// bytes, got this many bytes instead.
    InvalidByteLength(usize),
    /// Error in [`PublicKey`](struct.PublicKey.html).
    PublicKeyError(PublicKeyError),
}

impl From<FromHexError> for FromStrPublicKeyError {
    fn from(err: FromHexError) -> Self {
        Self::DecodeError(err)
    }
}

impl From<PublicKeyError> for FromStrPublicKeyError {
    fn from(err: PublicKeyError) -> Self {
        Self::PublicKeyError(err)
    }
}

impl From<FromSlicePublicKeyError> for FromStrPublicKeyError {
    fn from(err: FromSlicePublicKeyError) -> Self {
        match err {
            FromSlicePublicKeyError::InvalidLength(len) => Self::InvalidByteLength(len),
            FromSlicePublicKeyError::PublicKeyError(err) => err.into(),
        }
    }
}

impl FromHex for PublicKey {
    type Error = FromStrPublicKeyError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self::try_from(&<[u8; PUBLIC_KEY_LENGTH]>::from_hex(hex)?)?)
    }
}

impl FromStr for PublicKey {
    type Err = FromStrPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}
