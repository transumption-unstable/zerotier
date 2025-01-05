use arrayref::array_ref;
use hex::{FromHex, FromHexError};

use std::str::FromStr;

/// [`SecretKey`](struct.SecretKey.html) length in bytes.
pub const SECRET_KEY_LENGTH: usize = 64;

/// Concatenation of an X25519 secret key and an Ed25519 secret key.
pub struct SecretKey {
    /// X25519 secret key (the first 32 bytes)
    pub x25519: x25519_dalek::StaticSecret,
    /// Ed25519 secret key (the last 32 bytes)
    pub ed25519: ed25519_dalek::SigningKey,
}

impl From<&[u8; SECRET_KEY_LENGTH]> for SecretKey {
    fn from(bytes: &[u8; SECRET_KEY_LENGTH]) -> Self {
        let x25519_bytes = array_ref![bytes, 0, 32];
        let ed25519_bytes = array_ref![bytes, 32, 32];

        Self {
            x25519: x25519_dalek::StaticSecret::from(x25519_bytes.clone()),
            ed25519: ed25519_dalek::SigningKey::from_bytes(ed25519_bytes),
        }
    }
}

/// Error while reading [`SecretKey`](struct.SecretKey.html) from a byte slice.
#[derive(Debug)]
pub enum FromSliceSecretKeyError {
    /// Expected the slice to be [`SECRET_KEY_LENGTH`](constant.SECRET_KEY_LENGTH.html)
    /// bytes long, got this length instead.
    InvalidLength(usize),
}

impl TryFrom<&[u8]> for SecretKey {
    type Error = FromSliceSecretKeyError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let length = bytes.len();

        if length == SECRET_KEY_LENGTH {
            Ok(Self::from(array_ref![bytes, 0, SECRET_KEY_LENGTH]))
        } else {
            Err(Self::Error::InvalidLength(length))
        }
    }
}

/// Error while parsing [`SecretKey`](struct.SecretKey.html) from a string.
#[derive(Debug)]
pub enum FromStrSecretKeyError {
    /// Error while decoding the string.
    DecodeError(FromHexError),
    /// Expected the string to encode [`SECRET_KEY_LENGTH`](constant.SECRET_KEY_LENGTH.html)
    /// bytes, got this many bytes instead.
    InvalidByteLength(usize),
}

impl From<FromHexError> for FromStrSecretKeyError {
    fn from(err: FromHexError) -> Self {
        Self::DecodeError(err)
    }
}

impl From<FromSliceSecretKeyError> for FromStrSecretKeyError {
    fn from(err: FromSliceSecretKeyError) -> Self {
        match err {
            FromSliceSecretKeyError::InvalidLength(len) => Self::InvalidByteLength(len),
        }
    }
}

impl FromHex for SecretKey {
    type Error = FromStrSecretKeyError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self::from(&<[u8; SECRET_KEY_LENGTH]>::from_hex(hex)?))
    }
}

impl FromStr for SecretKey {
    type Err = FromStrSecretKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}
