use arrayref::array_ref;

use std::num::ParseIntError;
use std::str::FromStr;

/// [`IdentityType`](struct.IdentityType.html) length in bytes.
pub const IDENTITY_TYPE_LENGTH: usize = 1;

/// ZeroTier identity type.
#[derive(Debug)]
pub struct IdentityType(u8);

impl IdentityType {
    /// Returns [`IdentityType`](struct.IdentityType.html).
    pub fn new() -> Self {
        Self(0)
    }
}

/// Error in [`IdentityType`](struct.IdentityType.html).
#[derive(Debug)]
pub enum IdentityTypeError {
    /// Expected identity type 0, got this identity type instead.
    Unknown(IdentityType),
}

impl TryFrom<u8> for IdentityType {
    type Error = IdentityTypeError;

    fn try_from(n: u8) -> Result<Self, Self::Error> {
        match n {
            0 => Ok(Self(0)),
            _ => Err(Self::Error::Unknown(Self(0))),
        }
    }
}

impl TryFrom<&[u8; IDENTITY_TYPE_LENGTH]> for IdentityType {
    type Error = IdentityTypeError;

    fn try_from(bytes: &[u8; IDENTITY_TYPE_LENGTH]) -> Result<Self, Self::Error> {
        Self::try_from(bytes[0])
    }
}

/// Error while reading [`IdentityType`](struct.IdentityType.html) from a byte slice.
#[derive(Debug)]
pub enum FromSliceIdentityTypeError {
    /// Expected the slice to be [`IDENTITY_TYPE_LENGTH`](constant.IDENTITY_TYPE_LENGTH.html)
    /// bytes long, got this length instead.
    InvalidLength(usize),
    /// Error in [`IdentityType`](struct.IdentityType.html).
    IdentityTypeError(IdentityTypeError),
}

impl From<IdentityTypeError> for FromSliceIdentityTypeError {
    fn from(err: IdentityTypeError) -> Self {
        Self::IdentityTypeError(err)
    }
}

impl TryFrom<&[u8]> for IdentityType {
    type Error = FromSliceIdentityTypeError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let length = bytes.len();

        if length == IDENTITY_TYPE_LENGTH {
            Ok(Self::try_from(array_ref![bytes, 0, IDENTITY_TYPE_LENGTH])?)
        } else {
            Err(Self::Error::InvalidLength(length))
        }
    }
}

/// Error while parsing [`IdentityType`](struct.IdentityType.html) from a string.
#[derive(Debug)]
pub enum FromStrIdentityTypeError {
    /// Error while decoding the string.
    DecodeError(ParseIntError),
    /// Expected the string to encode [`IDENTITY_TYPE_LENGTH`](constant.IDENTITY_TYPE_LENGTH.html)
    /// bytes, got this many bytes instead.
    InvalidByteLength(usize),
    /// Error in [`IdentityType`](struct.IdentityType.html).
    IdentityTypeError(IdentityTypeError),
}

impl From<ParseIntError> for FromStrIdentityTypeError {
    fn from(err: ParseIntError) -> Self {
        Self::DecodeError(err)
    }
}

impl From<IdentityTypeError> for FromStrIdentityTypeError {
    fn from(err: IdentityTypeError) -> Self {
        Self::IdentityTypeError(err)
    }
}

impl From<FromSliceIdentityTypeError> for FromStrIdentityTypeError {
    fn from(err: FromSliceIdentityTypeError) -> Self {
        match err {
            FromSliceIdentityTypeError::InvalidLength(len) => Self::InvalidByteLength(len),
            FromSliceIdentityTypeError::IdentityTypeError(err) => err.into(),
        }
    }
}

impl FromStr for IdentityType {
    type Err = FromStrIdentityTypeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::try_from(s.parse::<u8>()?)?)
    }
}
