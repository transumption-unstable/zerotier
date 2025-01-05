use arrayref::{array_mut_ref, array_ref};
use hex::{FromHex, FromHexError};
use salsa20::cipher::{KeyIvInit, StreamCipher};
use salsa20::Salsa20;
use sha2::{Digest, Sha512};

use std::convert::TryFrom;
use std::mem;
use std::str::FromStr;

use crate::{PublicKey, PUBLIC_KEY_LENGTH};

/// [`Address`](struct.Address.html) length in bytes.
pub const ADDRESS_LENGTH: usize = 5;

const BLOCK_SIZE: usize = 1 << 6; // 64
const MEMORY_SIZE: usize = 1 << 21; // 2 MB
const U64_SIZE: usize = mem::size_of::<u64>();

const HASHCASH_MAX_FIRST_BYTE: u8 = 0x10; // 16

/// ZeroTier address derived from [`PublicKey`](struct.PublicKey.html).
///
/// The address is derived by taking the last five bytes of ZeroTier hashcash based on Salsa20 with
/// memory size of 2 MB.
///
/// The hashcash is valid if the first byte is at most `0x10`.
///
/// The address is reserved if the first byte is `0xFF` or all bytes are `0x00`.
#[derive(Clone, Debug, PartialEq)]
pub struct Address([u8; ADDRESS_LENGTH]);

/// Error in [`Address`](struct.Address.html).
#[derive(Debug)]
pub enum AddressError {
    /// Expected the first byte of hashcash to be at most `0x10`, got this byte instead.
    InvalidHashcash(u8),
    /// This address is reserved.
    Reserved(Address),
}

impl TryFrom<&[u8; ADDRESS_LENGTH]> for Address {
    type Error = AddressError;

    fn try_from(bytes: &[u8; ADDRESS_LENGTH]) -> Result<Self, Self::Error> {
        if bytes[0] != 0xFF && bytes[..] != [0, 0, 0, 0, 0] {
            Ok(Self(bytes.clone()))
        } else {
            Err(Self::Error::Reserved(Self(bytes.clone())))
        }
    }
}

/// Ad-hoc memory-hard hash function used to derive address from ZeroTier public key.
fn hashcash(public_key: &PublicKey) -> Result<[u8; BLOCK_SIZE], AddressError> {
    let mut buf = [0u8; BLOCK_SIZE];
    let mut mem = vec![0u8; MEMORY_SIZE];

    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key.into();
    buf.copy_from_slice(&Sha512::digest(&public_key_bytes));

    let mut cipher = Salsa20::new(buf[0..32].into(), buf[32..40].into());

    cipher.apply_keystream(&mut mem[..BLOCK_SIZE]);

    for i in (BLOCK_SIZE..MEMORY_SIZE).step_by(BLOCK_SIZE) {
        let (src, dst) = mem.split_at_mut(i);

        dst[..BLOCK_SIZE].copy_from_slice(&src[i - BLOCK_SIZE..]);
        cipher.apply_keystream(&mut dst[..BLOCK_SIZE]);
    }

    for i in (0..MEMORY_SIZE).step_by(2 * U64_SIZE) {
        let n1 = u64::from_be_bytes(*array_ref!(mem, i, U64_SIZE));
        let n2 = u64::from_be_bytes(*array_ref!(mem, i + U64_SIZE, U64_SIZE));

        let i1 = n1 % (BLOCK_SIZE as u64 / U64_SIZE as u64) * U64_SIZE as u64;
        let i2 = n2 % (MEMORY_SIZE as u64 / U64_SIZE as u64) * U64_SIZE as u64;

        mem::swap(
            array_mut_ref![buf, i1 as usize, U64_SIZE],
            array_mut_ref![mem, i2 as usize, U64_SIZE],
        );

        cipher.apply_keystream(&mut buf[..]);
    }

    if buf[0] <= HASHCASH_MAX_FIRST_BYTE {
        Ok(buf)
    } else {
        Err(AddressError::InvalidHashcash(buf[0]))
    }
}

impl TryFrom<&PublicKey> for Address {
    type Error = AddressError;

    fn try_from(public_key: &PublicKey) -> Result<Self, Self::Error> {
        let hash = hashcash(public_key)?;
        let addr_bytes = array_ref![hash, BLOCK_SIZE - ADDRESS_LENGTH, ADDRESS_LENGTH];

        Address::try_from(addr_bytes)
    }
}

/// Error while reading [`Address`](struct.Address.html) from a byte slice.
#[derive(Debug)]
pub enum FromSliceAddressError {
    /// Expected the slice to be [`ADDRESS_LENGTH`](constant.ADDRESS_LENGTH.html)
    /// bytes long, got this length instead.
    InvalidLength(usize),
    /// Error in [`Address`](struct.Address.html).
    AddressError(AddressError),
}

impl From<AddressError> for FromSliceAddressError {
    fn from(err: AddressError) -> Self {
        Self::AddressError(err)
    }
}

impl TryFrom<&[u8]> for Address {
    type Error = FromSliceAddressError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let length = bytes.len();

        if length == ADDRESS_LENGTH {
            Ok(Self::try_from(array_ref![bytes, 0, ADDRESS_LENGTH])?)
        } else {
            Err(Self::Error::InvalidLength(length))
        }
    }
}

/// Error while parsing [`Address`](struct.Address.html) from a string.
#[derive(Debug)]
pub enum FromStrAddressError {
    /// Error while decoding the string.
    DecodeError(FromHexError),
    /// Expected the string to encode [`ADDRESS_LENGTH`](constant.ADDRESS_LENGTH.html)
    /// bytes, got this many bytes instead.
    InvalidByteLength(usize),
    /// Error in [`Address`](struct.Address.html).
    AddressError(AddressError),
}

impl From<FromHexError> for FromStrAddressError {
    fn from(err: FromHexError) -> Self {
        Self::DecodeError(err)
    }
}

impl From<AddressError> for FromStrAddressError {
    fn from(err: AddressError) -> Self {
        Self::AddressError(err)
    }
}

impl From<FromSliceAddressError> for FromStrAddressError {
    fn from(err: FromSliceAddressError) -> Self {
        match err {
            FromSliceAddressError::InvalidLength(len) => Self::InvalidByteLength(len),
            FromSliceAddressError::AddressError(err) => err.into(),
        }
    }
}

impl FromHex for Address {
    type Error = FromStrAddressError;

    fn from_hex<T: AsRef<[u8]>>(hex: T) -> Result<Self, Self::Error> {
        Ok(Self::try_from(&<[u8; ADDRESS_LENGTH]>::from_hex(hex)?)?)
    }
}

impl FromStr for Address {
    type Err = FromStrAddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}
