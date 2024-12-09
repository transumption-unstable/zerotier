use crate::{InternalError, PublicKey, PUBLIC_KEY_LENGTH};

use arrayref::{array_mut_ref, array_ref};
use failure::Error;
use serde::*;
use std::{convert::TryFrom, mem};

use salsa20::Salsa20;
use salsa20::cipher::{KeyIvInit, StreamCipher};
use generic_array::GenericArray;

use sha2::{Digest, Sha512};

/// [`Address`](struct.Address.html) length in bytes.
pub const ADDRESS_LENGTH: usize = 5;

const BLOCK_SIZE: usize = 64;
const MEMORY_SIZE: usize = 1 << 21; // 2 MB
const U64_SIZE: usize = mem::size_of::<u64>();

/// 40-bit node ID derived from [`PublicKey`](struct.PublicKey.html).
///
/// Address is derived by taking last five bytes of memory-hard hash.
/// Address is valid unless:
///
/// - first byte of memory-hard hash is greater than `0x10`
/// - first byte of address is `0xFF`
/// - every byte of address is `0x00`
#[derive(Clone, Debug, PartialEq)]
pub struct Address([u8; ADDRESS_LENGTH]);

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

/// Ad-hoc memory-hard hash function used to derive address from ZeroTier public key.
fn memory_hard_hash(public_key: &PublicKey) -> Result<[u8; BLOCK_SIZE], Error> {
    let mut buf = [0u8; BLOCK_SIZE];
    let mut mem = vec![0u8; MEMORY_SIZE];

    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key.into();
    buf.copy_from_slice(&Sha512::digest(&public_key_bytes));

    let mut cipher = Salsa20::new(
        GenericArray::from_slice(&buf[0..32]),
        GenericArray::from_slice(&buf[32..40]),
    );

    cipher.apply_keystream(&mut mem[..BLOCK_SIZE]);

    for i in (BLOCK_SIZE..MEMORY_SIZE).step_by(BLOCK_SIZE) {
        let (src, dst) = mem.split_at_mut(i);

        dst[..BLOCK_SIZE].copy_from_slice(&src[i - BLOCK_SIZE..]);
        cipher.apply_keystream(&mut dst[..BLOCK_SIZE]);
    }

    for i in (0..MEMORY_SIZE).step_by(2 * U64_SIZE) {
        let n1 = u64::from_be_bytes(*array_ref!(mem, i, U64_SIZE));
        let n2 = u64::from_be_bytes(*array_ref!(mem, i + U64_SIZE, U64_SIZE));

        let i1 = usize::try_from(n1)? % (BLOCK_SIZE / U64_SIZE) * U64_SIZE;
        let i2 = usize::try_from(n2)? % (MEMORY_SIZE / U64_SIZE) * U64_SIZE;

        mem::swap(
            array_mut_ref!(buf, i1, U64_SIZE),
            array_mut_ref!(mem, i2, U64_SIZE),
        );

        cipher.apply_keystream(&mut buf[..]);
    }

    if buf[0] >= 17 {
        Err(InternalError::InvalidHashcash.into())
    } else {
        Ok(buf)
    }
}

/// Tries to derive address from [`PublicKey`](struct.PublicKey.html). Throws
/// [`InternalError`](enum.InternalError.html) for invalid addresses.
impl TryFrom<&PublicKey> for Address {
    type Error = Error;

    fn try_from(public_key: &PublicKey) -> Result<Self, Error> {
        let hash = memory_hard_hash(public_key)?;
        let addr = array_ref!(hash, BLOCK_SIZE - ADDRESS_LENGTH, ADDRESS_LENGTH).clone();

        if addr[0] == 0xff || addr[..] == [0, 0, 0, 0, 0] {
            Err(InternalError::ReservedAddress.into())
        } else {
            Ok(Address(addr))
        }
    }
}

/// Tries to construct an address from a slice of bytes. Fails if `len(bytes) != 5`.
impl TryFrom<&[u8]> for Address {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != ADDRESS_LENGTH {
            Err(InternalError::BytesLengthError.into())
        } else {
            Ok(Self(*array_ref!(bytes, 0, ADDRESS_LENGTH)))
        }
    }
}
