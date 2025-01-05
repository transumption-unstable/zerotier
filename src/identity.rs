use std::convert::TryFrom;
use std::str::FromStr;

use crate::{
    Address, AddressError, FromSliceAddressError, FromSliceIdentityTypeError,
    FromSlicePublicKeyError, FromSliceSecretKeyError, FromStrAddressError,
    FromStrIdentityTypeError, FromStrPublicKeyError, FromStrSecretKeyError, IdentityType,
    IdentityTypeError, PublicKey, PublicKeyError, SecretKey, ADDRESS_LENGTH, IDENTITY_TYPE_LENGTH,
    PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH,
};

/// [`Identity`](struct.Identity.html) length in bytes.
pub const IDENTITY_LENGTH: usize =
    ADDRESS_LENGTH + IDENTITY_TYPE_LENGTH + PUBLIC_KEY_LENGTH + SECRET_KEY_LENGTH;

/// ZeroTier identity; includes [`Address`](struct.Address.html),
/// [`PublicKey`](struct.PublicKey.html), and optionally [`SecretKey`](struct.SecretKey.html).
pub struct Identity {
    /// ZeroTier address belonging to [`PublicKey`](struct.PublicKey.html).
    pub address: Address,
    /// ZeroTier identity type; always 0.
    pub identity_type: IdentityType,
    /// ZeroTier public key (X25519 + Ed25519) belonging to [`SecretKey`](struct.SecretKey.html),
    /// if present.
    pub public_key: PublicKey,
    /// ZeroTier secret key (X25519 + Ed25519); optional.
    pub secret_key: Option<SecretKey>,
}

impl TryFrom<SecretKey> for Identity {
    type Error = AddressError;

    fn try_from(secret_key: SecretKey) -> Result<Self, Self::Error> {
        let public_key = PublicKey::from(&secret_key);

        Ok(Self {
            address: Address::try_from(&public_key)?,
            identity_type: IdentityType::new(),
            public_key: PublicKey::from(&secret_key),
            secret_key: Some(secret_key),
        })
    }
}

/// Error in [`Identity`](struct.Identity.html).
pub enum IdentityError {
    /// Error in the [`Address`](struct.Address.html) part.
    AddressError(AddressError),
    /// Error in the [`IdentityType`](struct.IdentityType.html) part.
    IdentityTypeError(IdentityTypeError),
    /// Error in the [`PublicKey`](struct.PublicKey.html) part.
    PublicKeyError(PublicKeyError),
}

impl From<AddressError> for IdentityError {
    fn from(err: AddressError) -> Self {
        Self::AddressError(err)
    }
}

impl From<IdentityTypeError> for IdentityError {
    fn from(err: IdentityTypeError) -> Self {
        Self::IdentityTypeError(err)
    }
}

impl From<PublicKeyError> for IdentityError {
    fn from(err: PublicKeyError) -> Self {
        Self::PublicKeyError(err)
    }
}

/// Error while parsing [`Identity`](struct.Identity.html) from a string.
#[derive(Debug)]
pub enum FromStrIdentityError {
    /// Expected 3 or 4 parts separated by `:`, got this many instead.
    InvalidPartCount(usize),
    /// Error while parsing the [`Address`](struct.Address.html) part.
    InvalidAddress(FromStrAddressError),
    /// Error while parsing the [`IdentityType`](struct.IdentityType.html) part.
    InvalidIdentityType(FromStrIdentityTypeError),
    /// Error while parsing the [`PublicKey`](struct.PublicKey.html) part.
    InvalidPublicKey(FromStrPublicKeyError),
    /// Error while parsing the [`SecretKey`](struct.SecretKey.html) part.
    InvalidSecretKey(FromStrSecretKeyError),
}

impl From<AddressError> for FromStrIdentityError {
    fn from(err: AddressError) -> Self {
        Self::InvalidAddress(FromStrAddressError::AddressError(err))
    }
}

impl From<IdentityTypeError> for FromStrIdentityError {
    fn from(err: IdentityTypeError) -> Self {
        Self::InvalidIdentityType(FromStrIdentityTypeError::IdentityTypeError(err))
    }
}

impl From<PublicKeyError> for FromStrIdentityError {
    fn from(err: PublicKeyError) -> Self {
        Self::InvalidPublicKey(FromStrPublicKeyError::PublicKeyError(err))
    }
}

impl From<FromStrAddressError> for FromStrIdentityError {
    fn from(err: FromStrAddressError) -> Self {
        Self::InvalidAddress(err)
    }
}

impl From<FromStrIdentityTypeError> for FromStrIdentityError {
    fn from(err: FromStrIdentityTypeError) -> Self {
        Self::InvalidIdentityType(err)
    }
}

impl From<FromStrPublicKeyError> for FromStrIdentityError {
    fn from(err: FromStrPublicKeyError) -> Self {
        Self::InvalidPublicKey(err)
    }
}

impl From<FromStrSecretKeyError> for FromStrIdentityError {
    fn from(err: FromStrSecretKeyError) -> Self {
        Self::InvalidSecretKey(err)
    }
}

impl FromStr for Identity {
    type Err = FromStrIdentityError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();

        let (addr, t, pk, maybe_sk) = match &parts[..] {
            [addr, t, pk, sk] => (addr, t, pk, Some(sk)),
            [addr, t, pk] => (addr, t, pk, None),
            _ => return Err(Self::Err::InvalidPartCount(parts.len())),
        };

        Ok(Identity {
            identity_type: t.parse()?,
            address: addr.parse()?,
            public_key: pk.parse()?,
            secret_key: match maybe_sk {
                Some(sk) => Some(sk.parse()?),
                None => None,
            },
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    #[test]
    fn test_identity() -> Result<(), FromStrIdentityError> {
        // `zerotier-idtool generate`
        let id_str = "538c34e03c:0:070288330a72d2aa3cb7935dfe6028d9fb83bdb42240aaa05e33529121babd183ff775351742a47487454195c08c0e83c520e7466fcdde3396a0c4cd40557737:f20542ab6955fe140fb3a5be9557666b9c89a3e2b73432de46d827d11736773aca15c3e03b89a1d09436ae45bc02f84b8d5a0a2f6c0d42b3856c2b22f5ab2b27";
        let id = id_str.parse::<Identity>()?;

        assert_eq!(id.address, Address::try_from(&id.public_key)?);

        let pk = id.public_key;
        let sk = id.secret_key.unwrap();
        let sk_pk = PublicKey::from(&sk);

        assert_eq!(pk.x25519.as_bytes(), sk_pk.x25519.as_bytes());
        assert_eq!(pk.ed25519, sk_pk.ed25519);

        let pk_ed = pk.ed25519;
        let sk_ed = sk.ed25519;

        let msg = b"7VbLpreCRY738Sw4OGecCw";
        let sig = sk_ed.sign(msg);

        pk_ed.verify(msg, &sig)?;

        Ok(())
    }
}
