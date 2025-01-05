//! ZeroTier-compatible cryptography library.

#![warn(future_incompatible, missing_docs, warnings)]

mod address;
mod identity;
mod identity_type;
mod public_key;
mod secret_key;

pub use address::{
    Address, AddressError, FromSliceAddressError, FromStrAddressError, ADDRESS_LENGTH,
};

pub use identity::{
    FromStrIdentityError, Identity, IdentityError, /*FromSliceIdentityError,*/
    IDENTITY_LENGTH,
};

pub use public_key::{
    FromSlicePublicKeyError, FromStrPublicKeyError, PublicKey, PublicKeyError, PUBLIC_KEY_LENGTH,
};

pub use secret_key::{
    FromSliceSecretKeyError, FromStrSecretKeyError, SecretKey, SECRET_KEY_LENGTH,
};

pub use identity_type::{
    FromSliceIdentityTypeError, FromStrIdentityTypeError, IdentityType, IdentityTypeError,
    IDENTITY_TYPE_LENGTH,
};
