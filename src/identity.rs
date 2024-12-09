use crate::{Address, InternalError, PublicKey, SecretKey};

use ed25519_dalek::Keypair;
use failure::*;

use std::convert::{TryFrom, TryInto};
use std::fs;
use std::path::Path;

/// Combination of [`Address`](struct.Address.html), [`PublicKey`](struct.PublicKey) and optionally
/// [`SecretKey`](struct.SecretKey.html).
pub struct Identity {
    pub address: Address,
    pub public_key: PublicKey,
    pub secret_key: Option<SecretKey>,
}

impl Identity {
    /// Read ZeroTier identity from given location.
    pub fn read<P: AsRef<Path>>(path: P) -> Fallible<Self> {
        Identity::try_from(&fs::read_to_string(path)?[..])
    }

    /// Read ZeroTier identity from default location.
    pub fn read_default() -> Fallible<Self> {
        Identity::read("/var/lib/zerotier-one/identity.secret")
    }
}

impl TryFrom<SecretKey> for Identity {
    type Error = Error;

    fn try_from(secret_key: SecretKey) -> Fallible<Self> {
        let public_key = PublicKey::from(&secret_key);

        Ok(Self {
            address: Address::try_from(&public_key)?,
            public_key: PublicKey::from(&secret_key),
            secret_key: Some(secret_key)
        })
    }
}

/// TODO: use IO reader instead
impl TryFrom<&str> for Identity {
    type Error = Error;

    fn try_from(identity: &str) -> Fallible<Self> {
        let split_identity: Vec<&str> = identity.split(':').collect();
        let (address, public_key, maybe_secret_key) = match &split_identity[..] {
            [address, "0", public_key] => (address, public_key, None),
            [address, "0", public_key, secret_key] => (address, public_key, Some(secret_key)),
            _ => return Err(InternalError::MalformedIdentity.into())
        };

        Ok(Identity {
            address: Address::try_from(hex::decode(address)?.as_slice())?,
            public_key: PublicKey::try_from(hex::decode(public_key)?.as_slice())?,
            secret_key: match maybe_secret_key {
                Some(secret_key) => Some(SecretKey::try_from(hex::decode(secret_key)?.as_slice())?),
                None => None
            }
        })
    }
}

impl TryInto<Keypair> for Identity {
    type Error = Error;

    fn try_into(self) -> Fallible<Keypair> {
        Ok(Keypair {
            public: self.public_key.ed,
            secret: self.secret_key.unwrap().ed
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use ed25519_dalek::{Signer, Verifier};

    #[test]
    fn test_identity() -> Fallible<()> {
        // nix-shell -p zerotierone --run 'zerotier-idtool generate'
        let identity_str = "538c34e03c:0:070288330a72d2aa3cb7935dfe6028d9fb83bdb42240aaa05e33529121babd183ff775351742a47487454195c08c0e83c520e7466fcdde3396a0c4cd40557737:f20542ab6955fe140fb3a5be9557666b9c89a3e2b73432de46d827d11736773aca15c3e03b89a1d09436ae45bc02f84b8d5a0a2f6c0d42b3856c2b22f5ab2b27";
        let identity = Identity::try_from(identity_str)?;

        assert_eq!(identity.address, Address::try_from(&identity.public_key)?);

        let secret_key = identity.secret_key.unwrap();
        let public_key = PublicKey::from(&secret_key);

        assert_eq!(identity.public_key.ed, public_key.ed);
        assert_eq!(identity.public_key.dh.as_bytes(), public_key.dh.as_bytes());

        let keypair = ed25519_dalek::Keypair {
            public: public_key.ed,
            secret: secret_key.ed,
        };

        let message = b"7VbLpreCRY738Sw4OGecCw";
        let signature = keypair.sign(message);

        identity.public_key.ed.verify(message, &signature)?;

        Ok(())
    }
}
