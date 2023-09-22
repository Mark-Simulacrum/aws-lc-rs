// Copyright 2015-2016 Brian Smith.
// SPDX-License-Identifier: ISC
// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

use crate::ec::{self, validate_ec_key, SCALAR_MAX_BYTES};
use crate::error::{KeyRejected, Unspecified};
use crate::pkcs8::{Document, Version};
use crate::ptr::{DetachableLcPtr, LcPtr};
#[cfg(not(feature = "fips"))]
use aws_lc::EC_KEY_generate_key;
#[cfg(feature = "fips")]
use aws_lc::EC_KEY_generate_key_fips;
use aws_lc::{
    EC_KEY_new_by_curve_name, EVP_PKEY_assign_EC_KEY, EVP_PKEY_new, EVP_PKEY_set1_EC_KEY, EC_KEY,
    EVP_PKEY,
};
use std::fmt;
use zeroize::Zeroize;

/// An elltipic curve algorithm
#[derive(PartialEq, Eq, Debug)]
pub struct Algorithm {
    id: &'static crate::ec::AlgorithmID,
}

/// NSA Suite B P-256 (secp256r1) curve
pub const P256: Algorithm = Algorithm {
    id: &crate::ec::AlgorithmID::P256,
};
/// NSA Suite B P-384 (secp384r1) curve
pub const P384: Algorithm = Algorithm {
    id: &crate::ec::AlgorithmID::P384,
};
/// NSA Suite B P-521 (secp521r1) curve
pub const P521: Algorithm = Algorithm {
    id: &crate::ec::AlgorithmID::P521,
};
/// secp256k1 curve
pub const P256K1: Algorithm = Algorithm {
    id: &crate::ec::AlgorithmID::P256K1,
};

/// An elliptic curve key pair, not bound to any particular purpose.
pub struct KeyPair {
    alg: &'static Algorithm,
    pub(crate) ec_key: LcPtr<EC_KEY>,
    pubkey: PublicKey,
}

impl fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!("KeyPair {{ public_key: {:?} }}", self.pubkey))
    }
}

unsafe impl Send for KeyPair {}

unsafe impl Sync for KeyPair {}

pub(crate) unsafe fn generate_key(nid: i32) -> Result<LcPtr<EVP_PKEY>, Unspecified> {
    let ec_key = DetachableLcPtr::new(EC_KEY_new_by_curve_name(nid))?;

    #[cfg(feature = "fips")]
    if 1 != EC_KEY_generate_key_fips(*ec_key) {
        return Err(Unspecified);
    }

    #[cfg(not(feature = "fips"))]
    if 1 != EC_KEY_generate_key(*ec_key) {
        return Err(Unspecified);
    }

    let evp_pkey = LcPtr::new(EVP_PKEY_new())?;
    if 1 != EVP_PKEY_assign_EC_KEY(*evp_pkey, *ec_key) {
        return Err(Unspecified);
    }
    ec_key.detach();

    Ok(evp_pkey)
}

impl KeyPair {
    unsafe fn new(alg: &'static Algorithm, ec_key: LcPtr<EC_KEY>) -> Result<Self, ()> {
        let pubkey = ec::marshal_public_key(&ec_key.as_const())?;
        Ok(Self {
            alg,
            ec_key,
            pubkey,
        })
    }

    /// Generates a new key pair.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn generate(alg: &'static Algorithm) -> Result<Self, Unspecified> {
        unsafe {
            let evp_pkey = generate_key(alg.id.nid())?;

            let ec_key = evp_pkey.get_ec_key()?;

            validate_ec_key(&ec_key.as_const(), alg.id.nid())?;

            Ok(Self::new(alg, ec_key)?)
        }
    }

    /// Constructs an key pair by parsing an unencrypted PKCS#8 v1 id-ecPublicKey
    /// `ECPrivateKey` key.
    ///
    /// # Errors
    /// `error::KeyRejected` if bytes do not encode an key pair or if the key is otherwise not
    /// acceptable.
    pub fn from_pkcs8(alg: &'static Algorithm, pkcs8: &[u8]) -> Result<Self, KeyRejected> {
        unsafe {
            let evp_pkey = LcPtr::try_from(pkcs8)?;

            let ec_key = evp_pkey.get_ec_key()?;

            validate_ec_key(&ec_key.as_const(), alg.id.nid())?;

            let key_pair = Self::new(alg, ec_key)?;

            Ok(key_pair)
        }
    }

    /// Serializes this `KeyPair` into a PKCS#8 v1 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn to_pkcs8v1(&self) -> Result<Document, Unspecified> {
        unsafe {
            let evp_pkey = LcPtr::new(EVP_PKEY_new())?;
            if 1 != EVP_PKEY_set1_EC_KEY(*evp_pkey, *self.ec_key) {
                return Err(Unspecified);
            }
            evp_pkey.marshall_private_key(Version::V1)
        }
    }

    /// Serializes this `KeyPair` into a PKCS#8 v2 document.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn to_pkcs8v2(&self) -> Result<Document, Unspecified> {
        unsafe {
            let evp_pkey = LcPtr::new(EVP_PKEY_new())?;
            if 1 != EVP_PKEY_set1_EC_KEY(*evp_pkey, *self.ec_key) {
                return Err(Unspecified);
            }
            evp_pkey.marshall_private_key(Version::V2)
        }
    }

    /// Constructs an key pair from the private key and public key bytes
    ///
    /// The private key must encoded as a big-endian fixed-length integer. For
    /// example, a P-256 private key must be 32 bytes prefixed with leading
    /// zeros as needed.
    ///
    /// The public key is encoding in uncompressed form using the
    /// Octet-String-to-Elliptic-Curve-Point algorithm in
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0].
    ///
    /// This is intended for use by code that deserializes key pairs. It is
    /// recommended to use `KeyPair::from_pkcs8()` (with a PKCS#8-encoded
    /// key) instead.
    ///
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
    ///     http://www.secg.org/sec1-v2.pdf
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn from_private_key_and_public_key(
        alg: &'static Algorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        unsafe {
            let ec_group = ec::ec_group_from_nid(alg.id.nid())?;
            let public_ec_point = ec::ec_point_from_bytes(&ec_group, public_key)
                .map_err(|_| KeyRejected::invalid_encoding())?;
            let private_bn = DetachableLcPtr::try_from(private_key)?;
            let ec_key = ec::ec_key_from_public_private(&ec_group, &public_ec_point, &private_bn)?;
            validate_ec_key(&ec_key.as_const(), alg.id.nid())?;
            let key_pair = Self::new(alg, ec_key)?;
            Ok(key_pair)
        }
    }

    /// Exposes the private key encoded as a big-endian fixed-length integer.
    ///
    /// For most use-cases, `KeyPair::to_pkcs8()` should be preferred.
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn private_key(&self) -> Result<PrivateKey, Unspecified> {
        unsafe {
            let mut priv_key_bytes = [0u8; SCALAR_MAX_BYTES];

            let key_len = ec::marshal_private_key_to_buffer(
                self.alg.id,
                &mut priv_key_bytes,
                &self.ec_key.as_const(),
            )?;

            Ok(PrivateKey::new(self, priv_key_bytes[0..key_len].into()))
        }
    }

    /// Exposes the private key encoded as a big-endian fixed-length integer.
    ///
    /// For most use-cases, `KeyPair::to_pkcs8()` should be preferred.
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn public_key(&self) -> &PublicKey {
        &self.pubkey
    }
}

/// A raw private key.
#[derive(Clone)]
pub struct PrivateKey<'a>(&'a KeyPair, Box<[u8]>);

impl Drop for PrivateKey<'_> {
    fn drop(&mut self) {
        self.1.zeroize();
    }
}

impl fmt::Debug for PrivateKey<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str("EcdsaPrivateKey()")
    }
}

impl<'a> PrivateKey<'a> {
    fn new(key_pair: &'a KeyPair, box_bytes: Box<[u8]>) -> Self {
        PrivateKey(key_pair, box_bytes)
    }
}

impl AsRef<[u8]> for PrivateKey<'_> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.1.as_ref()
    }
}

unsafe impl Send for PrivateKey<'_> {}
unsafe impl Sync for PrivateKey<'_> {}

/// A raw public key.
#[derive(Clone)]
pub struct PublicKey(Box<[u8]>);

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "EcdsaPublicKey(\"{}\")",
            crate::test::to_hex(self.0.as_ref())
        ))
    }
}

impl PublicKey {
    pub(crate) fn new(pubkey_box: Box<[u8]>) -> Self {
        PublicKey(pubkey_box)
    }
}

impl AsRef<[u8]> for PublicKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
