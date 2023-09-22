use super::Signature;
use super::VerificationAlgorithm;
use crate::ec;
use crate::ec::ec_group_from_nid;
use crate::ec::AlgorithmID;

use crate::error::KeyRejected;
use crate::error::Unspecified;
use crate::pkcs8::Document;
use crate::pkey::elliptic_curve::{self, KeyPair, PublicKey};
use crate::ptr::LcPtr;
use crate::rand::SecureRandom;
use crate::{digest, sealed};
use aws_lc_sys::ECDSA_do_sign;
use aws_lc_sys::ECDSA_do_verify;
use std::fmt;
use std::os::raw::c_uint;
use untrusted::Input;

/// An ECDSA key pair, used for signing.
#[allow(clippy::module_name_repetitions)]
pub struct EcdsaKeyPair {
    algorithm: &'static EcdsaSigningAlgorithm,
    key: crate::pkey::elliptic_curve::KeyPair,
}

impl fmt::Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        f.write_str(&format!(
            "EcdsaKeyPair {{ public_key: {:?} }}",
            self.key.public_key()
        ))
    }
}

impl super::KeyPair for EcdsaKeyPair {
    type PublicKey = PublicKey;

    #[inline]
    fn public_key(&self) -> &Self::PublicKey {
        self.key.public_key()
    }
}

/// An ECDSA verification algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaVerificationAlgorithm {
    pub(super) id: &'static AlgorithmID,
    pub(super) digest: &'static digest::Algorithm,
    pub(super) bits: c_uint,
    pub(super) sig_format: EcdsaSignatureFormat,
}

impl VerificationAlgorithm for EcdsaVerificationAlgorithm {
    #[inline]
    #[cfg(feature = "ring-sig-verify")]
    fn verify(
        &self,
        public_key: Input<'_>,
        msg: Input<'_>,
        signature: Input<'_>,
    ) -> Result<(), Unspecified> {
        self.verify_sig(
            public_key.as_slice_less_safe(),
            msg.as_slice_less_safe(),
            signature.as_slice_less_safe(),
        )
    }

    fn verify_sig(
        &self,
        public_key: &[u8],
        msg: &[u8],
        signature: &[u8],
    ) -> Result<(), Unspecified> {
        unsafe {
            let ec_group = ec_group_from_nid(self.id.nid())?;
            let ec_point = ec::ec_point_from_bytes(&ec_group, public_key)?;
            let ec_key = ec::ec_key_from_public_point(&ec_group, &ec_point)?;

            let ecdsa_sig = match self.sig_format {
                EcdsaSignatureFormat::ASN1 => ec::ecdsa_sig_from_asn1(signature),
                EcdsaSignatureFormat::Fixed => ec::ecdsa_sig_from_fixed(self.id, signature),
            }?;
            let msg_digest = digest::digest(self.digest, msg);
            let msg_digest = msg_digest.as_ref();

            if 1 != ECDSA_do_verify(msg_digest.as_ptr(), msg_digest.len(), *ecdsa_sig, *ec_key) {
                return Err(Unspecified);
            }

            Ok(())
        }
    }
}

/// An ECDSA signing algorithm.
#[derive(Debug, Eq, PartialEq)]
pub struct EcdsaSigningAlgorithm(pub(crate) &'static EcdsaVerificationAlgorithm);

impl std::ops::Deref for EcdsaSigningAlgorithm {
    type Target = EcdsaVerificationAlgorithm;
    #[inline]
    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl EcdsaSigningAlgorithm {
    fn ec(&self) -> &crate::pkey::elliptic_curve::Algorithm {
        match self.id {
            AlgorithmID::P256 => &elliptic_curve::P256,
            AlgorithmID::P384 => &elliptic_curve::P384,
            AlgorithmID::P521 => &elliptic_curve::P521,
            AlgorithmID::P256K1 => &elliptic_curve::P256K1,
        }
    }
}

impl sealed::Sealed for EcdsaVerificationAlgorithm {}
impl sealed::Sealed for EcdsaSigningAlgorithm {}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum EcdsaSignatureFormat {
    ASN1,
    Fixed,
}

impl EcdsaKeyPair {
    /// Constructs an ECDSA key pair by parsing an unencrypted PKCS#8 v1
    /// id-ecPublicKey `ECPrivateKey` key.
    ///
    /// # Errors
    /// `error::KeyRejected` if bytes do not encode an ECDSA key pair or if the key is otherwise not
    /// acceptable.
    pub fn from_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        pkcs8: &[u8],
    ) -> Result<Self, KeyRejected> {
        Ok(EcdsaKeyPair {
            algorithm: alg,
            key: KeyPair::from_pkcs8(alg.ec(), pkcs8)?,
        })
    }

    /// Generates a new key pair and returns the key pair serialized as a
    /// PKCS#8 v1 document.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    pub fn generate_pkcs8(
        alg: &'static EcdsaSigningAlgorithm,
        _rng: &dyn SecureRandom,
    ) -> Result<Document, Unspecified> {
        KeyPair::generate(alg.ec())?.to_pkcs8v1()
    }

    /// Constructs an ECDSA key pair from the private key and public key bytes
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
    /// recommended to use `EcdsaKeyPair::from_pkcs8()` (with a PKCS#8-encoded
    /// key) instead.
    ///
    /// [SEC 1: Elliptic Curve Cryptography, Version 2.0]:
    ///     http://www.secg.org/sec1-v2.pdf
    ///
    /// # Errors
    /// `error::KeyRejected` if parsing failed or key otherwise unacceptable.
    pub fn from_private_key_and_public_key(
        alg: &'static EcdsaSigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<Self, KeyRejected> {
        Ok(EcdsaKeyPair {
            algorithm: alg,
            key: KeyPair::from_private_key_and_public_key(alg.ec(), private_key, public_key)?,
        })
    }

    /// Returns the signature of the message using a random nonce.
    ///
    /// # *ring* Compatibility
    /// Our implementation ignores the `SecureRandom` parameter.
    ///
    /// # Errors
    /// `error::Unspecified` on internal error.
    ///
    #[inline]
    pub fn sign(&self, _rng: &dyn SecureRandom, message: &[u8]) -> Result<Signature, Unspecified> {
        unsafe {
            let digest = digest::digest(self.algorithm.digest, message);
            let digest = digest.as_ref();
            let ecdsa_sig = LcPtr::new(ECDSA_do_sign(
                digest.as_ptr(),
                digest.len(),
                *self.key.ec_key,
            ))?;
            match self.algorithm.sig_format {
                EcdsaSignatureFormat::ASN1 => ec::ecdsa_sig_to_asn1(&ecdsa_sig),
                EcdsaSignatureFormat::Fixed => {
                    ec::ecdsa_sig_to_fixed(self.algorithm.id, &ecdsa_sig)
                }
            }
        }
    }
}
