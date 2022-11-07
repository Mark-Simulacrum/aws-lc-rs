// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

// Modifications copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: ISC

//! Authenticated Encryption with Associated Data (AEAD).
//!
//! See [Authenticated encryption: relations among notions and analysis of the
//! generic composition paradigm][AEAD] for an introduction to the concept of
//! AEADs.
//!
//! [AEAD]: http://www-cse.ucsd.edu/~mihir/papers/oem.html
//! [`crypto.cipher.AEAD`]: https://golang.org/pkg/crypto/cipher/#AEAD

use crate::{derive_debug_via_id, error, hkdf};
use aes_gcm::aes_gcm_seal_separate;
use std::fmt::Debug;

use crate::error::Unspecified;
use key_inner::KeyInner;
use std::mem::MaybeUninit;
use std::ops::RangeFrom;

mod aes;
mod aes_gcm;
mod block;
mod chacha;
pub mod chacha20_poly1305_openssh;
mod cipher;
mod key_inner;
mod nonce;
mod poly1305;
pub mod quic;

#[cfg(feature = "threadlocal")]
use thread_local::ThreadLocal;
#[cfg(feature = "threadlocal")]
use zeroize::Zeroize;

pub use self::{
    aes_gcm::{AES_128_GCM, AES_256_GCM},
    chacha::CHACHA20_POLY1305,
    nonce::{Nonce, NONCE_LEN},
};

/// A sequences of unique nonces.
///
/// A given `NonceSequence` must never return the same `Nonce` twice from
/// `advance()`.
///
/// A simple counter is a reasonable (but probably not ideal) `NonceSequence`.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the sequence.
pub trait NonceSequence {
    /// Returns the next nonce in the sequence.
    ///
    /// # Errors
    /// `error::Unspecified` if  "too many" nonces have been requested, where how many
    /// is too many is up to the implementation of `NonceSequence`. An
    /// implementation may that enforce a maximum number of records are
    /// sent/received under a key this way. Once `advance()` fails, it must
    /// fail for all subsequent calls.
    fn advance(&mut self) -> Result<Nonce, Unspecified>;
}

/// An AEAD key bound to a nonce sequence.
pub trait BoundKey<N: NonceSequence>: Debug {
    /// Constructs a new key from the given `UnboundKey` and `NonceSequence`.
    fn new(key: UnboundKey, nonce_sequence: N) -> Self;

    /// The key's AEAD algorithm.
    fn algorithm(&self) -> &'static Algorithm;
}

/// An AEAD key for authenticating and decrypting ("opening"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
pub struct OpeningKey<N: NonceSequence> {
    key: UnboundKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for OpeningKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key,
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm
    }
}

impl<N: NonceSequence> Debug for OpeningKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("OpeningKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

impl<N: NonceSequence> OpeningKey<N> {
    /// Authenticates and decrypts (“opens”) data in place.
    ///
    /// `aad` is the additional authenticated data (AAD), if any.
    ///
    /// On input, `in_out` must be the ciphertext followed by the tag. When
    /// `open_in_place()` returns `Ok(plaintext)`, the input ciphertext
    /// has been overwritten by the plaintext; `plaintext` will refer to the
    /// plaintext without the tag.
    ///
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid. In this case, `in_out` may have been
    /// overwritten in an unspecified way.
    ///
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.open_within(aad, in_out, 0..)
    }

    /// Authenticates and decrypts (“opens”) data in place, with a shift.
    ///
    /// `aad` is the additional authenticated data (AAD), if any.
    ///
    /// On input, `in_out[ciphertext_and_tag]` must be the ciphertext followed
    /// by the tag. When `open_within()` returns `Ok(plaintext)`, the plaintext
    /// will be at `in_out[0..plaintext.len()]`. In other words, the following
    /// two code fragments are equivalent for valid values of
    /// `ciphertext_and_tag`, except `open_within` will often be more efficient:
    ///
    ///
    /// ```skip
    /// let plaintext = key.open_within(aad, in_out, cipertext_and_tag)?;
    /// ```
    ///
    /// ```skip
    /// let ciphertext_and_tag_len = in_out[ciphertext_and_tag].len();
    /// in_out.copy_within(ciphertext_and_tag, 0);
    /// let plaintext = key.open_in_place(aad, &mut in_out[..ciphertext_and_tag_len])?;
    /// ```
    ///
    /// Similarly, `key.open_within(aad, in_out, 0..)` is equivalent to
    /// `key.open_in_place(aad, in_out)`.
    ///
    ///
    /// The shifting feature is useful in the case where multiple packets are
    /// being reassembled in place. Consider this example where the peer has
    /// sent the message “Split stream reassembled in place” split into
    /// three sealed packets:
    ///
    /// ```ascii-art
    ///                 Packet 1                  Packet 2                 Packet 3
    /// Input:  [Header][Ciphertext][Tag][Header][Ciphertext][Tag][Header][Ciphertext][Tag]
    ///                      |         +--------------+                        |
    ///               +------+   +-----+    +----------------------------------+
    ///               v          v          v
    /// Output: [Plaintext][Plaintext][Plaintext]
    ///        “Split stream reassembled in place”
    /// ```
    ///
    /// This reassembly be accomplished with three calls to `open_within()`.
    ///
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid. In this case, `in_out` may have been
    /// overwritten in an unspecified way.
    ///
    #[inline]
    pub fn open_within<'in_out, A>(
        &mut self,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        open_within_(
            &self.key,
            self.nonce_sequence.advance()?,
            aad,
            in_out,
            ciphertext_and_tag,
        )
    }
}

#[inline]
fn open_within_<'in_out, A: AsRef<[u8]>>(
    key: &UnboundKey,
    nonce: Nonce,
    Aad(aad): Aad<A>,
    in_out: &'in_out mut [u8],
    ciphertext_and_tag: RangeFrom<usize>,
) -> Result<&'in_out mut [u8], Unspecified> {
    fn open_within<'in_out>(
        key: &UnboundKey,
        nonce: Nonce,
        aad: Aad<&[u8]>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified> {
        let in_prefix_len = ciphertext_and_tag.start;
        let ciphertext_and_tag_len = in_out.len().checked_sub(in_prefix_len).ok_or(Unspecified)?;
        let ciphertext_len = ciphertext_and_tag_len
            .checked_sub(TAG_LEN)
            .ok_or(Unspecified)?;
        check_per_nonce_max_bytes(key.algorithm, ciphertext_len)?;
        let key_inner_ref = key.get_inner_key()?;

        aead_open_combined(key_inner_ref, nonce, aad, &mut in_out[in_prefix_len..])?;

        // ring is shifting the plaintext to the left
        in_out.copy_within(in_prefix_len..in_prefix_len + ciphertext_len, 0);

        // `ciphertext_len` is also the plaintext length.
        Ok(&mut in_out[..ciphertext_len])
    }

    open_within(
        key,
        nonce,
        Aad::from(aad.as_ref()),
        in_out,
        ciphertext_and_tag,
    )
}

/// An AEAD key for encrypting and signing ("sealing"), bound to a nonce
/// sequence.
///
/// Intentionally not `Clone` or `Copy` since cloning would allow duplication
/// of the nonce sequence.
pub struct SealingKey<N: NonceSequence> {
    key: UnboundKey,
    nonce_sequence: N,
}

impl<N: NonceSequence> BoundKey<N> for SealingKey<N> {
    fn new(key: UnboundKey, nonce_sequence: N) -> Self {
        Self {
            key,
            nonce_sequence,
        }
    }

    #[inline]
    fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm
    }
}

impl<N: NonceSequence> Debug for SealingKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("SealingKey")
            .field("algorithm", &self.algorithm())
            .finish()
    }
}

impl<N: NonceSequence> SealingKey<N> {
    /// Encrypts and signs (“seals”) data in place, appending the tag to the
    /// resulting ciphertext.
    ///
    /// `key.seal_in_place_append_tag(aad, in_out)` is equivalent to:
    ///
    /// ```skip
    /// key.seal_in_place_separate_tag(aad, in_out.as_mut())
    ///     .map(|tag| in_out.extend(tag.as_ref()))
    /// ```
    /// # Errors
    /// `error::Unspecified` when `nonce_sequence` cannot be advanced.
    ///
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_append_tag<A, InOut>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        seal_in_place_append_tag_(
            &self.key,
            self.nonce_sequence.advance()?,
            Aad::from(aad.as_ref()),
            in_out,
        )
    }

    /// Encrypts and signs (“seals”) data in place.
    ///
    /// `aad` is the additional authenticated data (AAD), if any. This is
    /// authenticated but not encrypted. The type `A` could be a byte slice
    /// `&[u8]`, a byte array `[u8; N]` for some constant `N`, `Vec<u8>`, etc.
    /// If there is no AAD then use `Aad::empty()`.
    ///
    /// The plaintext is given as the input value of `in_out`. `seal_in_place()`
    /// will overwrite the plaintext with the ciphertext and return the tag.
    /// For most protocols, the caller must append the tag to the ciphertext.
    /// The tag will be `self.algorithm.tag_len()` bytes long.
    ///
    /// # Errors
    /// `error::Unspecified` when `nonce_sequence` cannot be advanced.
    ///
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_separate_tag<A>(
        &mut self,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, Unspecified>
    where
        A: AsRef<[u8]>,
    {
        seal_in_place_separate_tag_(
            &self.key,
            self.nonce_sequence.advance()?,
            Aad::from(aad.as_ref()),
            in_out,
        )
    }
}

#[inline]
fn seal_in_place_append_tag_<InOut>(
    key: &UnboundKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut InOut,
) -> Result<(), Unspecified>
where
    InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
{
    check_per_nonce_max_bytes(key.algorithm, in_out.as_mut().len())?;
    let key_inner_ref = key.get_inner_key()?;
    aead_seal_combined(key_inner_ref, nonce, aad, in_out)
}

#[inline]
fn seal_in_place_separate_tag_(
    key: &UnboundKey,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<Tag, Unspecified> {
    check_per_nonce_max_bytes(key.algorithm, in_out.len())?;
    let key_inner_ref = key.get_inner_key()?;
    match key_inner_ref {
        KeyInner::AES_128_GCM(..) => aes_gcm_seal_separate(key_inner_ref, nonce, aad, in_out),
        KeyInner::AES_256_GCM(..) => aes_gcm_seal_separate(key_inner_ref, nonce, aad, in_out),
        #[cfg(feature = "alloc")]
        KeyInner::CHACHA20_POLY1305(..) => {
            let mut extendable_in_out = Vec::new();
            extendable_in_out.extend_from_slice(in_out);
            let plaintext_len = in_out.len();

            aead_seal_combined(key_inner_ref, nonce, aad, &mut extendable_in_out)?;
            let ciphertext = &extendable_in_out[..plaintext_len];
            let tag = &extendable_in_out[plaintext_len..];

            in_out.copy_from_slice(ciphertext);

            let mut my_tag = Vec::new();
            my_tag.extend_from_slice(tag);
            Ok(Tag(my_tag.try_into().unwrap()))
        }
        #[cfg(not(feature = "alloc"))]
        KeyInner::CHACHA20_POLY1305(..) => {
            panic!("seal_in_place_separate_tag for CHACHA20_POLY1305 requires feature=alloc");
        }
    }
}

/// The additionally authenticated data (AAD) for an opening or sealing
/// operation. This data is authenticated but is **not** encrypted.
///
/// The type `A` could be a byte slice `&[u8]`, a byte array `[u8; N]`
/// for some constant `N`, `Vec<u8>`, etc.
pub struct Aad<A: AsRef<[u8]>>(A);

impl<A: AsRef<[u8]>> Aad<A> {
    /// Construct the `Aad` from the given bytes.
    #[inline]
    pub fn from(aad: A) -> Self {
        Aad(aad)
    }
}

impl<A> AsRef<[u8]> for Aad<A>
where
    A: AsRef<[u8]>,
{
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Aad<[u8; 0]> {
    /// Construct an empty `Aad`.
    #[must_use]
    pub fn empty() -> Self {
        Self::from([])
    }
}

#[cfg(feature = "threadlocal")]
const MAX_KEY_BYTE_LEN: usize = 32;

/// An AEAD key without a designated role or nonce sequence.
#[cfg(feature = "threadlocal")]
pub struct UnboundKey {
    // There are concerns about using ThreadLocal due to platform-specific behaviour. The best
    // solution would be to restructure our structs so that they contain no mutable state.
    inner: ThreadLocal<KeyInner>,
    key_bytes: [u8; MAX_KEY_BYTE_LEN],
    key_len: usize,
    algorithm: &'static Algorithm,
}

#[cfg(not(feature = "threadlocal"))]
pub struct UnboundKey {
    inner: KeyInner,
    algorithm: &'static Algorithm,
}

#[cfg(feature = "threadlocal")]
impl Drop for UnboundKey {
    fn drop(&mut self) {
        self.key_bytes.zeroize();
    }
}

impl Debug for UnboundKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("UnboundKey")
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl UnboundKey {
    /// Constructs an `UnboundKey`.
    /// # Errors
    /// `error::Unspecified` if `key_bytes.len() != algorithm.key_len()`.
    #[cfg(feature = "threadlocal")]
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        if key_bytes.len() > MAX_KEY_BYTE_LEN {
            return Err(Unspecified);
        }
        let key_len = key_bytes.len();
        let mut my_key_bytes = [0u8; MAX_KEY_BYTE_LEN];
        my_key_bytes[0..key_len].copy_from_slice(key_bytes);
        let key_bytes = my_key_bytes;
        let unbound_key = Self {
            inner: ThreadLocal::new(),
            key_bytes,
            key_len,
            algorithm,
        };
        unbound_key.get_inner_key()?;
        Ok(unbound_key)
    }

    #[cfg(not(feature = "threadlocal"))]
    pub fn new(algorithm: &'static Algorithm, key_bytes: &[u8]) -> Result<Self, Unspecified> {
        Ok(Self {
            inner: (algorithm.init)(key_bytes)?,
            algorithm,
        })
    }

    #[cfg(feature = "threadlocal")]
    fn get_inner_key(&self) -> Result<&KeyInner, Unspecified> {
        let inner_key = self
            .inner
            .get_or_try(|| (self.algorithm.init)(&self.key_bytes[0..self.key_len]))?;
        Ok(inner_key)
    }

    /// No-op function if thread_local is turned off.
    #[cfg(not(feature = "threadlocal"))]
    fn get_inner_key(&self) -> Result<&KeyInner, Unspecified> {
        Ok(&self.inner)
    }

    /// The key's AEAD algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.algorithm
    }
}

impl From<hkdf::Okm<'_, &'static Algorithm>> for UnboundKey {
    fn from(okm: hkdf::Okm<&'static Algorithm>) -> Self {
        let mut key_bytes = [0; MAX_KEY_LEN];
        let key_bytes = &mut key_bytes[..okm.len().key_len];
        let algorithm = *okm.len();
        okm.fill(key_bytes).unwrap();
        Self::new(algorithm, key_bytes).unwrap()
    }
}

impl hkdf::KeyType for &'static Algorithm {
    #[inline]
    fn len(&self) -> usize {
        self.key_len()
    }
}

/// Immutable keys for use in situations where `OpeningKey`/`SealingKey` and
/// `NonceSequence` cannot reasonably be used.
///
/// Prefer to use `OpeningKey`/`SealingKey` and `NonceSequence` when practical.
pub struct LessSafeKey {
    key: UnboundKey,
}

impl LessSafeKey {
    /// Constructs a `LessSafeKey` from an `UnboundKey`.
    pub fn new(key: UnboundKey) -> Self {
        Self { key }
    }

    /// Like [`OpeningKey::open_in_place()`], except it accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    ///
    #[inline]
    pub fn open_in_place<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        self.open_within(nonce, aad, in_out, 0..)
    }

    /// Like [`OpeningKey::open_within()`], except it accepts an arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to open data.
    ///
    /// # Errors
    /// `error::Unspecified` when ciphertext is invalid.
    ///
    #[inline]
    pub fn open_within<'in_out, A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &'in_out mut [u8],
        ciphertext_and_tag: RangeFrom<usize>,
    ) -> Result<&'in_out mut [u8], Unspecified>
    where
        A: AsRef<[u8]>,
    {
        open_within_(&self.key, nonce, aad, in_out, ciphertext_and_tag)
    }

    /// Deprecated. Renamed to `seal_in_place_append_tag()`.
    #[deprecated(note = "Renamed to `seal_in_place_append_tag`.")]
    #[inline]
    #[allow(clippy::missing_errors_doc)]
    pub fn seal_in_place<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        self.seal_in_place_append_tag(nonce, aad, in_out)
    }

    /// Like [`SealingKey::seal_in_place_append_tag()`], except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    ///
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_append_tag<A, InOut>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut InOut,
    ) -> Result<(), Unspecified>
    where
        A: AsRef<[u8]>,
        InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
    {
        seal_in_place_append_tag_(&self.key, nonce, Aad::from(aad.as_ref()), in_out)
    }

    /// Like `SealingKey::seal_in_place_separate_tag()`, except it accepts an
    /// arbitrary nonce.
    ///
    /// `nonce` must be unique for every use of the key to seal data.
    ///
    /// # Errors
    /// `error::Unspecified` if encryption operation fails.
    ///
    #[inline]
    #[allow(clippy::needless_pass_by_value)]
    pub fn seal_in_place_separate_tag<A>(
        &self,
        nonce: Nonce,
        aad: Aad<A>,
        in_out: &mut [u8],
    ) -> Result<Tag, Unspecified>
    where
        A: AsRef<[u8]>,
    {
        seal_in_place_separate_tag_(&self.key, nonce, Aad::from(aad.as_ref()), in_out)
    }

    /// The key's AEAD algorithm.
    #[inline]
    pub fn algorithm(&self) -> &'static Algorithm {
        self.key.algorithm
    }
}

impl Debug for LessSafeKey {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        f.debug_struct("LessSafeKey")
            .field("algorithm", self.algorithm())
            .finish()
    }
}

/// An AEAD Algorithm.
pub struct Algorithm {
    init: fn(key: &[u8]) -> Result<KeyInner, Unspecified>,
    key_len: usize,
    id: AlgorithmID,

    // /// Use `max_input_len!()` to initialize this.
    // TODO: Make this `usize`.
    max_input_len: u64,
}

impl Algorithm {
    /// The length of the key.
    #[inline]
    #[must_use]
    pub fn key_len(&self) -> usize {
        self.key_len
    }

    /// The length of a tag.
    ///
    /// See also `MAX_TAG_LEN`.
    #[inline]
    #[must_use]
    pub fn tag_len(&self) -> usize {
        TAG_LEN
    }

    /// The length of the nonces.
    #[inline]
    #[must_use]
    pub fn nonce_len(&self) -> usize {
        NONCE_LEN
    }
}

derive_debug_via_id!(Algorithm);

#[derive(Debug, Eq, PartialEq, Copy, Clone)]
#[allow(non_camel_case_types)]
enum AlgorithmID {
    AES_128_GCM,
    AES_256_GCM,
    CHACHA20_POLY1305,
}

impl PartialEq for Algorithm {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for Algorithm {}

/// An authentication tag.
#[must_use]
#[repr(C)]
pub struct Tag([u8; TAG_LEN]);

impl AsRef<[u8]> for Tag {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

#[allow(dead_code)]
const MAX_KEY_LEN: usize = 32;

// All the AEADs we support use 128-bit tags.
const TAG_LEN: usize = 16;

/// The maximum length of a tag for the algorithms in this module.
pub const MAX_TAG_LEN: usize = TAG_LEN;

#[inline]
#[must_use]
pub const fn u64_from_usize(x: usize) -> u64 {
    x as u64
}

#[inline]
fn check_per_nonce_max_bytes(alg: &Algorithm, in_out_len: usize) -> Result<(), Unspecified> {
    if u64_from_usize(in_out_len) > alg.max_input_len {
        return Err(Unspecified);
    }
    Ok(())
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_seal_combined<InOut>(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut InOut,
) -> Result<(), Unspecified>
where
    InOut: AsMut<[u8]> + for<'in_out> Extend<&'in_out u8>,
{
    unsafe {
        let aead_ctx = match key {
            KeyInner::AES_128_GCM(.., aead_ctx)
            | KeyInner::AES_256_GCM(.., aead_ctx)
            | KeyInner::CHACHA20_POLY1305(.., aead_ctx) => aead_ctx,
        };
        let nonce = nonce.as_ref();

        let plaintext_len = in_out.as_mut().len();

        in_out.extend([0u8; TAG_LEN].iter());

        let mut out_len = MaybeUninit::<usize>::uninit();
        let mut_in_out = in_out.as_mut();
        let add_str = aad.0;

        if 1 != aws_lc_sys::EVP_AEAD_CTX_seal(
            aead_ctx,
            mut_in_out.as_mut_ptr(),
            out_len.as_mut_ptr(),
            plaintext_len + TAG_LEN,
            nonce.as_ptr(),
            NONCE_LEN,
            mut_in_out.as_ptr(),
            plaintext_len,
            add_str.as_ptr(),
            add_str.len(),
        ) {
            return Err(Unspecified);
        }

        Ok(())
    }
}

#[inline]
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn aead_open_combined(
    key: &KeyInner,
    nonce: Nonce,
    aad: Aad<&[u8]>,
    in_out: &mut [u8],
) -> Result<(), Unspecified> {
    unsafe {
        let aead_ctx = match key {
            KeyInner::AES_128_GCM(.., aead_ctx)
            | KeyInner::AES_256_GCM(.., aead_ctx)
            | KeyInner::CHACHA20_POLY1305(.., aead_ctx) => aead_ctx,
        };
        let nonce = nonce.as_ref();

        let plaintext_len = in_out.len() - TAG_LEN;

        let aad_str = aad.0;
        let mut out_len = MaybeUninit::<usize>::uninit();
        if 1 != aws_lc_sys::EVP_AEAD_CTX_open(
            aead_ctx,
            in_out.as_mut_ptr(),
            out_len.as_mut_ptr(),
            plaintext_len,
            nonce.as_ptr(),
            NONCE_LEN,
            in_out.as_ptr(),
            plaintext_len + TAG_LEN,
            aad_str.as_ptr(),
            aad_str.len(),
        ) {
            return Err(Unspecified);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test::from_hex;

    #[test]
    fn test_aes_128() {
        let key = from_hex("000102030405060708090a0b0c0d0e0f").unwrap();
        let og_nonce = from_hex("5bf11a0951f0bfc7ea5c9e58").unwrap();
        let plaintext = from_hex("00112233445566778899aabbccddeeff").unwrap();
        let unbound_key = UnboundKey::new(&AES_128_GCM, &key).unwrap();
        let less_safe_key = LessSafeKey::new(unbound_key);

        let nonce: [u8; NONCE_LEN] = og_nonce.as_slice().try_into().unwrap();
        let mut in_out = Vec::from(plaintext.as_slice());

        less_safe_key
            .seal_in_place_append_tag(Nonce(nonce), Aad::empty(), &mut in_out)
            .unwrap();

        let nonce: [u8; NONCE_LEN] = og_nonce.as_slice().try_into().unwrap();
        less_safe_key
            .open_in_place(Nonce(nonce), Aad::empty(), &mut in_out)
            .unwrap();

        assert_eq!(plaintext, in_out[..plaintext.len()]);
    }
}
