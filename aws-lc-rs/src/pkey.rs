// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0 OR ISC

//! Public/private key types.
//!
//! This module provides raw key pair types.

/// Elliptic curve keys.
pub mod elliptic_curve {
    pub use crate::ec::key_pair::{Algorithm, P256, P256K1, P384, P521};
    pub use crate::ec::key_pair::{KeyPair, PrivateKey, PublicKey};
}
