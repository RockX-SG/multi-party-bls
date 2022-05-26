#![allow(non_snake_case)]

use curv::BigInt;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use sha2::Sha256;

use crate::types::*;

pub mod party_i;
#[cfg(any(test, feature = "dev"))]
pub mod test;

pub fn h1(index: usize, pk_vec: &[PkPoint]) -> BigInt {
    Sha256::new().chain_point(&pk_vec[index]).chain_points(pk_vec.iter()).result_bigint()
}
