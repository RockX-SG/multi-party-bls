#![allow(non_snake_case)]

use curv::BigInt;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::Point;
use curv_bls12_381::Bls12_381_1;
use sha2::Sha256;

pub mod party_i;
#[cfg(any(test, feature = "dev"))]
pub mod test;

pub fn h1(index: usize, pk_vec: &[Point<Bls12_381_1>]) -> BigInt {
    Sha256::new().chain_point(&pk_vec[index]).chain_points(pk_vec.iter()).result_bigint()
}
