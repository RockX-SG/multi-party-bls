#![allow(non_snake_case)]
use curv::BigInt;
use curv::elliptic::curves::Point;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv_bls12_381::g1::GE1;
use curv_bls12_381::Bls12_381_1;
use sha2::Sha256;

pub mod party_i;
#[cfg(any(test, feature = "dev"))]
pub mod test;

pub fn h1(index: usize, pk_vec: &[GE1]) -> BigInt {
    let mut pk = vec![Point::<Bls12_381_1>::from_raw(pk_vec[index]).unwrap()];
    let pk_ref_vec: Vec<_> = pk_vec.iter().map(|k| Point::<Bls12_381_1>::from_raw(*k).unwrap()).collect();
    pk.extend_from_slice(&pk_ref_vec[..]);
    Sha256::new().chain_points(pk.iter()).result_bigint()
}
