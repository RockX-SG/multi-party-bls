use curv::elliptic::curves::{ECPoint, Point};
use curv::elliptic::curves::ECScalar;
use curv::BigInt;
use curv::arithmetic::Modulo;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv_bls12_381::{Bls12_381_1, Bls12_381_2};
use curv_bls12_381::g1::GE1;
use curv_bls12_381::g2::GE2;
use curv_bls12_381::scalar::FieldScalar;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

type FE1 = FieldScalar;
type FE2 = FieldScalar;

/// NIZK required for our threshold BLS:
/// This is a special case of the ec ddh proof from Curv:
/// [https://github.com/ZenGo-X/curv/blob/master/src/cryptographic_primitives/proofs/sigma_ec_ddh.rs]
/// In which {g1,h1} belong to G1 group and {g2,h2} belong to G2 group.
/// This special case is possible when |G1| = |G2|. i.e the order of G1 group is equal to the order
/// of G2 (there is a map between the groups). This is the case for BLS12-381.
/// This is a deviation from the GLOW-BLS protocol that degrades security from strong-unforgeability
/// to standard-unforgeability,as defined in "Threshold Signatures, Multisignatures and Blind Signatures Based on the Gap-Diffie-Hellman-Group Signature Scheme"

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct ECDDHProof {
    pub a1: GE2,
    pub a2: GE1,
    pub z: BigInt,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHStatement {
    pub g1: GE2,
    pub h1: GE2,
    pub g2: GE1,
    pub h2: GE1,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHWitness {
    pub x: BigInt,
}

impl ECDDHProof {
    pub fn prove(w: &ECDDHWitness, delta: &ECDDHStatement) -> ECDDHProof {
        let mut s1 = FE2::random();
        let a1 = delta.g1.scalar_mul(&s1); // g1 * s1
        let s = s1.to_bigint();
        let mut s2: FE1 = ECScalar::from_bigint(&s);
        let a2 = delta.g2.scalar_mul(&s2); // g2 * s2
        let e = Sha256::new()
            .chain_point(&Point::<Bls12_381_2>::from_raw(delta.g1).unwrap())
            .chain_point(&Point::<Bls12_381_2>::from_raw(delta.h1).unwrap())
            .chain_point(&Point::<Bls12_381_1>::from_raw(delta.g2).unwrap())
            .chain_point(&Point::<Bls12_381_1>::from_raw(delta.h2).unwrap())
            .chain_point(&Point::<Bls12_381_2>::from_raw(a1).unwrap())
            .chain_point(&Point::<Bls12_381_1>::from_raw(a2).unwrap())
            .result_scalar::<Bls12_381_1>().into_raw().to_bigint();
        let z = s + e * &w.x;
        let z = z.modulus(FE1::group_order());
        s1.zeroize();
        s2.zeroize();
        ECDDHProof { a1, a2, z }
    }

    pub fn verify(&self, delta: &ECDDHStatement) -> bool {
        if self.z > *FE1::group_order() {
            return false;
        }
        let scalar_z = ECScalar::from_bigint(&self.z);
        let e = Sha256::new()
            .chain_point(&Point::<Bls12_381_2>::from_raw(delta.g1).unwrap())
            .chain_point(&Point::<Bls12_381_2>::from_raw(delta.h1).unwrap())
            .chain_point(&Point::<Bls12_381_1>::from_raw(delta.g2).unwrap())
            .chain_point(&Point::<Bls12_381_1>::from_raw(delta.h2).unwrap())
            .chain_point(&Point::<Bls12_381_2>::from_raw(self.a1).unwrap())
            .chain_point(&Point::<Bls12_381_1>::from_raw(self.a2).unwrap())
            .result_scalar::<Bls12_381_1>().into_raw();
        let z_g1 = &delta.g1.scalar_mul(&scalar_z);
        let z_g2 = &delta.g2.scalar_mul(&scalar_z);

        let a1_plus_e_h1 = &self.a1.add_point(&(&delta.h1.scalar_mul(&e)));
        let a2_plus_e_h2 = &self.a2.add_point(&(&delta.h2.scalar_mul(&e)));
        z_g1 == a1_plus_e_h1 && z_g2 == a2_plus_e_h2
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use curv::elliptic::curves::{ECPoint, ECScalar};
    use curv::arithmetic::traits::*;
    use curv_bls12_381::g2::GE2;
    use curv_bls12_381::scalar::FieldScalar as FE2;

    #[test]
    fn test_ecddh_proof() {
        let x = FE2::random().to_bigint();
        let g1 = *GE2::generator();
        let g2 = *GE1::base_point2();
        let h1 = g1.scalar_mul(&ECScalar::from_bigint(&x));
        let h2 = g2.scalar_mul(&ECScalar::from_bigint(&x));

        let delta = ECDDHStatement { g1, h1, g2, h2 };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta));
    }

    #[test]
    #[should_panic]
    fn test_bad_ecddh_proof() {
        let x = FE2::random().to_bigint();
        let g1 = *GE2::generator();
        let g2 = *GE1::base_point2();
        let h1 = g1.scalar_mul(&ECScalar::from_bigint(&x));
        let h2 = g2.scalar_mul(&ECScalar::from_bigint(&(&x + BigInt::one())));

        let delta = ECDDHStatement { g1, h1, g2, h2 };
        let w = ECDDHWitness { x };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta));
    }
}
