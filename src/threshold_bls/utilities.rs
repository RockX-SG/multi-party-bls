use curv::arithmetic::{Modulo, Zero};
use curv::BigInt;
use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::types::*;

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
    pub a1: PkPoint,
    pub a2: SigPoint,
    pub z: BigInt,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHStatement {
    pub g1: PkPoint,
    pub h1: PkPoint,
    pub g2: SigPoint,
    pub h2: SigPoint,
}

#[derive(Clone, PartialEq, Debug)]
pub struct ECDDHWitness {
    pub x: BigInt,
}

impl ECDDHProof {
    fn hash_scalar(&self, delta: &ECDDHStatement) -> PkScalar {
        let raw = Sha256::new()
            .chain_point(&delta.g2)
            .chain_point(&delta.h2)
            .chain_point(&delta.g1)
            .chain_point(&delta.h1)
            .chain_point(&self.a1)
            .chain_point(&self.a2)
            .result_scalar::<PkCurve>().into_raw();
        PkScalar::from_raw(raw)
    }

    pub fn prove(w: &ECDDHWitness, delta: &ECDDHStatement) -> ECDDHProof {
        let s1 = PkScalar::random();
        let a1 = &delta.g1 * &s1; // g1 * s1
        let mut s = s1.to_bigint();
        let s2 = SigScalar::from_bigint(&s);
        let a2 = &delta.g2 * &s2; // g2 * s2

        let mut my_proof = ECDDHProof {
            a1,
            a2,
            z: BigInt::zero(),
        };

        let e = my_proof.hash_scalar(delta).to_bigint();
        let z = &s + e * &w.x;
        let z = z.modulus(PkScalar::group_order());
        s1.into_raw().zeroize();
        s.zeroize();
        my_proof.z = z;
        my_proof
    }

    pub fn verify(&self, delta: &ECDDHStatement) -> bool {
        if self.z > *PkScalar::group_order() {
            return false;
        }
        let scalar_z1 = PkScalar::from_bigint(&self.z);
        let scalar_z2 = SigScalar::from_bigint(&self.z);
        let e = self.hash_scalar(delta);
        let z_g1 = &delta.g1 * (&scalar_z1);
        let z_g2 = &delta.g2 * (&scalar_z2);

        let a1_plus_e_h1 = &self.a1 + &delta.h1 * &e;
        let a2_plus_e_h2 = &self.a2 + &delta.h2 * &SigScalar::from_bigint(&e.to_bigint());
        z_g1 == a1_plus_e_h1 && z_g2 == a2_plus_e_h2
    }
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;

    use crate::types::*;

    use super::*;

    #[test]
    fn test_ecddh_proof() {
        let x1 = PkScalar::random();
        let x2 = SigScalar::from_bigint(&x1.to_bigint());

        let g1 = PkPoint::base_point2().clone();
        let g2 = SigPoint::generator().to_point();

        let h1 = &g1 * &x1;
        let h2 = &g2 * &x2;

        let delta = ECDDHStatement { g1, h1, g2, h2 };
        let w = ECDDHWitness { x: x1.to_bigint() };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta));
    }

    #[test]
    #[should_panic]
    fn test_bad_ecddh_proof() {
        let x1 = PkScalar::random();
        let x2 = SigScalar::from_bigint(&(x1.to_bigint() + BigInt::one())).into(); // bad


        let g1 = PkPoint::base_point2().clone();
        let g2 = SigPoint::generator().to_point();

        let h1 = &g1 * &x1;
        let h2 = &g2 * &x2;

        let delta = ECDDHStatement { g1, h1, g2, h2 };
        let w = ECDDHWitness { x: x1.to_bigint() };
        let proof = ECDDHProof::prove(&w, &delta);
        assert!(proof.verify(&delta));
    }
}
