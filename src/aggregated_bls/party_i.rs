use std::iter::Sum;

use curv::arithmetic::traits::Modulo;
use curv::BigInt;

use crate::aggregated_bls::h1;
use crate::basic_bls::BLSSignature;
use crate::types::*;

/// This is an implementation of BDN18 [https://eprint.iacr.org/2018/483.pdf]
/// protocol 3.1 (MSP): pairing-based multi-signature with public-key aggregation
#[derive(PartialEq, Clone, Debug)]
pub struct Keys {
    pub sk_i: PkScalar,
    pub pk_i: PkPoint,
    pub party_index: usize,
}

impl Keys {
    pub fn new(index: usize) -> Self {
        let u = PkScalar::random();
        let y = PkPoint::generator() * &u;

        Keys {
            sk_i: u,
            pk_i: y,
            party_index: index,
        }
    }

    pub fn aggregate(pk_vec: &[PkPoint]) -> PkPoint {
        let pk_s = pk_vec.iter().enumerate().map(|(i, pk)| {
            pk * &PkScalar::from_bigint(&h1(i, pk_vec))
        });
        PkPoint::sum(pk_s)
    }

    pub fn local_sign(&self, message: &[u8], pk_vec: &[PkPoint]) -> SigPoint {
        let a_i = h1(self.party_index.clone(), pk_vec);
        let exp = BigInt::mod_mul(&a_i, &self.sk_i.to_bigint(), &PkScalar::group_order());
        let exp_fe1 = SigScalar::from_bigint(&exp);
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let h_0_m = hash_to_curve(message, dst);
        h_0_m * &exp_fe1
    }

    pub fn combine_local_signatures(sigs: &[SigPoint]) -> BLSSignature {
        let sig_sum = SigPoint::sum(sigs.iter());
        BLSSignature { sigma: sig_sum }
    }

    pub fn verify(signature: &BLSSignature, message: &[u8], apk: &PkPoint) -> bool {
        signature.verify(message, apk)
    }

    pub fn batch_aggregate_bls(sig_vec: &[BLSSignature]) -> BLSSignature {
        let inner_vec = sig_vec.iter().map(|sig| {
            &sig.sigma
        });
        let sig_sum = SigPoint::sum(inner_vec);
        BLSSignature {
            sigma: sig_sum,
        }
    }

    fn core_aggregate_verify(apk_vec: &[PkPoint], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        assert!(apk_vec.len() >= 1);
        let product_c2 = Pair::compute_pairing(&PkPoint::generator().to_point(), &sig.sigma);

        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let vec_g1: Vec<SigPoint> = msg_vec.iter().map(|&x| hash_to_curve(&x, dst)).collect();
        let vec: Vec<_> = vec_g1.iter().zip(apk_vec.iter()).collect();
        let (head, tail) = vec.split_at(1);
        let product_c1 = tail
            .iter()
            .fold(Pair::compute_pairing(&head[0].1, &head[0].0), |acc, x| {
                acc.add_pair(&Pair::compute_pairing(&x.1, &x.0))
            });
        product_c1.e == product_c2.e
    }

    pub fn aggregate_verify(apk_vec: &[PkPoint], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        assert_eq!(apk_vec.len(), msg_vec.len());
        if {
            let mut tmp = msg_vec.to_vec();
            tmp.sort();
            tmp.dedup();
            tmp.len() != msg_vec.len()
        } {
            return false; // verification fails if there is a repeated message
        }
        Keys::core_aggregate_verify(apk_vec, msg_vec, sig)
    }
}
