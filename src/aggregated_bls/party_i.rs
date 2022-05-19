use curv::arithmetic::traits::Modulo;
use curv::elliptic::curves::{ECPoint, Point};
use curv::elliptic::curves::ECScalar;
use curv::BigInt;
use curv_bls12_381::g1::GE1;
use curv_bls12_381::g2::GE2;
use curv_bls12_381::Pair;
use curv_bls12_381::scalar::FieldScalar;

use crate::aggregated_bls::h1;
use crate::basic_bls::BLSSignature;
type FE1 = FieldScalar;

/// This is an implementation of BDN18 [https://eprint.iacr.org/2018/483.pdf]
/// protocol 3.1 (MSP): pairing-based multi-signature with public-key aggregation
#[derive(PartialEq, Clone, Debug)]
pub struct Keys {
    pub sk_i: FE1,
    pub pk_i: GE1,
    pub party_index: usize,
}

pub type APK = GE1;
pub type SIG = GE2;

impl Keys {
    pub fn new(index: usize) -> Self {
        let u = FE1::random();
        let y = APK::generator().scalar_mul(&u);

        Keys {
            sk_i: u,
            pk_i: y,
            party_index: index,
        }
    }

    pub fn aggregate(pk_vec: &[GE1]) -> APK {
        let mut apk_plus_g = *GE1::generator();
        for (i, pk) in pk_vec.iter().enumerate() {
            let pt = &pk.scalar_mul(&ECScalar::from_bigint(&h1(i, pk_vec)));
            apk_plus_g.add_point_assign(pt);
        }
        apk_plus_g.sub_point(&GE1::generator())
    }

    pub fn local_sign(&self, message: &[u8], pk_vec: &[GE1]) -> SIG {
        let a_i = h1(self.party_index.clone(), pk_vec);
        let exp = BigInt::mod_mul(&a_i, &self.sk_i.to_bigint(), &FE1::group_order());
        let exp_fe1 = FE1::from_bigint(&exp);
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let h_0_m = GE2::hash_to_curve(message, dst);
        h_0_m.scalar_mul(&exp_fe1)
    }

    pub fn combine_local_signatures(sigs: &[SIG]) -> BLSSignature {
        let (head, tail) = sigs.split_at(1);
        let sig_sum = tail.iter().fold(head[0], |acc, x| acc.add_point(x));
        BLSSignature { sigma: sig_sum }
    }

    pub fn verify(signature: &BLSSignature, message: &[u8], apk: &APK) -> bool {
        signature.verify(message, apk)
    }

    pub fn batch_aggregate_bls(sig_vec: &[BLSSignature]) -> BLSSignature {
        let (head, tail) = sig_vec.split_at(1);
        BLSSignature {
            sigma: tail.iter().fold(head[0].sigma, |acc, x| acc.add_point(&x.sigma)),
        }
    }

    fn core_aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        assert!(apk_vec.len() >= 1);
        let product_c2 = Pair::compute_pairing(&Point::from_raw(GE1::generator().clone()).unwrap(), &Point::from_raw(sig.sigma).unwrap());

        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let vec_g1: Vec<GE2> = msg_vec.iter().map(|&x| GE2::hash_to_curve(&x, dst)).collect();
        let vec: Vec<_> = vec_g1.iter().zip(apk_vec.iter()).collect();
        let (head, tail) = vec.split_at(1);
        let product_c1 = tail
            .iter()
            .fold(Pair::compute_pairing(&Point::from_raw(head[0].1.clone()).unwrap(), &Point::from_raw(head[0].0.clone()).unwrap()), |acc, x| {
                acc.add_pair(&Pair::compute_pairing(&Point::from_raw(x.1.clone()).unwrap(), &Point::from_raw(x.0.clone()).unwrap()))
            });
        product_c1.e == product_c2.e
    }

    pub fn aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        assert!(apk_vec.len() == msg_vec.len());
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
