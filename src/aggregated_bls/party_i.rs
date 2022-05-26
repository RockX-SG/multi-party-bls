use curv::arithmetic::traits::Modulo;
use curv::BigInt;
use curv::elliptic::curves::{Curve, Point, Scalar};
use curv::elliptic::curves::ECScalar;
use curv_bls12_381::{Bls12_381_1, Bls12_381_2, Pair};
use curv_bls12_381::scalar::FieldScalar;

use crate::aggregated_bls::h1;
use crate::basic_bls::BLSSignature;

type FE1 = FieldScalar;

/// This is an implementation of BDN18 [https://eprint.iacr.org/2018/483.pdf]
/// protocol 3.1 (MSP): pairing-based multi-signature with public-key aggregation
#[derive(PartialEq, Clone, Debug)]
pub struct Keys {
    pub sk_i: Scalar<Bls12_381_1>,
    pub pk_i: Point<Bls12_381_1>,
    pub party_index: usize,
}

pub type APK = Point<Bls12_381_1>;
pub type SIG = Point<Bls12_381_2>;

impl Keys {
    pub fn new(index: usize) -> Self {
        let u = Scalar::random();
        let y = Point::generator() * &u;

        Keys {
            sk_i: u,
            pk_i: y,
            party_index: index,
        }
    }

    pub fn aggregate(pk_vec: &[Point<Bls12_381_1>]) -> APK {
        let mut apk_plus_g = Point::generator().to_point();
        for (i, pk) in pk_vec.iter().enumerate() {
            let pt = pk * &Scalar::from_bigint(&h1(i, pk_vec));
            apk_plus_g = apk_plus_g + pt;
        }
        apk_plus_g = apk_plus_g - &Point::generator().to_point();
        apk_plus_g
    }

    pub fn local_sign(&self, message: &[u8], pk_vec: &[Point<Bls12_381_1>]) -> SIG {
        let a_i = h1(self.party_index.clone(), pk_vec);
        let exp = BigInt::mod_mul(&a_i, &self.sk_i.to_bigint(), &FE1::group_order());
        let exp_fe1 = Scalar::from_bigint(&exp);
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let h_0_m = Point::from_raw(<Bls12_381_2 as Curve>::Point::hash_to_curve(message, dst)).unwrap();
        h_0_m * &exp_fe1
    }

    pub fn combine_local_signatures(sigs: &[SIG]) -> BLSSignature {
        let (head, tail) = sigs.split_at(1);
        let sig_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);
        BLSSignature { sigma: sig_sum }
    }

    pub fn verify(signature: &BLSSignature, message: &[u8], apk: &APK) -> bool {
        signature.verify(message, apk)
    }

    pub fn batch_aggregate_bls(sig_vec: &[BLSSignature]) -> BLSSignature {
        let (head, tail) = sig_vec.split_at(1);
        BLSSignature {
            sigma: tail.iter().fold(head[0].sigma.clone(), |acc, x| &acc + &x.sigma),
        }
    }

    fn core_aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
        assert!(apk_vec.len() >= 1);
        let product_c2 = Pair::compute_pairing(&Point::generator(), &sig.sigma);

        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let vec_g1: Vec<Point<Bls12_381_2>> = msg_vec.iter().map(|&x| Point::from_raw(<Bls12_381_2 as Curve>::Point::hash_to_curve(&x, dst)).unwrap()).collect();
        let vec: Vec<_> = vec_g1.iter().zip(apk_vec.iter()).collect();
        let (head, tail) = vec.split_at(1);
        let product_c1 = tail
            .iter()
            .fold(Pair::compute_pairing(&head[0].1, &head[0].0), |acc, x| {
                acc.add_pair(&Pair::compute_pairing(&x.1, &x.0))
            });
        product_c1.e == product_c2.e
    }

    pub fn aggregate_verify(apk_vec: &[APK], msg_vec: &[&[u8]], sig: &BLSSignature) -> bool {
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
