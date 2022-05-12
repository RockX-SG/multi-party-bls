use curv::elliptic::curves::bls12_381::g2::G2Point;
use pairing_plus::bls12_381::{Fq12, G1Affine, G2, G2Affine};
use pairing_plus::CurveProjective;
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use sha2::Sha256;

pub fn g2_hash_to_curve(message: &[u8]) -> G2Point {
    let cs = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
    let point = <G2 as HashToCurve<ExpandMsgXmd<Sha256>>>::hash_to_curve(message, cs);
    G2Point::from(point.into_affine())
}
