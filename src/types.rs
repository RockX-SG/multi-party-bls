use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{Curve, Point, Scalar};
use curv_bls12_381::{Bls12_381_1, Bls12_381_2};
use sha2::Sha256;

pub type PkCurve = Bls12_381_1;
pub type PkScalar = Scalar<Bls12_381_1>;
pub type PkPoint = Point<Bls12_381_1>;

pub type SigCurve = Bls12_381_2;
pub type SigScalar = Scalar<Bls12_381_2>;
pub type SigPoint = Point<Bls12_381_2>;
pub type Pair = curv_bls12_381::Pair;
pub(crate) type KeyVss = VerifiableSS<PkCurve>;
pub(crate) type SigVss = VerifiableSS<SigCurve>;
pub(crate) type KeyProof = DLogProof<PkCurve, Sha256>;

pub fn hash_to_curve(message: &[u8], dst: &[u8]) -> SigPoint {
    Point::from_raw(<SigCurve as Curve>::Point::hash_to_curve(message, dst)).unwrap()
}