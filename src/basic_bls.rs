#![allow(non_snake_case)]

use anyhow::Result;
use curv::arithmetic::Converter;
use curv::BigInt;
use curv::elliptic::curves::{Point, Scalar};
use curv_bls12_381::{Bls12_381_1, Bls12_381_2, Pair};
use curv_bls12_381::g2::GE2;
use group::Group;

/// Based on https://eprint.iacr.org/2018/483.pdf
#[derive(Clone, Debug)]
pub struct KeyPairG2 {
    Y: Point<Bls12_381_1>,
    x: Scalar<Bls12_381_1>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BLSSignature {
    pub sigma: Point<Bls12_381_2>,
}

impl KeyPairG2 {
    pub fn new() -> Self {
        let x = Scalar::random();
        let Y = Point::generator() * &x;
        KeyPairG2 { x, Y }
    }

    pub fn from_hex(sk: &str) -> Result<Self> {
        let sk: Vec<u8> = hex::decode(sk)?;

        let sk = BigInt::from_bytes(&sk);

        let x = Scalar::from_bigint(&sk);
        let Y = Point::generator() * &x;

        let keypair = KeyPairG2 {
            x,
            Y,
        };
        Ok(keypair)
    }
}

impl BLSSignature {
    // compute sigma  = x H(m)
    pub fn sign(message: &[u8], keys: &KeyPairG2) -> Self {
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let H_m = Point::<Bls12_381_2>::from_raw(GE2::hash_to_curve(message, dst)).unwrap();
        BLSSignature {
            sigma: &H_m * &Scalar::from_raw(keys.x.clone().into_raw()),
        }
    }

    // check e(H(m), Y) == e(sigma, g2)
    pub fn verify(&self, message: &[u8], pubkey: &Point<Bls12_381_1>) -> bool {
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let H_m = Point::from_raw(GE2::hash_to_curve(message, dst)).unwrap();
        let neg_one = -Point::generator().to_point();
        let product = Pair::efficient_pairing_mul(
            &pubkey,
            &H_m,
            &neg_one,
            &self.sigma,
        );
        product.e.is_identity().into()
    }

    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        self.sigma.to_bytes(compressed).to_vec()
    }
}

mod test {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    pub fn test_simple_bls() {
        let keypair = KeyPairG2::new();
        let Y = keypair.Y.clone();
        let message_bytes = [1, 2, 3, 4, 5];
        let signature = BLSSignature::sign(&message_bytes[..], &keypair);
        assert!(signature.verify(&message_bytes[..], &Y));
    }

    #[test]
    #[should_panic]
    pub fn test_bad_simple_bls() {
        let keypair = KeyPairG2::new();
        let Y = keypair.Y.clone();
        let message_bytes = [1, 2, 3, 4, 5];
        let signature = BLSSignature::sign(&message_bytes[..], &keypair);
        let message_bytes_corrupt = [0, 2, 3, 4, 5];
        assert!(signature.verify(&message_bytes_corrupt[..], &Y));
    }

    #[test]
    pub fn test_bls_eth_vectors() {
        // https://media.githubusercontent.com/media/ethereum/consensus-spec-tests/master/tests/general/phase0/bls/sign/small/sign_case_142f678a8d05fcd1/data.yaml
        let sk = "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138";
        let msg = "5656565656565656565656565656565656565656565656565656565656565656";
        let sig = "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe";

        let keypair = KeyPairG2::from_hex(sk).unwrap();
        let message_bytes = hex::decode(msg).unwrap();
        let signature = BLSSignature::sign(&message_bytes[..], &keypair);
        let sigBytes = signature.to_bytes(true);

        assert!(signature.verify(&message_bytes[..], &keypair.Y));
        assert_eq!(sig, hex::encode(sigBytes));
    }
}
