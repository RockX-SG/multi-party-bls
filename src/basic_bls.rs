#![allow(non_snake_case)]

use std::convert::TryInto;
use curv::elliptic::curves::bls12_381::g1::FE as FE1;
use curv::elliptic::curves::bls12_381::g1::GE as GE1;
use curv::elliptic::curves::bls12_381::g2::{FE as FE2, G2Point};
use curv::elliptic::curves::bls12_381::g2::GE as GE2;
use curv::elliptic::curves::bls12_381::Pair;
use curv::elliptic::curves::traits::{ECPoint, ECScalar};

use ff_zeroize::Field;
use pairing_plus::bls12_381::{Fq12, G1Affine, G2, G2Affine};
use pairing_plus::CurveProjective;
use pairing_plus::hash_to_curve::HashToCurve;
use pairing_plus::hash_to_field::ExpandMsgXmd;
use pairing_plus::serdes::SerDes;
use crate::utils::g2_hash_to_curve;
use anyhow::Result;
use curv::BigInt;
use curv::arithmetic::Converter;

/// Based on https://eprint.iacr.org/2018/483.pdf

#[derive(Clone, Copy, Debug)]
pub struct KeyPairG2 {
    Y: GE1,
    x: FE1,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BLSSignature {
    pub sigma: GE2,
}

impl KeyPairG2 {
    pub fn new() -> Self {
        let x: FE1 = ECScalar::new_random();
        let Y = GE1::generator() * &x;
        KeyPairG2 { x, Y }
    }

    pub fn from_hex(sk:&str) -> Result<Self> {
        let sk:Vec<u8> = hex::decode(sk)?;

        let sk = BigInt::from_bytes(&sk);
        let x = ECScalar::from(&sk);
        let Y = GE1::generator() * &x;

        let keypair = KeyPairG2{
            x,Y
        };
        Ok(keypair)
    }
}

impl BLSSignature {
    // compute sigma  = x H(m)
    pub fn sign(message: &[u8], keys: &KeyPairG2) -> Self {
        let H_m = g2_hash_to_curve(message);
        let fe1_x: FE2 = ECScalar::from(&ECScalar::to_big_int(&keys.x));
        BLSSignature {
            sigma: H_m * &fe1_x,
        }
    }

    // check e(H(m), Y) == e(sigma, g2)
    pub fn verify(&self, message: &[u8], pubkey: &GE1) -> bool {
        let H_m = g2_hash_to_curve(message);
        let product = Pair::efficient_pairing_mul( pubkey,&H_m,  &(-GE1::generator()), &self.sigma);
        product.e == Fq12::one()
    }

    pub fn to_bytes(&self, compressed: bool) -> Vec<u8> {
        let mut pk = vec![];
        G2Affine::serialize( &self.sigma.get_element(),&mut pk, compressed)
            .expect("serialize to vec should always succeed");
        pk
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

        println!("pubkey is: {}", hex::encode(keypair.Y.pk_to_key_slice()));
        assert!(signature.verify(&message_bytes[..], &keypair.Y));
        assert_eq!(sig, hex::encode(sigBytes));
    }
}
