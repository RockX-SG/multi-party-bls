#![allow(non_snake_case)]

use anyhow::Result;
use curv::arithmetic::Converter;
use curv::BigInt;
use group::Group;

use crate::types::*;

/// Based on https://eprint.iacr.org/2018/483.pdf
#[derive(Clone, Debug)]
pub struct Key {
    x: PkScalar,
}

#[derive(Clone, Debug, PartialEq)]
pub struct BLSSignature {
    pub sigma: SigPoint,
}

impl Key {
    pub fn new() -> Self {
        let x = PkScalar::random();
        Key { x }
    }

    pub fn from_hex(sk: &str) -> Result<Self> {
        let sk: Vec<u8> = hex::decode(sk)?;

        let sk = BigInt::from_bytes(&sk);

        let x = PkScalar::from_bigint(&sk);

        let keypair = Key {
            x,
        };
        Ok(keypair)
    }
    pub fn public_key(&self) -> PkPoint {
        PkPoint::generator() * &self.x
    }
}

impl BLSSignature {
    // compute sigma  = x H(m)
    pub fn sign(message: &[u8], keys: &Key) -> Self {
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let H_m = hash_to_curve(message, dst);
        BLSSignature {
            sigma: &H_m * &SigScalar::from_raw(keys.x.as_raw().clone()),
        }
    }

    // check e(H(m), Y) == e(sigma, g2)
    pub fn verify(&self, message: &[u8], pubkey: &PkPoint) -> bool {
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let H_m = hash_to_curve(message, dst);
        let neg_one = -PkPoint::generator().to_point();
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
        let key = Key::new();
        let message_bytes = [1, 2, 3, 4, 5];
        let signature = BLSSignature::sign(&message_bytes[..], &key);
        assert!(signature.verify(&message_bytes[..], &key.public_key()));
    }

    #[test]
    #[should_panic]
    pub fn test_bad_simple_bls() {
        let key = Key::new();
        let message_bytes = [1, 2, 3, 4, 5];
        let signature = BLSSignature::sign(&message_bytes[..], &key);
        let message_bytes_corrupt = [0, 2, 3, 4, 5];
        assert!(signature.verify(&message_bytes_corrupt[..], &key.public_key()));
    }

    #[test]
    pub fn test_bls_eth_vectors() {
        // https://media.githubusercontent.com/media/ethereum/consensus-spec-tests/master/tests/general/phase0/bls/sign/small/sign_case_142f678a8d05fcd1/data.yaml
        let sk = "47b8192d77bf871b62e87859d653922725724a5c031afeabc60bcef5ff665138";
        let msg = "5656565656565656565656565656565656565656565656565656565656565656";
        let sig = "af1390c3c47acdb37131a51216da683c509fce0e954328a59f93aebda7e4ff974ba208d9a4a2a2389f892a9d418d618418dd7f7a6bc7aa0da999a9d3a5b815bc085e14fd001f6a1948768a3f4afefc8b8240dda329f984cb345c6363272ba4fe";

        let key = Key::from_hex(sk).unwrap();
        let message_bytes = hex::decode(msg).unwrap();
        let signature = BLSSignature::sign(&message_bytes[..], &key);
        let sigBytes = signature.to_bytes(true);

        assert!(signature.verify(&message_bytes[..], &key.public_key()));
        assert_eq!(sig, hex::encode(sigBytes));
    }
}
