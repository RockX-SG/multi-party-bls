use std::iter::Sum;
use std::ops::Add;

use curv::arithmetic::traits::*;
use curv::BigInt;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::SecretShares;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::basic_bls::BLSSignature;
use crate::Error;
use crate::threshold_bls::utilities::{ECDDHProof, ECDDHStatement, ECDDHWitness};
use crate::types::*;

const SECURITY: usize = 256;

/// The protocol follows threshold GLOW signature from  [https://eprint.iacr.org/2020/096.pdf] section VIII.
/// In our protocol we assume dishonest majority. We adapt the DKG accordingly.
/// Specifically, as robustness in not achievable, we follow the design of optimistic DKG:
/// In it, we hope that all parties behave honestly, however, if a party misbehaves all other members
/// are able to detect it and re-run the protocol without the faulty party. This design principle is common to
/// real world applications.
/// Frost [https://eprint.iacr.org/2020/852.pdf]  and GG19 [https://eprint.iacr.org/2019/114.pdf] DKGs
/// are two implementations that follows this design. We picked GG19 (see section 4.1) as the paper
/// provides a full security proof for the DKG.
/// We removed the RSA modulus generation from the DKG as this is unrelated to threshold BLS and do not affect the security proof.
/// We note that the DKG can probably be biased to some extent, however, we do not find it concerning
/// for the threshold BLS application.
#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct Keys {
    pub u_i: PkScalar,
    pub y_i: PkPoint,
    pub party_index: u16,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenComm {
    pub com: BigInt,
}

#[derive(PartialEq, Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecom {
    pub blind_factor: BigInt,
    pub y_i: PkPoint,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SharedKeys {
    pub index: u16,
    pub params: ShamirSecretSharing,
    pub vk: PkPoint,
    pub sk_i: PkScalar,
}

#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
pub struct PartialSignature {
    pub index: u16,
    pub sigma_i: SigPoint,
    pub ddh_proof: ECDDHProof,
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub struct Signature {
    pub sigma: SigPoint,
}

impl Keys {
    pub fn phase1_create(index: u16) -> Keys {
        let u = PkScalar::random();
        let y = PkPoint::generator() * &u;

        Keys {
            u_i: u,
            y_i: y,
            party_index: index,
        }
    }

    pub fn phase1_broadcast(&self) -> (KeyGenComm, KeyGenDecom) {
        let blind_factor = BigInt::sample(SECURITY);
        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &(BigInt::from_bytes(&self.y_i.to_bytes(true)[..]) + BigInt::from(self.party_index as u32)), // we add context to the hash function
            &blind_factor,
        );
        let bcm1 = KeyGenComm { com };
        let decm1 = KeyGenDecom {
            blind_factor,
            y_i: self.y_i.clone(),
        };
        (bcm1, decm1)
    }

    pub fn phase1_verify_com_phase2_distribute(
        &self,
        params: &ShamirSecretSharing,
        decom_vec: &Vec<KeyGenDecom>,
        bc1_vec: &Vec<KeyGenComm>,
    ) -> Result<(KeyVss, SecretShares<PkCurve>, u16), Error> {
        // test length:
        if decom_vec.len() != params.share_count as usize || bc1_vec.len() != params.share_count as usize {
            return Err(Error::KeyGenMisMatchedVectors);
        }
        // test decommitments
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &(BigInt::from_bytes(&decom_vec[i].y_i.to_bytes(true)[..]) + BigInt::from(i as u32)),
                    &decom_vec[i].blind_factor,
                ) == bc1_vec[i].com
            })
            .all(|x| x == true);

        let (vss_scheme, secret_shares) =
            KeyVss::share(params.threshold, params.share_count, &self.u_i);

        match correct_key_correct_decom_all {
            true => Ok((vss_scheme, secret_shares, self.party_index.clone())),
            false => Err(Error::KeyGenBadCommitment),
        }
    }

    pub fn phase2_verify_vss_construct_keypair_prove_dlog(
        &self,
        params: &ShamirSecretSharing,
        y_vec: &Vec<PkPoint>,
        secret_shares_vec: &Vec<PkScalar>,
        vss_scheme_vec: &Vec<KeyVss>,
        index: &u16,
    ) -> Result<(SharedKeys, KeyProof), Error> {
        if y_vec.len() != params.share_count as usize
            || secret_shares_vec.len() != params.share_count as usize
            || vss_scheme_vec.len() != params.share_count as usize
        {
            return Err(Error::KeyGenMisMatchedVectors);
        }

        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], *index)
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0].clone() == y_vec[i]
            })
            .all(|x| x == true);

        match correct_ss_verify {
            true => {
                let y = PkPoint::sum(y_vec.iter());
                let x_i = PkScalar::sum(secret_shares_vec.iter());
                let dlog_proof = KeyProof::prove(&x_i);
                Ok((
                    SharedKeys {
                        index: self.party_index,
                        params: params.clone(),
                        vk: y,
                        sk_i: x_i,
                    },
                    dlog_proof,
                ))
            }
            false => Err(Error::KeyGenInvalidShare),
        }
    }

    pub fn verify_dlog_proofs(
        params: &ShamirSecretSharing,
        dlog_proofs_vec: &[KeyProof],
    ) -> Result<(), Error> {
        if dlog_proofs_vec.len() != params.share_count as usize {
            return Err(Error::KeyGenMisMatchedVectors);
        }
        let xi_dlog_verify = (0..dlog_proofs_vec.len())
            .map(|i| KeyProof::verify(&dlog_proofs_vec[i]).is_ok())
            .all(|x| x);

        if xi_dlog_verify {
            Ok(())
        } else {
            Err(Error::KeyGenDlogProofError)
        }
    }
}

impl SharedKeys {
    pub fn get_shared_pubkey(&self) -> PkPoint {
        PkPoint::generator().to_point() * &self.sk_i
    }

    pub fn partial_sign(&self, x: &[u8]) -> (PartialSignature, SigPoint) {
        let dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_bytes();
        let H_x = hash_to_curve(x, dst);
        let sigma_i = &H_x * &SigScalar::from_raw(self.sk_i.clone().into_raw());

        let sk_bn = self.sk_i.to_bigint();
        let w = ECDDHWitness { x: sk_bn };

        let delta = ECDDHStatement {
            g2: H_x.clone(),
            h2: sigma_i.clone(),
            g1: PkPoint::generator().to_point(),
            h1: self.get_shared_pubkey(),
        };
        let ddh_proof = ECDDHProof::prove(&w, &delta);
        assert!(ddh_proof.verify(&delta));

        (
            PartialSignature {
                index: self.index,
                sigma_i,
                ddh_proof,
            },
            H_x,
        )
    }

    pub fn combine(
        &self,
        vk_vec: &[PkPoint],
        partial_sigs_vec: &[PartialSignature],
        H_x: &SigPoint,
        s: &[u16],
    ) -> Result<BLSSignature, Error> {
        if vk_vec.len() != partial_sigs_vec.len()
            || vk_vec.len() < self.params.threshold as usize
            || s.len() < self.params.threshold as usize
            || s.len() > self.params.share_count as usize
        {
            return Err(Error::SigningMisMatchedVectors);
        }
        //verify ec_ddh proofs and signatures

        let partial_sigs_verify = (0..vk_vec.len())
            .map(|i| {
                let delta = ECDDHStatement {
                    g2: H_x.clone(),
                    h2: partial_sigs_vec[i].sigma_i.clone(),
                    g1: PkPoint::generator().to_point(),
                    h1: vk_vec[i].clone(),
                };

                partial_sigs_vec[i].ddh_proof.verify(&delta)
            })
            .all(|x| x);
        if partial_sigs_verify == false {
            return Err(Error::PartialSignatureVerificationError);
        }
        let sigma_s = partial_sigs_vec[0..usize::from(self.params.threshold) + 1].iter()
            .map(|sig| {
                &sig.sigma_i * &SigVss::map_share_to_new_params(
                    &self.params,
                    sig.index as u16,
                    &s[0..usize::from(self.params.threshold) + 1],
                )
            });
        let sigma = SigPoint::sum(sigma_s);

        return Ok(BLSSignature { sigma });
    }

    // check e(H(m), vk) == e(sigma, g2)
    pub fn verify(&self, sig: &BLSSignature, x: &[u8]) -> bool {
        sig.verify(x, &self.vk)
    }
}
