use curv::cryptographic_primitives::secret_sharing::feldman_vss::ShamirSecretSharing;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::containers::push::Push;
use round_based::Msg;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::threshold_bls::party_i;
use crate::types::*;

#[derive(Serialize, Deserialize)]
pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
        where
            O: Push<Msg<party_i::KeyGenComm>>,
    {
        let keys = party_i::Keys::phase1_create(self.party_i);
        let (comm, decom) = keys.phase1_broadcast();
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: comm.clone(),
        });
        Ok(Round1 {
            keys,
            comm,
            decom,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

#[derive(Serialize, Deserialize)]
pub struct Round1 {
    keys: party_i::Keys,
    comm: party_i::KeyGenComm,
    decom: party_i::KeyGenDecom,

    pub(crate) party_i: u16,
    pub(crate) t: u16,
    pub(crate) n: u16,
}

impl Round1 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<party_i::KeyGenComm>,
        mut output: O,
    ) -> Result<Round2>
        where
            O: Push<Msg<party_i::KeyGenDecom>>,
    {
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: self.decom.clone(),
        });
        Ok(Round2 {
            keys: self.keys,
            received_comm: input.into_vec_including_me(self.comm),
            decom: self.decom.clone(),

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<party_i::KeyGenComm>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Round2 {
    keys: party_i::Keys,
    received_comm: Vec<party_i::KeyGenComm>,
    decom: party_i::KeyGenDecom,

    pub(crate) party_i: u16,
    pub(crate) t: u16,
    pub(crate) n: u16,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<party_i::KeyGenDecom>,
        mut output: O,
    ) -> Result<Round3>
        where
            O: Push<Msg<party_i::KeyShare>>,
    {
        let params = ShamirSecretSharing {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let received_decom = input.into_vec_including_me(self.decom);
        let (vss_scheme, secret_shares, _) = self
            .keys
            .phase1_verify_com_phase2_distribute(&params, &received_decom, &self.received_comm)
            .map_err(ProceedError::Round2VerifyCommitments)?;
        for (j, share) in secret_shares.iter().enumerate() {
            if j + 1 == usize::from(self.party_i) {
                continue;
            }

            output.push(Msg {
                sender: self.party_i,
                receiver: Some(j as u16 + 1),
                body: party_i::KeyShare{
                    i: self.party_i,
                    t: self.t,
                    n: self.n,
                    j: j as u16 + 1,
                    commitments: vss_scheme.commitments.clone(),
                    share: share.clone()
                },
            })
        }

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),
            own_share: party_i::KeyShare{
                i: self.party_i,
                t: self.t,
                n: self.n,
                j: self.party_i,
                commitments: vss_scheme.commitments,
                share: secret_shares[usize::from(self.party_i - 1)].clone(),
            },

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<party_i::KeyGenDecom>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Round3 {
    keys: party_i::Keys,

    y_vec: Vec<PkPoint>,

    own_share: party_i::KeyShare,

    pub(crate) party_i: u16,
    pub(crate) t: u16,
    pub(crate) n: u16,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<party_i::KeyShare>,
        mut output: O,
    ) -> Result<Round4>
        where
            O: Push<Msg<KeyProof>>,
    {
        let params = ShamirSecretSharing {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let (vss_schemes, party_shares): (Vec<_>, Vec<_>) = input
            .into_vec_including_me(self.own_share)
            .into_iter()
            .map(
                |s|{
                    let scheme = KeyVss{
                        parameters: params.clone(),
                        commitments: s.commitments.clone(),
                    };
                    (scheme, s.share)
                }
            )
            .unzip();

        let y_vec = self.y_vec.iter().map(|y| y.clone()).collect::<Vec<PkPoint>>();
        let (shared_keys, dlog_proof) = self
            .keys
            .phase2_verify_vss_construct_keypair_prove_dlog(
                &params,
                &y_vec,
                &party_shares,
                &vss_schemes,
                &self.party_i
            )
            .map_err(ProceedError::Round3VerifyVssConstruct)?;

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: dlog_proof.clone(),
        });

        Ok(Round4 {
            shared_keys,
            own_dlog_proof: dlog_proof,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<party_i::KeyShare>> {
        containers::P2PMsgsStore::new(i, n)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Round4 {
    shared_keys: party_i::SharedKey,
    own_dlog_proof: KeyProof,

    pub(crate) party_i: u16,
    pub(crate) t: u16,
    pub(crate) n: u16,
}

impl Round4 {
    pub fn proceed(self, input: BroadcastMsgs<KeyProof>) -> Result<party_i::LocalKey> {
        let params = ShamirSecretSharing {
            threshold: self.t.into(),
            share_count: self.n.into(),
        };
        let dlog_proofs = input.into_vec_including_me(self.own_dlog_proof);
        party_i::Keys::verify_dlog_proofs(&params, &dlog_proofs)
            .map_err(ProceedError::Round4VerifyDLogProof)?;
        let vk_vec = dlog_proofs.into_iter().map(|p| p.pk).collect();
        Ok(party_i::LocalKey {
            shared_key: self.shared_keys,
            vk_vec,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyProof>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

// Errors

type Result<T> = std::result::Result<T, ProceedError>;

/// Proceeding protocol error
///
/// Subset of [keygen errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 2: verify commitments: {0:?}")]
    Round2VerifyCommitments(crate::Error),
    #[error("round 3: verify vss construction: {0:?}")]
    Round3VerifyVssConstruct(crate::Error),
    #[error("round 4: verify dlog proof: {0:?}")]
    Round4VerifyDLogProof(crate::Error),
}
