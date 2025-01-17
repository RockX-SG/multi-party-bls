use round_based::containers::{self, BroadcastMsgs, Store};
use round_based::containers::push::Push;
use round_based::Msg;
use thiserror::Error;

use crate::basic_bls::BLSSignature;
use crate::threshold_bls::party_i;
use crate::types::*;

pub struct Round0 {
    pub key: party_i::LocalKey,
    pub message: Vec<u8>,

    pub i: u16,
    pub n: u16,
}

impl Round0 {
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
        where
            O: Push<Msg<party_i::PartialSignature>>,
    {
        let (partial_sig, H_x) = self.key.shared_key.partial_sign(&self.message);
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: partial_sig.clone(),
        });
        Ok(Round1 {
            key: self.key,
            message: H_x,
            partial_sig,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    key: party_i::LocalKey,
    message: SigPoint,

    partial_sig: party_i::PartialSignature,
}

impl Round1 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<party_i::PartialSignature>,
    ) -> Result<(SigPoint, BLSSignature)> {
        let  sigs= input
            .into_vec_including_me(self.partial_sig);

        let mut vk_vec = vec![];
        for (party_i, sig) in sigs.iter().enumerate() {
            if sig.i == 0 || sig.i > self.key.shared_key.n {
                return Err(ProceedError::PartySentOutOfRangeIndex {
                    who: party_i as u16 + 1,
                    claimed_index: sig.i,
                });
            }
            vk_vec.push(self.key.vk_vec[usize::from(sig.i) - 1].clone())
        }

        let sig = self
            .key
            .shared_key
            .combine(vk_vec.as_slice(), &sigs, &self.message)
            .map_err(ProceedError::PartialSignatureVerification)?;
        Ok((self.message, sig))
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<BroadcastMsgs<party_i::PartialSignature>> {
        containers::BroadcastMsgsStore::new(i, n)
    }
}

// Errors

/// Proceeding protocol error
///
/// Subset of [signing errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    /// Every party needs to say which index it was using at keygen. This error is raised if
    /// `index == 0 || index > n` where n is a number of parties holding a key.
    #[error(
    "party {who} claimed its index at keygen was {claimed_index} which is not in range [1;n]"
    )]
    PartySentOutOfRangeIndex { who: u16, claimed_index: u16 },
    #[error("partial signatures verification: {0:?}")]
    PartialSignatureVerification(crate::Error),
}

type Result<T> = std::result::Result<T, ProceedError>;
