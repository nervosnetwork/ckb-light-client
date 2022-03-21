use std::collections::HashMap;

use ckb_merkle_mountain_range::{leaf_index_to_mmr_size, leaf_index_to_pos};
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{
    core::{BlockNumber, HeaderView},
    packed,
    prelude::*,
    utilities::merkle_mountain_range::{ChainRootMMR, MMRProof},
};
use log::{error, info, warn};
use rand::{prelude::*, thread_rng};

use super::{
    super::{prelude::*, Peers, Status, StatusCode},
    BlockSamplingStrategy,
};

const CHECK_RATIO: usize = 10;

pub struct NaiveApproach {
    honest_peer: Option<PeerIndex>,
    peers: Peers,
    proofs: HashMap<PeerIndex, (Vec<BlockNumber>, Option<bool>)>,
}

impl BlockSamplingStrategy for NaiveApproach {
    fn new() -> Self {
        Self {
            honest_peer: None,
            peers: Peers::default(),
            proofs: HashMap::new(),
        }
    }

    fn honest_peer(&self) -> Option<PeerIndex> {
        self.honest_peer
    }

    fn peers(&self) -> &Peers {
        &self.peers
    }

    fn mut_peers(&mut self) -> &mut Peers {
        &mut self.peers
    }

    fn start(&mut self, nc: &dyn CKBProtocolContext) {
        let peers = self.peers.get_peers_which_are_ready();
        for (peer, state) in peers {
            let mmr_activated_number = state
                .mmr_activated_number
                .expect("checked: mmr_activated_number is not none");
            let last_header = state.last_header.expect("checked: last_header is not none");
            let last_hash = last_header.hash();
            let last_number = last_header.number();

            let blocks_count = last_number - mmr_activated_number;
            let checked_block_count = {
                let tmp = blocks_count as usize / CHECK_RATIO;
                if tmp == 0 {
                    1
                } else {
                    tmp
                }
            };

            let numbers = {
                let mut tmp = (mmr_activated_number..last_number).collect::<Vec<_>>();
                let mut rng = thread_rng();
                tmp.shuffle(&mut rng);
                tmp.truncate(checked_block_count);

                tmp.sort();
                tmp.dedup();
                tmp
            };

            let content = packed::GetBlockProof::new_builder()
                .last_hash(last_hash)
                .numbers(numbers.pack())
                .build();
            let message = packed::LightClientMessage::new_builder()
                .set(content)
                .build();
            nc.reply(peer, &message);

            self.proofs.insert(peer, (numbers, None));
        }
    }

    fn handle_block_proof(
        &mut self,
        peer: PeerIndex,
        message: packed::SendBlockProofReader<'_>,
    ) -> Status {
        if self.honest_peer().is_some() {
            return Status::ok(); // TODO add a new status to skip
        }

        let mmr_activated_number =
            if let Some(mmr_activated_number) = self.peers().get_mmr_activated_number(&peer) {
                mmr_activated_number
            } else {
                warn!("mmr_activated_number is not existed");
                return StatusCode::InternalError.into(); // TODO add a new status for this error
            };

        let numbers_in_request: Vec<_> = if let Some((numbers, _)) = self.proofs.get(&peer) {
            numbers.clone()
        } else {
            warn!("numbers for sending block proof is not existed");
            return StatusCode::InternalError.into(); // TODO add a new status for this error
        };

        let chain_root = message.root().to_entity();
        let proof: MMRProof = message.proof().unpack();
        let headers = message
            .headers()
            .iter()
            .map(|header| header.to_entity().into_view())
            .collect::<Vec<_>>();

        let numbers_in_response: Vec<_> = headers.iter().map(HeaderView::number).collect();
        if &numbers_in_request != &numbers_in_response {
            return StatusCode::InternalError.into(); // TODO add a new status for this error
        }

        let digests_with_positions = headers
            .iter()
            .map(|header| {
                let index = header.number() - mmr_activated_number;
                let position = leaf_index_to_pos(index);
                let digest = header.digest();
                (position, digest)
            })
            .collect::<Vec<_>>();

        let result = proof.verify(chain_root, digests_with_positions).unwrap();
        if result {
            info!("passed: verify mmr proof");
        } else {
            error!("failed: verify mmr proof");
        }

        self.proofs.entry(peer).and_modify(|e| e.1 = Some(result));

        Status::ok()
    }

    fn try_find_honest(&mut self) -> Option<PeerIndex> {
        if self.honest_peer().is_none() {
            let honest_peer = self
                .proofs
                .iter()
                .filter_map(|(peer, (_, state))| {
                    if state.unwrap_or(false) {
                        None
                    } else {
                        Some(peer)
                    }
                })
                .fold(None, |ret: Option<(PeerIndex, HeaderView)>, peer| {
                    if let Some(last_header) = self.peers().get_last_header(peer) {
                        if let Some((peer, last_header_prev)) = ret {
                            if last_header.number() < last_header_prev.number() {
                                Some((peer, last_header_prev))
                            } else {
                                Some((peer, last_header))
                            }
                        } else {
                            Some((*peer, last_header))
                        }
                    } else {
                        None
                    }
                })
                .map(|(peer, _)| peer);
            if honest_peer.is_some() {
                self.honest_peer = honest_peer;
            }
        }
        return self.honest_peer();
    }
}
