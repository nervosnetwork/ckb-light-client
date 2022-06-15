//! Client-side implementation for CKB light client protocol.
//!
//! TODO(light-client) More documentation.

use std::sync::Arc;

use ckb_network::{bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_pow::{Pow, PowEngine};
use ckb_types::{packed, prelude::*, utilities::merkle_mountain_range::VerifiableHeader, U256};
use log::{debug, error, info, trace, warn};

mod components;
pub mod constant;
mod peers;
mod prelude;
mod sampling;

use prelude::*;

pub(crate) use self::peers::{PeerState, Peers, ProveState};
use super::{
    status::{Status, StatusCode},
    BAD_MESSAGE_BAN_TIME,
};
use crate::storage::Storage;

pub struct LightClientProtocol {
    storage: Storage,
    peers: Arc<Peers>,
    pow: Pow,
    best: Option<(PeerIndex, ProveState)>,
}

impl CKBProtocolHandler for LightClientProtocol {
    fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        info!("LightClient.protocol initialized");
        nc.set_notify(
            constant::REFRESH_PEERS_DURATION,
            constant::REFRESH_PEERS_TOKEN,
        )
        .expect("set_notify should be ok");
    }

    fn connected(
        &mut self,
        nc: Arc<dyn CKBProtocolContext + Sync>,
        peer: PeerIndex,
        version: &str,
    ) {
        info!("LightClient({}).connected peer={}", version, peer);
        self.peers().add_peer(peer);
        self.get_last_state(nc.as_ref(), peer);
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        info!("LightClient.disconnected peer={}", peer);
        self.peers().remove_peer(peer);
    }

    fn received(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex, data: Bytes) {
        trace!("LightClient.received peer={}", peer);

        let msg = match packed::LightClientMessageReader::from_slice(&data) {
            Ok(msg) => msg.to_enum(),
            _ => {
                warn!(
                    "LightClient.received a malformed message from Peer({})",
                    peer
                );
                nc.ban_peer(
                    peer,
                    BAD_MESSAGE_BAN_TIME,
                    String::from("send us a malformed message"),
                );
                return;
            }
        };

        let item_name = msg.item_name();
        let status = self.try_process(nc.as_ref(), peer, msg.clone());
        if status.is_ok()
            && matches!(
                msg,
                packed::LightClientMessageUnionReader::SendBlockProof(_)
            )
        {
            self.update_best_state();
        }

        if let Some(ban_time) = status.should_ban() {
            error!(
                "process {} from {}, ban {:?} since result is {}",
                item_name, peer, ban_time, status
            );
            nc.ban_peer(peer, ban_time, status.to_string());
        } else if status.should_warn() {
            warn!("process {} from {}, result is {}", item_name, peer, status);
        } else if !status.is_ok() {
            debug!("process {} from {}, result is {}", item_name, peer, status);
        }
    }

    fn notify(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>, token: u64) {
        match token {
            constant::REFRESH_PEERS_TOKEN => {
                self.refresh_all_peers(nc.as_ref());
            }
            _ => unreachable!(),
        }
    }
}

impl LightClientProtocol {
    fn try_process(
        &mut self,
        nc: &dyn CKBProtocolContext,
        peer: PeerIndex,
        message: packed::LightClientMessageUnionReader<'_>,
    ) -> Status {
        match message {
            packed::LightClientMessageUnionReader::SendLastState(reader) => {
                components::SendLastStateProcess::new(reader, self, peer, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendBlockProof(reader) => {
                components::SendBlockProofProcess::new(reader, self, peer, nc).execute()
            }
            _ => StatusCode::UnexpectedProtocolMessage.into(),
        }
    }

    fn get_last_state(&self, nc: &dyn CKBProtocolContext, peer: PeerIndex) {
        let content = packed::GetLastState::new_builder().build();
        let message = packed::LightClientMessage::new_builder()
            .set(content)
            .build();
        nc.reply(peer, &message);
    }
}

impl LightClientProtocol {
    pub(crate) fn new(storage: Storage, peers: Arc<Peers>, pow: Pow) -> Self {
        Self {
            storage,
            peers,
            pow,
            best: None,
        }
    }

    pub(crate) fn peers(&self) -> &Peers {
        &self.peers
    }

    pub(crate) fn pow_engine(&self) -> Arc<dyn PowEngine> {
        self.pow.engine()
    }

    fn refresh_all_peers(&mut self, nc: &dyn CKBProtocolContext) {
        let now = faketime::unix_time_as_millis();
        let before = now - constant::REFRESH_PEERS_INTERVAL.as_millis() as u64;

        for peer in self.peers().get_peers_which_require_updating(before) {
            self.get_last_state(nc, peer);
            self.peers().update_timestamp(peer, now);
        }
        self.update_best_state();
    }

    fn update_best_state(&mut self) {
        let mut best: Option<(PeerIndex, ProveState)> = None;
        for (curr_peer, curr_state) in self.peers().get_peers_which_are_proved() {
            if best.is_none() {
                best = Some((curr_peer, curr_state));
            } else {
                let best_total_difficulty = best
                    .as_ref()
                    .map(|(_, state)| state.get_total_difficulty())
                    .expect("checkd: best is not None");
                let curr_total_difficulty = curr_state.get_total_difficulty();
                if curr_total_difficulty > best_total_difficulty {
                    best = Some((curr_peer, curr_state));
                }
            }
        }
        if let Some((_, prove_state)) = best.as_ref() {
            self.storage
                .update_tip_header(&prove_state.get_last_header().header().data());
        }
        self.best = best;
    }

    fn build_prove_request_content(
        &self,
        peer_state: &PeerState,
        last_header: &VerifiableHeader,
        last_total_difficulty: &U256,
    ) -> packed::GetBlockProof {
        let (start_number, start_total_difficulty) = peer_state
            .get_prove_state()
            .map(|inner| {
                (
                    inner.get_last_header().header().number(),
                    inner.get_total_difficulty().to_owned(),
                )
            })
            .unwrap_or((0, U256::zero()));
        let last_number = last_header.header().number();
        let (last_n_blocks, difficulty_boundary, difficulties) = sampling::sample_blocks(
            start_number,
            &start_total_difficulty,
            last_number,
            last_total_difficulty,
        );
        packed::GetBlockProof::new_builder()
            .last_hash(last_header.header().hash())
            .start_number(start_number.pack())
            .last_n_blocks(last_n_blocks.pack())
            .difficulty_boundary(difficulty_boundary.pack())
            .difficulties(difficulties.into_iter().map(|inner| inner.pack()).pack())
            .build()
    }
}
