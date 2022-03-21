//! Client-side implementation for CKB light client protocol.
//!
//! TODO(light-client) More documentation.

use std::{collections::HashMap, sync::Arc};

use ckb_network::{bytes::Bytes, CKBProtocolContext, CKBProtocolHandler, PeerIndex};
use ckb_types::{
    core::{BlockNumber, HeaderView},
    packed,
    prelude::*,
};
use faketime::unix_time_as_millis;
use log::{debug, error, info, trace, warn};

mod components;
pub mod constant;
mod prelude;
mod status;
pub(crate) mod strategies;

use prelude::*;
pub use status::{Status, StatusCode};
use strategies::BlockSamplingStrategy;

use crate::storage::Storage;

#[derive(Clone)]
pub struct PeerState {
    mmr_activated_number: Option<BlockNumber>,
    last_header: Option<HeaderView>,
    update_timestamp: u64,
}

#[derive(Default, Clone)]
pub struct Peers {
    state: HashMap<PeerIndex, PeerState>,
}

pub struct LightClientProtocol<S: BlockSamplingStrategy> {
    strategy: S,
    storage: Storage,
}

impl PeerState {
    fn new(update_timestamp: u64) -> Self {
        Self {
            mmr_activated_number: None,
            last_header: None,
            update_timestamp,
        }
    }

    fn is_ready(&self) -> bool {
        self.mmr_activated_number.is_some() && self.last_header.is_some()
    }
}

impl Peers {
    fn add_peer(&mut self, index: PeerIndex, update_timestamp: u64) {
        let state = PeerState::new(update_timestamp);
        self.state.insert(index, state);
    }

    fn remove_peer(&mut self, index: PeerIndex) {
        self.state.remove(&index);
    }

    fn is_ready(&self) -> bool {
        self.state.iter().any(|(_, state)| state.is_ready())
    }

    fn update_timestamp(&mut self, index: PeerIndex, timestamp: u64) {
        if let Some(state) = self.state.get_mut(&index) {
            state.update_timestamp = timestamp;
        }
    }

    pub(crate) fn get_mmr_activated_number(&self, index: &PeerIndex) -> Option<BlockNumber> {
        self.state
            .get(&index)
            .and_then(|state| state.mmr_activated_number)
    }

    pub(crate) fn get_last_header(&self, index: &PeerIndex) -> Option<HeaderView> {
        self.state
            .get(&index)
            .and_then(|state| state.last_header.clone())
    }

    pub(crate) fn update_mmr_activated_number(
        &mut self,
        index: PeerIndex,
        mmr_activated_number: BlockNumber,
    ) {
        let now = faketime::unix_time_as_millis();
        if let Some(state) = self.state.get_mut(&index) {
            state.mmr_activated_number = Some(mmr_activated_number);
            state.update_timestamp = now;
        }
    }

    pub(crate) fn update_last_header(&mut self, index: PeerIndex, last_header: HeaderView) {
        let now = faketime::unix_time_as_millis();
        if let Some(state) = self.state.get_mut(&index) {
            state.last_header = Some(last_header);
            state.update_timestamp = now;
        }
    }

    fn get_peers_which_require_chain_info(&self, before_timestamp: u64) -> Vec<PeerIndex> {
        self.state
            .iter()
            .filter_map(|(index, state)| {
                if state.mmr_activated_number.is_none() && state.update_timestamp < before_timestamp
                {
                    Some(*index)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_peers_which_require_last_header(&self, before_timestamp: u64) -> Vec<PeerIndex> {
        self.state
            .iter()
            .filter_map(|(index, state)| {
                if state.mmr_activated_number.is_some()
                    && state.last_header.is_none()
                    && state.update_timestamp < before_timestamp
                {
                    Some(*index)
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_peers_which_are_ready(&self) -> Vec<(PeerIndex, PeerState)> {
        self.state
            .iter()
            .filter_map(|(index, state)| {
                if state.is_ready() {
                    Some((index.to_owned(), state.to_owned()))
                } else {
                    None
                }
            })
            .collect()
    }
}

impl<S: BlockSamplingStrategy> LightClientProtocol<S> {
    pub(crate) fn new(storage: Storage) -> Self {
        Self {
            strategy: S::new(),
            storage,
        }
    }

    pub(crate) fn honest_peer(&self) -> Option<PeerIndex> {
        self.strategy.honest_peer()
    }

    pub(crate) fn peers(&self) -> &Peers {
        self.strategy.peers()
    }

    pub(crate) fn mut_peers(&mut self) -> &mut Peers {
        self.strategy.mut_peers()
    }
}

impl<S: BlockSamplingStrategy> CKBProtocolHandler for LightClientProtocol<S> {
    fn init(&mut self, nc: Arc<dyn CKBProtocolContext + Sync>) {
        nc.set_notify(
            constant::WAIT_FOR_PEERS_DURATION,
            constant::WAIT_FOR_PEERS_TOKEN,
        )
        .expect("set_notify should be ok");
        nc.set_notify(
            constant::GET_CHAIN_INFO_DURATION,
            constant::GET_CHAIN_INFO_TOKEN,
        )
        .expect("set_notify should be ok");
        nc.set_notify(
            constant::GET_LAST_HEADER_DURATION,
            constant::GET_LAST_HEADER_TOKEN,
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
        let now = faketime::unix_time_as_millis();
        self.get_chain_info(nc.as_ref(), peer);
        self.mut_peers().add_peer(peer, now);
    }

    fn disconnected(&mut self, _nc: Arc<dyn CKBProtocolContext + Sync>, peer: PeerIndex) {
        info!("LightClient.disconnected peer={}", peer);
        self.mut_peers().remove_peer(peer);
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
                    constant::BAD_MESSAGE_BAN_TIME,
                    String::from("send us a malformed message"),
                );
                return;
            }
        };

        let item_name = msg.item_name();
        let status = self.try_process(nc.as_ref(), peer, msg);
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
            constant::WAIT_FOR_PEERS_TOKEN => {
                if self.peers().is_ready() {
                    if nc.remove_notify(constant::WAIT_FOR_PEERS_TOKEN).is_err() {
                        trace!("failed to remove notify WAIT_FOR_PEERS_TOKEN")
                    }
                    self.strategy.start(nc.as_ref());
                    if nc
                        .set_notify(
                            constant::FIND_HONEST_PEER_DURATION,
                            constant::FIND_HONEST_PEER_TOKEN,
                        )
                        .is_err()
                    {
                        trace!("failed to set notify FIND_HONEST_PEER_TOKEN")
                    }
                }
            }
            constant::GET_CHAIN_INFO_TOKEN => {
                let now = faketime::unix_time_as_millis();
                let before = now - constant::GET_CHAIN_INFO_DURATION.as_millis() as u64;
                for peer in self.peers().get_peers_which_require_chain_info(before) {
                    self.get_chain_info(nc.as_ref(), peer);
                    self.mut_peers().update_timestamp(peer, now);
                }
            }
            constant::GET_LAST_HEADER_TOKEN => {
                let now = faketime::unix_time_as_millis();
                let before = now - constant::GET_LAST_HEADER_DURATION.as_millis() as u64;
                for peer in self.peers().get_peers_which_require_last_header(before) {
                    self.get_last_header(nc.as_ref(), peer);
                    self.mut_peers().update_timestamp(peer, now);
                }
            }
            constant::FIND_HONEST_PEER_TOKEN => {
                if self.honest_peer().is_some() {
                    if nc.remove_notify(constant::FIND_HONEST_PEER_TOKEN).is_err() {
                        trace!("failed to remove notify FIND_HONEST_PEER_TOKEN")
                    }
                } else {
                    self.strategy.try_find_honest();
                }
            }
            _ => unreachable!(),
        }
    }
}

impl<S: BlockSamplingStrategy> LightClientProtocol<S> {
    fn try_process(
        &mut self,
        nc: &dyn CKBProtocolContext,
        peer: PeerIndex,
        message: packed::LightClientMessageUnionReader<'_>,
    ) -> Status {
        match message {
            packed::LightClientMessageUnionReader::SendChainInfo(reader) => {
                components::SendChainInfoProcess::new(reader, self, peer, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendLastHeader(reader) => {
                components::SendLastHeaderProcess::new(reader, self, peer, nc).execute()
            }
            packed::LightClientMessageUnionReader::SendBlockProof(reader) => {
                components::SendBlockProofProcess::new(reader, self, peer, nc).execute()
            }
            _ => StatusCode::UnexpectedProtocolMessage.into(),
        }
    }

    fn get_chain_info(&self, nc: &dyn CKBProtocolContext, peer: PeerIndex) {
        let content = packed::GetChainInfo::new_builder().build();
        let message = packed::LightClientMessage::new_builder()
            .set(content)
            .build();
        nc.reply(peer, &message);
    }

    fn get_last_header(&self, nc: &dyn CKBProtocolContext, peer: PeerIndex) {
        let content = packed::GetLastHeader::new_builder().build();
        let message = packed::LightClientMessage::new_builder()
            .set(content)
            .build();
        nc.reply(peer, &message);
    }
}
