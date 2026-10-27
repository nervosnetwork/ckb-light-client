//! Shared trusted-anchor fixture for proof lifecycle tests.
use crate::{
    protocols::{LastState, LightClientProtocol, Peers, ProveRequest, ProveState},
    service::{FetchStatus, LightClientChainService},
    storage::{LightClientStorage, Storage, StorageWithChainData},
};
use ckb_chain_spec::consensus::ConsensusBuilder;
use ckb_merkle_mountain_range::{leaf_index_to_pos, util::MemMMR};
use ckb_network::{CKBProtocolHandler, PeerIndex, SupportProtocols};
use ckb_types::{
    core, packed,
    prelude::*,
    utilities::merkle_mountain_range::{MergeHeaderDigest, VerifiableHeader},
    U256,
};
use std::sync::Arc;

use super::MockNetworkContext;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Kind {
    Header,
    Transaction,
}
pub(crate) const KINDS: [Kind; 2] = [Kind::Header, Kind::Transaction];

pub(crate) struct Fixture {
    pub(crate) _directory: tempfile::TempDir,
    pub(crate) storage: Storage,
    pub(crate) peers: Arc<Peers>,
    pub(crate) service: LightClientChainService,
    pub(crate) protocol: LightClientProtocol,
    pub(crate) context: MockNetworkContext,
    pub(crate) peer: PeerIndex,
    pub(crate) block: core::BlockView,
    pub(crate) wire: packed::VerifiableHeader,
    pub(crate) proof: packed::HeaderDigestVec,
}
impl Fixture {
    pub(crate) fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let storage = Storage::new(directory.path());
        let consensus = ConsensusBuilder::default().build();
        storage.init_genesis_block(consensus.genesis_block().data());
        let genesis = consensus.genesis_block().header();
        let tx = core::TransactionBuilder::default()
            .output(packed::CellOutput::new_builder().capacity(100u64).build())
            .output_data(packed::Bytes::default())
            .build();
        let block = core::BlockBuilder::default()
            .number(1u64)
            .parent_hash(genesis.hash())
            .compact_target(genesis.compact_target())
            .epoch(core::EpochNumberWithFraction::new(0, 1, 100))
            .transaction(tx)
            .build();
        let mut mmr = MemMMR::<packed::HeaderDigest, MergeHeaderDigest>::default();
        mmr.push(genesis.digest()).unwrap();
        mmr.push(block.header().digest()).unwrap();
        let root = mmr.get_root().unwrap();
        let extension: packed::Bytes = root.calc_mmr_hash().as_slice().pack();
        let extra =
            core::ExtraHashView::new(packed::Byte32::zero(), Some(extension.calc_raw_data_hash()));
        let anchor = core::HeaderBuilder::default()
            .number(2u64)
            .parent_hash(block.hash())
            .compact_target(genesis.compact_target())
            .epoch(core::EpochNumberWithFraction::new(0, 2, 100))
            .extra_hash(extra.extra_hash())
            .build();
        let wire = packed::VerifiableHeader::new_builder()
            .header(anchor.data())
            .uncles_hash(packed::Byte32::zero())
            .extension(packed::BytesOpt::new_builder().set(Some(extension)).build())
            .parent_chain_root(root)
            .build();
        let proof = mmr
            .gen_proof(vec![leaf_index_to_pos(1)])
            .unwrap()
            .proof_items()
            .to_vec()
            .pack();
        storage.update_last_state(&U256::from(3u64), &anchor.data(), &[]);
        let peers = Arc::new(Peers::new(2, 2000, storage.get_last_check_point(), 10));
        let peer = PeerIndex::new(1);
        peers.add_peer(peer);
        let state = LastState::new(VerifiableHeader::from(wire.clone()));
        let request = ProveRequest::new(state.clone(), Default::default());
        peers.request_last_state(peer).unwrap();
        peers.update_last_state(peer, state).unwrap();
        peers.update_prove_request(peer, request.clone()).unwrap();
        peers
            .update_prove_state(peer, ProveState::new_from_request(request, vec![], vec![]))
            .unwrap();
        let service = LightClientChainService::new(
            StorageWithChainData::new(storage.clone(), peers.clone(), Default::default()),
            Arc::new(consensus.clone()),
        );
        let protocol = LightClientProtocol::new(storage.clone(), peers.clone(), consensus);
        Self {
            _directory: directory,
            storage,
            peers,
            service,
            protocol,
            context: MockNetworkContext::new(SupportProtocols::LightClient),
            peer,
            block,
            wire,
            proof,
        }
    }
    pub(crate) fn hash(&self, kind: Kind) -> packed::Byte32 {
        match kind {
            Kind::Header => self.block.hash(),
            Kind::Transaction => self.block.transactions()[0].hash(),
        }
    }
    pub(crate) fn fetch(&self, kind: Kind, hash: &packed::Byte32) -> &'static str {
        fn state<T>(value: FetchStatus<T>) -> &'static str {
            match value {
                FetchStatus::Added { .. } => "added",
                FetchStatus::NotFound => "missing",
                _ => "other",
            }
        }
        match kind {
            Kind::Header => state(self.service.fetch_header(&hash.unpack())),
            Kind::Transaction => state(self.service.fetch_transaction(&hash.unpack())),
        }
    }
    pub(crate) async fn tick(&mut self) {
        self.protocol.notify(self.context.context(), 1).await;
    }
    pub(crate) async fn arm(&mut self, kind: Kind, hash: &packed::Byte32) {
        assert_eq!(self.fetch(kind, hash), "added");
        assert!(match kind {
            Kind::Header => self.peers.fetching_headers().contains_key(hash),
            Kind::Transaction => self.peers.fetching_txs().contains_key(hash),
        });
        self.tick().await;
        assert!(!self.context.sent_messages().borrow().is_empty());
        self.context.sent_messages().borrow_mut().clear();
    }
    pub(crate) fn present(&self, kind: Kind) -> bool {
        match kind {
            Kind::Header => self.storage.get_header(&self.hash(kind)).is_some(),
            Kind::Transaction => self.storage.get_transaction(&self.hash(kind)).is_some(),
        }
    }
    pub(crate) fn positive(
        &self,
        kind: Kind,
        wire: packed::VerifiableHeader,
        invalid: bool,
    ) -> packed::LightClientMessage {
        let proof = if invalid {
            self.proof
                .clone()
                .as_builder()
                .set(vec![self
                    .proof
                    .get(0)
                    .unwrap()
                    .as_builder()
                    .children_hash(packed::Byte32::new([17; 32]))
                    .build()])
                .build()
        } else {
            self.proof.clone()
        };
        match kind {
            Kind::Header => packed::LightClientMessage::new_builder()
                .set(
                    packed::SendBlocksProofV1::new_builder()
                        .last_header(wire)
                        .proof(proof)
                        .headers(vec![self.block.header().data()].pack())
                        .blocks_uncles_hash(vec![self.block.calc_uncles_hash()].pack())
                        .blocks_extension(vec![packed::BytesOpt::default()])
                        .build(),
                )
                .build(),
            Kind::Transaction => {
                let tx = self.block.transactions()[0].data();
                let filtered = packed::FilteredBlock::new_builder()
                    .header(self.block.header().data())
                    .witnesses_root(self.block.calc_witnesses_root())
                    .transactions(vec![tx].pack())
                    .proof(
                        packed::MerkleProof::new_builder()
                            .indices([0u32].pack())
                            .build(),
                    )
                    .build();
                packed::LightClientMessage::new_builder()
                    .set(
                        packed::SendTransactionsProofV1::new_builder()
                            .last_header(wire)
                            .proof(proof)
                            .filtered_blocks(vec![filtered])
                            .blocks_uncles_hash(vec![self.block.calc_uncles_hash()].pack())
                            .blocks_extension(vec![packed::BytesOpt::default()])
                            .build(),
                    )
                    .build()
            }
        }
    }
    pub(crate) fn negative(
        &self,
        kind: Kind,
        wire: packed::VerifiableHeader,
        hashes: Vec<packed::Byte32>,
    ) -> packed::LightClientMessage {
        match kind {
            Kind::Header => packed::LightClientMessage::new_builder()
                .set(
                    packed::SendBlocksProofV1::new_builder()
                        .last_header(wire)
                        .missing_block_hashes(hashes.pack())
                        .build(),
                )
                .build(),
            Kind::Transaction => packed::LightClientMessage::new_builder()
                .set(
                    packed::SendTransactionsProofV1::new_builder()
                        .last_header(wire)
                        .missing_tx_hashes(hashes.pack())
                        .build(),
                )
                .build(),
        }
    }
    pub(crate) async fn receive(&mut self, message: packed::LightClientMessage) {
        self.protocol
            .received(self.context.context(), self.peer, message.as_bytes())
            .await;
    }
}
