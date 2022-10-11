use std::sync::Arc;

use ckb_chain::chain::ChainController;
use ckb_chain_spec::consensus::Consensus;
use ckb_merkle_mountain_range::leaf_index_to_pos;
use ckb_shared::{Shared, Snapshot};
use ckb_store::ChainStore;
use ckb_tx_pool::TxPoolController;
use ckb_types::{
    core::{BlockExt, BlockNumber, BlockView, HeaderView},
    packed,
    prelude::*,
    utilities::{compact_to_difficulty, merkle_mountain_range::VerifiableHeader},
    U256,
};

use crate::{
    protocols::{
        FilterProtocol, LastState, LightClientProtocol, Peers, ProveRequest, SyncProtocol,
    },
    storage::Storage,
    tests::ALWAYS_SUCCESS_BIN,
};

macro_rules! epoch {
    ($number:expr, $index:expr, $length:expr) => {
        ckb_types::core::EpochNumberWithFraction::new($number, $index, $length)
    };
    ($tuple:ident) => {{
        let (number, index, length) = $tuple;
        ckb_types::core::EpochNumberWithFraction::new(number, index, length)
    }};
}

pub(crate) trait SnapshotExt {
    fn get_header_by_number(&self, num: BlockNumber) -> Option<HeaderView>;

    fn get_block_by_number(&self, num: BlockNumber) -> Option<BlockView>;

    fn get_block_ext_by_number(&self, num: BlockNumber) -> Option<BlockExt>;

    fn get_verifiable_header_by_number(&self, num: BlockNumber)
        -> Option<packed::VerifiableHeader>;

    fn get_block_difficulty_by_number(&self, num: BlockNumber) -> Option<U256> {
        self.get_header_by_number(num)
            .map(|header| compact_to_difficulty(header.compact_target()))
    }

    fn get_total_difficulty_by_number(&self, num: BlockNumber) -> Option<U256> {
        self.get_block_ext_by_number(num)
            .map(|block_ext| block_ext.total_difficulty)
    }

    fn build_last_state_by_number(&self, num: BlockNumber) -> Option<packed::LightClientMessage> {
        self.get_verifiable_header_by_number(num).map(|header| {
            let content = packed::SendLastState::new_builder()
                .last_header(header)
                .build();
            packed::LightClientMessage::new_builder()
                .set(content)
                .build()
        })
    }
}

pub(crate) trait ChainExt {
    fn client_storage(&self) -> &Storage;

    fn consensus(&self) -> &Consensus;

    fn create_light_client_protocol(&self, peers: Arc<Peers>) -> LightClientProtocol {
        let storage = self.client_storage().to_owned();
        let consensus = self.consensus().to_owned();
        LightClientProtocol::new(storage, peers, consensus)
    }

    fn create_filter_protocol(&self, peers: Arc<Peers>) -> FilterProtocol {
        let storage = self.client_storage().to_owned();
        FilterProtocol::new(storage, peers)
    }

    fn create_sync_protocol(&self, peers: Arc<Peers>) -> SyncProtocol {
        let storage = self.client_storage().to_owned();
        SyncProtocol::new(storage, peers)
    }
}

pub(crate) trait RunningChainExt: ChainExt {
    fn controller(&self) -> &ChainController;

    fn shared(&self) -> &Shared;

    fn tx_pool(&self) -> &TxPoolController {
        &self.shared().tx_pool_controller()
    }

    fn always_success_cell_dep(&self) -> packed::CellDep {
        self.shared()
            .snapshot()
            .get_block_by_number(0)
            .unwrap()
            .transactions()
            .into_iter()
            .filter_map(|tx| {
                tx.outputs_data()
                    .into_iter()
                    .enumerate()
                    .find(|(_, data)| data.raw_data().as_ref() == ALWAYS_SUCCESS_BIN)
                    .map(|(idx, _)| {
                        let out_point = packed::OutPoint::new_builder()
                            .tx_hash(tx.hash())
                            .index((idx as u32).pack())
                            .build();
                        packed::CellDep::new_builder().out_point(out_point).build()
                    })
            })
            .next()
            .unwrap()
    }

    fn mine_to(&self, block_number: BlockNumber) {
        let chain_tip_number = self.shared().snapshot().tip_number();
        if chain_tip_number < block_number {
            self.mine_blocks((block_number - chain_tip_number) as usize);
        }
    }

    fn mine_block<F: FnMut(packed::Block) -> BlockView>(&self, mut builder: F) -> BlockNumber {
        let block_template = self
            .shared()
            .get_block_template(None, None, None)
            .unwrap()
            .unwrap();
        let block: packed::Block = block_template.into();
        let block = builder(block);
        let block_number = block.number();
        let is_ok = self
            .controller()
            .process_block(Arc::new(block))
            .expect("process block");
        assert!(is_ok, "failed to process block {}", block_number);
        while self
            .tx_pool()
            .get_tx_pool_info()
            .expect("get tx pool info")
            .tip_number
            != block_number
        {}
        block_number
    }

    fn mine_blocks(&self, blocks_count: usize) {
        for _ in 0..blocks_count {
            let _ = self.mine_block(|block| block.as_advanced_builder().build());
        }
    }

    fn build_prove_request(
        &self,
        start_num: BlockNumber,
        last_num: BlockNumber,
        sampled_nums: &[BlockNumber],
        boundary_num: BlockNumber,
        last_n_blocks: BlockNumber,
    ) -> ProveRequest {
        let snapshot = self.shared().snapshot();
        let last_header: VerifiableHeader = snapshot
            .get_verifiable_header_by_number(last_num)
            .expect("block stored")
            .into();
        let content = {
            let start_header = snapshot
                .get_header_by_number(start_num)
                .expect("block stored");
            let difficulties = {
                let u256_one = &U256::from(1u64);
                let total_diffs = (0..last_num)
                    .into_iter()
                    .map(|num| snapshot.get_total_difficulty_by_number(num).unwrap())
                    .collect::<Vec<_>>();
                let mut difficulties = Vec::new();
                for n in sampled_nums {
                    let n = *n as usize;
                    difficulties.push(&total_diffs[n - 1] + u256_one);
                    difficulties.push(&total_diffs[n] - u256_one);
                    difficulties.push(total_diffs[n].to_owned());
                }
                difficulties.sort();
                difficulties.dedup();
                difficulties.into_iter().map(|diff| diff.pack())
            };
            let difficulty_boundary = snapshot
                .get_total_difficulty_by_number(boundary_num)
                .unwrap();
            packed::GetLastStateProof::new_builder()
                .last_hash(last_header.header().hash())
                .start_hash(start_header.hash())
                .start_number(start_header.number().pack())
                .last_n_blocks(last_n_blocks.pack())
                .difficulty_boundary(difficulty_boundary.pack())
                .difficulties(difficulties.pack())
                .build()
        };
        let last_state = LastState::new(last_header);
        ProveRequest::new(last_state, content)
    }

    fn build_blocks_proof_content(
        &self,
        last_num: BlockNumber,
        block_nums: &[BlockNumber],
        missing_block_hashes: &[packed::Byte32],
    ) -> packed::GetBlocksProof {
        let snapshot = self.shared().snapshot();
        let last_header = snapshot
            .get_header_by_number(last_num)
            .expect("block stored");
        let block_hashes = block_nums
            .iter()
            .map(|n| {
                snapshot
                    .get_header_by_number(*n)
                    .expect("block stored")
                    .hash()
            })
            .chain(missing_block_hashes.iter().map(ToOwned::to_owned))
            .collect::<Vec<_>>();
        packed::GetBlocksProof::new_builder()
            .last_hash(last_header.hash())
            .block_hashes(block_hashes.pack())
            .build()
    }

    fn build_proof_by_numbers(
        &self,
        last_num: BlockNumber,
        block_nums: &[BlockNumber],
    ) -> packed::HeaderDigestVec {
        let positions = block_nums
            .iter()
            .map(|num| leaf_index_to_pos(*num))
            .collect::<Vec<_>>();
        if positions.is_empty() {
            Default::default()
        } else {
            self.shared()
                .snapshot()
                .chain_root_mmr(last_num - 1)
                .gen_proof(positions)
                .expect("generate proof")
                .proof_items()
                .to_owned()
                .pack()
        }
    }
}

impl SnapshotExt for Snapshot {
    fn get_header_by_number(&self, num: BlockNumber) -> Option<HeaderView> {
        self.get_block_hash(num)
            .and_then(|hash| self.get_block_header(&hash))
    }

    fn get_block_by_number(&self, num: BlockNumber) -> Option<BlockView> {
        self.get_block_hash(num)
            .and_then(|hash| self.get_block(&hash))
    }

    fn get_block_ext_by_number(&self, num: BlockNumber) -> Option<BlockExt> {
        self.get_block_hash(num)
            .and_then(|hash| self.get_block_ext(&hash))
    }

    fn get_verifiable_header_by_number(
        &self,
        num: BlockNumber,
    ) -> Option<packed::VerifiableHeader> {
        self.get_block_by_number(num).map(|block| {
            let mmr = self.chain_root_mmr(num - 1);
            let parent_chain_root = mmr.get_root().expect("has chain root");
            packed::VerifiableHeader::new_builder()
                .header(block.data().header())
                .uncles_hash(block.calc_uncles_hash())
                .extension(Pack::pack(&block.extension()))
                .parent_chain_root(parent_chain_root)
                .build()
        })
    }
}
