use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{
    core::{EpochNumber, EpochNumberWithFraction, ExtraHashView, HeaderView},
    packed::LightClientMessage,
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
};

use super::{Status, StatusCode};

pub(crate) trait LightClientProtocolReply<'a> {
    fn reply(&'a self, peer_index: PeerIndex, message: &LightClientMessage) -> Status;
}

impl<'a> LightClientProtocolReply<'a> for &(dyn CKBProtocolContext + 'a) {
    fn reply(&'a self, peer_index: PeerIndex, message: &LightClientMessage) -> Status {
        let enum_message = message.to_enum();
        let item_name = enum_message.item_name();
        let protocol_id = self.protocol_id();
        if let Err(err) = self.send_message(protocol_id, peer_index, message.as_bytes()) {
            let error_message = format!("nc.send_message {} failed since {:?}", item_name, err);
            StatusCode::Network.with_context(error_message)
        } else {
            Status::ok()
        }
    }
}

// TODO Since these methods are so useful, we could move then into `ckb-types`.
// And also, we should add the `header.epoch().is_well_formed()` check into `header.is_valid()`.
pub(crate) trait HeaderUtils {
    fn is_parent_of(&self, child: &Self) -> bool;

    fn is_child_of(&self, parent: &Self) -> bool {
        parent.is_parent_of(self)
    }
}

impl HeaderUtils for HeaderView {
    fn is_parent_of(&self, child: &Self) -> bool {
        self.number() + 1 == child.number()
            && (self.is_genesis() || child.epoch().is_successor_of(self.epoch()))
            && self.hash() == child.parent_hash()
    }
}

// TODO Remove patch after the upstream fixed.
//
// Ref: https://github.com/nervosnetwork/ckb/blob/v0.112.1/util/types/src/utilities/merkle_mountain_range.rs#L212-L241
pub(crate) trait VerifiableHeaderPatch {
    fn patched_is_valid(&self, mmr_activated_epoch_number: EpochNumber) -> bool;
}

impl VerifiableHeaderPatch for VerifiableHeader {
    fn patched_is_valid(&self, mmr_activated_epoch_number: EpochNumber) -> bool {
        let mmr_activated_epoch = EpochNumberWithFraction::new(mmr_activated_epoch_number, 0, 1);
        let has_chain_root = self.header().epoch() > mmr_activated_epoch;
        if has_chain_root {
            if self.header().is_genesis() {
                if !self.parent_chain_root().is_default() {
                    return false;
                }
            } else {
                let is_extension_beginning_with_chain_root_hash = self
                    .extension()
                    .map(|extension| {
                        let actual_extension_data = extension.raw_data();
                        let parent_chain_root_hash = self.parent_chain_root().calc_mmr_hash();
                        actual_extension_data.starts_with(parent_chain_root_hash.as_slice())
                    })
                    .unwrap_or(false);
                if !is_extension_beginning_with_chain_root_hash {
                    return false;
                }
            }
        }

        let expected_extension_hash = self
            .extension()
            .map(|extension| extension.calc_raw_data_hash());
        let extra_hash_view = ExtraHashView::new(self.uncles_hash(), expected_extension_hash);
        let expected_extra_hash = extra_hash_view.extra_hash();
        let actual_extra_hash = self.header().extra_hash();
        expected_extra_hash == actual_extra_hash
    }
}
