use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{core::HeaderView, packed::LightClientMessage, prelude::*};

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
