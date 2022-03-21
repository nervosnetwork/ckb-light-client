use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::packed;

use super::{Peers, Status};

mod binary_search_approach;
mod bounding_the_fork_point;
mod naive_approach;

pub use binary_search_approach::BinarySearchApproach;
pub use bounding_the_fork_point::BoundingTheForkPoint;
pub use naive_approach::NaiveApproach;

pub trait BlockSamplingStrategy: Sync + Send {
    fn new() -> Self;
    fn honest_peer(&self) -> Option<PeerIndex>;
    fn peers(&self) -> &Peers;
    fn mut_peers(&mut self) -> &mut Peers;

    fn start(&mut self, nc: &dyn CKBProtocolContext) {}
    fn handle_block_proof(
        &mut self,
        peer: PeerIndex,
        message: packed::SendBlockProofReader<'_>,
    ) -> Status;
    fn try_find_honest(&mut self) -> Option<PeerIndex>;
}
