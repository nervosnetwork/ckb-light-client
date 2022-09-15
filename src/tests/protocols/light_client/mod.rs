use std::sync::Arc;

use ckb_types::{
    core::{BlockNumber, EpochNumberWithFraction, HeaderBuilder},
    prelude::*,
    utilities::merkle_mountain_range::VerifiableHeader,
    U256,
};

use crate::protocols::{LightClientProtocol, PeerState, Peers, LAST_N_BLOCKS};

use super::super::verify::setup;

#[test]
fn build_prove_request_content() {
    let (storage, consensus) = setup("test-light-client");

    let peers = Arc::new(Peers::default());
    let protocol = LightClientProtocol::new(storage.clone(), peers, consensus);

    let peer_state = PeerState::default();
    let last_number = 50;
    let last_total_difficulty = 500u64;
    let epoch_length = LAST_N_BLOCKS + last_number + 100;

    // Setup the storage.
    {
        let epoch = EpochNumberWithFraction::new(0, last_number, epoch_length);
        let header = HeaderBuilder::default()
            .number(last_number.pack())
            .epoch(epoch.pack())
            .build();
        let last_total_difficulty = U256::from(500u64);
        storage.update_last_state(&last_total_difficulty, &header.data());
    }

    // Test different total difficulties.
    {
        let verifiable_header = {
            let new_last_number = last_number + 1;
            let epoch = EpochNumberWithFraction::new(0, new_last_number, epoch_length);
            let header = HeaderBuilder::default()
                .number(new_last_number.pack())
                .epoch(epoch.pack())
                .build();
            VerifiableHeader::new(header, Default::default(), None)
        };

        for diff in 1u64..10 {
            let new_last_total_difficulty = U256::from(last_total_difficulty - diff);
            let prove_request = protocol.build_prove_request_content(
                &peer_state,
                &verifiable_header,
                &new_last_total_difficulty,
            );
            assert!(prove_request.is_none());
        }
        for diff in 0u64..10 {
            let new_last_total_difficulty = U256::from(last_total_difficulty + diff);
            let prove_request = protocol.build_prove_request_content(
                &peer_state,
                &verifiable_header,
                &new_last_total_difficulty,
            );
            assert!(prove_request.is_some());
            let start_number: BlockNumber = prove_request.expect("checked").start_number().unpack();
            assert_eq!(start_number, last_number);
        }
    }

    // Test different block numbers.
    {
        let new_last_total_difficulty = U256::from(last_total_difficulty * 2);

        for new_last_number in 1..=last_number {
            let verifiable_header = {
                let epoch = EpochNumberWithFraction::new(0, new_last_number, epoch_length);
                let header = HeaderBuilder::default()
                    .number(new_last_number.pack())
                    .epoch(epoch.pack())
                    .build();
                VerifiableHeader::new(header, Default::default(), None)
            };
            let prove_request = protocol.build_prove_request_content(
                &peer_state,
                &verifiable_header,
                &new_last_total_difficulty,
            );
            assert!(prove_request.is_none());
        }

        for new_last_number in (last_number + 1)..=(last_number + 10) {
            let verifiable_header = {
                let epoch = EpochNumberWithFraction::new(0, new_last_number, epoch_length);
                let header = HeaderBuilder::default()
                    .number(new_last_number.pack())
                    .epoch(epoch.pack())
                    .build();
                VerifiableHeader::new(header, Default::default(), None)
            };
            let prove_request = protocol.build_prove_request_content(
                &peer_state,
                &verifiable_header,
                &new_last_total_difficulty,
            );
            assert!(prove_request.is_some());
            let start_number: BlockNumber = prove_request.expect("checked").start_number().unpack();
            assert_eq!(start_number, last_number);
        }
    }
}
