use std::cmp::Ordering;

use ckb_constant::consensus::TAU;
use ckb_merkle_mountain_range::leaf_index_to_pos;
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{
    packed,
    prelude::*,
    utilities::{
        compact_to_difficulty,
        merkle_mountain_range::{MMRProof, VerifiableHeader},
    },
    U256,
};
use log::{error, info, trace};

use super::super::{
    peers::ProveRequest, prelude::*, LightClientProtocol, ProveState, Status, StatusCode,
};

pub(crate) struct SendBlockProofProcess<'a> {
    message: packed::SendBlockProofReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a> SendBlockProofProcess<'a> {
    pub(crate) fn new(
        message: packed::SendBlockProofReader<'a>,
        protocol: &'a mut LightClientProtocol,
        peer: PeerIndex,
        nc: &'a dyn CKBProtocolContext,
    ) -> Self {
        Self {
            message,
            protocol,
            peer,
            nc,
        }
    }

    pub(crate) fn execute(self) -> Status {
        let peer_state = self
            .protocol
            .peers()
            .get_state(&self.peer)
            .expect("checked: should have state");

        // TODO(light-client) check if the response is match the request.
        let prove_request = if let Some(prove_request) = peer_state.get_prove_request() {
            prove_request
        } else {
            error!("peer {} isn't waiting for a proof", self.peer);
            return StatusCode::PeerIsNotOnProcess.into();
        };
        let last_header = prove_request.get_last_header();
        let mmr_activated_number = prove_request.get_mmr_activated_number();
        let last_total_difficulty = prove_request.get_total_difficulty();

        let chain_root = self.message.root().to_entity();
        let proof: MMRProof = self.message.proof().unpack();
        let sampled_headers = self
            .message
            .sampled_headers()
            .iter()
            .map(|header| header.to_entity().header().into_view())
            .collect::<Vec<_>>();
        let last_n_headers = self
            .message
            .last_n_headers()
            .iter()
            .map(|header| header.to_entity().header().into_view())
            .collect::<Vec<_>>();

        // Check epoch difficulties.
        let failed_to_verify_tau = if prove_request.if_skip_check_tau() {
            trace!("peer {} skip checking TAU since the flag is set", self.peer);
            false
        } else {
            if !sampled_headers.is_empty() {
                let start_header = sampled_headers
                    .first()
                    .expect("checked: start header should be existed");
                let end_header = last_n_headers
                    .last()
                    .expect("checked: end header should be existed");
                // Check difficulties.
                let start_epoch = start_header.epoch();
                let end_epoch = end_header.epoch();
                let start_compact_target = start_header.compact_target();
                let end_compact_target = end_header.compact_target();
                if start_epoch.number() == end_epoch.number() {
                    if start_compact_target != end_compact_target {
                        error!("failed: different compact targets for a same epoch");
                        return StatusCode::InvalidCompactTarget.into();
                    }
                    trace!(
                        "peer {} skip checking TAU since headers in the same epoch",
                        self.peer
                    );
                    false
                } else {
                    // How many times are epochs switched?
                    let epochs_switch_count = end_epoch.number() - start_epoch.number();

                    let start_block_difficulty = compact_to_difficulty(start_compact_target);
                    let end_block_difficulty = compact_to_difficulty(end_compact_target);
                    let start_epoch_difficulty =
                        start_block_difficulty.clone() * start_epoch.length();
                    let end_epoch_difficulty = end_block_difficulty.clone() * end_epoch.length();

                    let tau = TAU;
                    let tau_u256 = U256::from(TAU);

                    match start_epoch_difficulty.cmp(&end_epoch_difficulty) {
                        Ordering::Equal => {
                            trace!(
                                "peer {}: end epoch difficulty is {} \
                                and it's same as the start epoch",
                                self.peer,
                                end_epoch_difficulty,
                            );
                            false
                        }
                        Ordering::Less => {
                            let mut end_epoch_difficulty_max = start_epoch_difficulty;
                            for _ in 0..epochs_switch_count {
                                end_epoch_difficulty_max =
                                    end_epoch_difficulty_max.saturating_mul(&tau_u256);
                            }
                            trace!(
                                "peer {}: end epoch difficulty is {} and upper limit is {}",
                                self.peer,
                                end_epoch_difficulty,
                                end_epoch_difficulty_max
                            );
                            end_epoch_difficulty > end_epoch_difficulty_max
                        }
                        Ordering::Greater => {
                            let mut end_epoch_difficulty_min = start_epoch_difficulty;
                            for _ in 0..epochs_switch_count {
                                end_epoch_difficulty_min = end_epoch_difficulty_min / tau;
                            }
                            trace!(
                                "peer {}: end epoch difficulty is {} and lower limit is {}",
                                self.peer,
                                end_epoch_difficulty,
                                end_epoch_difficulty_min
                            );
                            end_epoch_difficulty < end_epoch_difficulty_min
                        }
                    }
                }
            } else {
                trace!(
                    "peer {} skip checking TAU since no sampled headers",
                    self.peer
                );
                false
            }
        };

        // Check POW.
        let pow_engine = self.protocol.pow_engine();
        for header in sampled_headers.iter().chain(last_n_headers.iter()) {
            if !pow_engine.verify(&header.data()) {
                let errmsg = format!(
                    "failed to verify nonce for block#{}, hash: {:#x}",
                    header.number(),
                    header.hash()
                );
                return StatusCode::InvalidNonce.with_context(errmsg);
            }
        }

        // Check parent hashes for the continuous headers.
        for headers in last_n_headers.windows(2) {
            if headers[0].hash() != headers[1].parent_hash() {
                let errmsg = format!(
                    "failed to verify parent hash for block#{}, hash: {:#x}",
                    headers[1].number(),
                    headers[1].hash()
                );
                return StatusCode::InvalidParentHash.with_context(errmsg);
            }
        }

        // If no sampled headers, we can skip the check for the MMR proof.
        if !sampled_headers.is_empty() {
            // Check total difficulty.
            if let Some(prove_state) = peer_state.get_prove_state() {
                let prev_last_header = prove_state.get_last_header();
                let prev_total_difficulty = prove_state.get_total_difficulty();
                if let Err(msg) = verify_total_difficuly(
                    prev_last_header,
                    prev_total_difficulty,
                    last_header,
                    last_total_difficulty,
                ) {
                    return StatusCode::InvalidTotalDifficulty.with_context(msg);
                }
            }

            let digests_with_positions = {
                let res = sampled_headers
                    .iter()
                    .chain(last_n_headers.iter())
                    .map(|header| {
                        let index = header.number();
                        let position = leaf_index_to_pos(index);
                        let digest = header.digest();
                        digest.verify()?;
                        Ok((position, digest))
                    })
                    .collect::<Result<Vec<_>, String>>();
                match res {
                    Ok(tmp) => tmp,
                    Err(err) => {
                        let errmsg = format!("failed to verify all digest since {}", err);
                        return StatusCode::FailedToVerifyTheProof.with_context(errmsg);
                    }
                }
            };

            let verify_result = match proof.verify(chain_root.clone(), digests_with_positions) {
                Ok(verify_result) => verify_result,
                Err(err) => {
                    let errmsg = format!("failed to do verify the proof since {}", err);
                    return StatusCode::FailedToVerifyTheProof.with_context(errmsg);
                }
            };

            if verify_result {
                info!("passed: verify mmr proof");
            } else {
                error!("failed: verify mmr proof");
                return StatusCode::FailedToVerifyTheProof.into();
            }

            let expected_root_hash = chain_root.calc_mmr_hash();
            let check_extra_hash_result =
                last_header.is_valid(mmr_activated_number, Some(&expected_root_hash));
            if check_extra_hash_result {
                info!(
                    "passed: verify extra hash for block-{} ({:#x})",
                    last_header.header().number(),
                    last_header.header().hash(),
                );
            } else {
                error!(
                    "failed: verify extra hash for block-{} ({:#x})",
                    last_header.header().number(),
                    last_header.header().hash(),
                );
                let errmsg = "failed to do verify the extra hash";
                return StatusCode::FailedToVerifyTheProof.with_context(errmsg);
            };
        }

        // Failed to verify TAU, ask for new sampled headers.
        if failed_to_verify_tau {
            let content = self.protocol.build_prove_request_content(
                &peer_state,
                &last_header,
                &last_total_difficulty,
            );
            let mut prove_request = ProveRequest::new(
                mmr_activated_number,
                last_header.clone(),
                last_total_difficulty.clone(),
                content.clone(),
            );
            prove_request.skip_check_tau();
            self.protocol
                .mut_peers()
                .submit_prove_request(self.peer, prove_request);

            let message = packed::LightClientMessage::new_builder()
                .set(content)
                .build();
            self.nc.reply(self.peer, &message);
        } else {
            let prove_state =
                ProveState::new_from_request(prove_request.to_owned(), last_n_headers);
            self.protocol
                .mut_peers()
                .commit_prove_state(self.peer, prove_state);
        }

        Status::ok()
    }
}

pub fn verify_total_difficuly(
    start_verifiable_header: &VerifiableHeader,
    start_total_difficulty: &U256,
    end_verifiable_header: &VerifiableHeader,
    end_total_difficulty: &U256,
) -> Result<(), String> {
    let start_header = start_verifiable_header.header();
    let end_header = end_verifiable_header.header();
    let start_epoch = start_header.epoch();
    let end_epoch = end_header.epoch();
    let start_compact_target = start_header.compact_target();
    let end_compact_target = end_header.compact_target();
    let total_difficulty = end_total_difficulty - start_total_difficulty;
    if start_epoch.number() != end_epoch.number() {
        let start_block_difficulty = compact_to_difficulty(start_compact_target);
        let end_block_difficulty = compact_to_difficulty(end_compact_target);
        let start_epoch_difficulty = start_block_difficulty.clone() * start_epoch.length();
        let end_epoch_difficulty = end_block_difficulty.clone() * end_epoch.length();
        // How many times are epochs switched?
        let epochs_switch_count = end_epoch.number() - start_epoch.number();
        let difficulty_changes_state = start_epoch_difficulty.cmp(&end_epoch_difficulty);

        let tau = TAU;

        // Step-1 Check the magnitude of the difficulty changes.
        let k = match difficulty_changes_state {
            Ordering::Equal => 0,
            Ordering::Less => calculate_tau_exponent_when_increased(
                tau,
                &start_epoch_difficulty,
                &end_epoch_difficulty,
                epochs_switch_count,
            )
            .ok_or_else(|| {
                format!(
                    "failed since the epoch difficulty increased \
                                    too fast ({}->{}) during epochs ([{},{}])",
                    start_epoch_difficulty, end_epoch_difficulty, start_epoch, end_epoch
                )
            })?,
            Ordering::Greater => calculate_tau_exponent_when_decreased(
                tau,
                &start_epoch_difficulty,
                &end_epoch_difficulty,
                epochs_switch_count,
            )
            .ok_or_else(|| {
                format!(
                    "failed since the epoch difficulty decreased \
                                    too fast ({}->{}) during epochs ([{},{}])",
                    start_epoch_difficulty, end_epoch_difficulty, start_epoch, end_epoch
                )
            })?,
        };

        // Step-2 Check the range of total difficulty.
        let start_epoch_blocks_count = start_epoch.length() - start_epoch.index();
        let end_epoch_blocks_count = end_epoch.length() - end_epoch.index();
        let unaligned_difficulty_calculated = start_block_difficulty * start_epoch_blocks_count
            + end_block_difficulty * end_epoch_blocks_count;
        if epochs_switch_count == 1 {
            if total_difficulty != unaligned_difficulty_calculated {
                let errmsg = format!(
                    "failed since total difficulty is {} but the calculated is {} \
                                during epochs ([{:#},{:#}])",
                    total_difficulty, unaligned_difficulty_calculated, start_epoch, end_epoch
                );
                return Err(errmsg);
            }
        } else {
            // `k <= n` was checked in Step-1.
            // `n / 2 >= 1` was checked since the above branch.
            let n = epochs_switch_count;
            let diff = &start_epoch_difficulty;
            let (aligned_difficulty_min, aligned_difficulty_max) = match difficulty_changes_state {
                Ordering::Equal => {
                    let min = {
                        let n_decreased = (n + 1) / 2;
                        let n_increased = n - n_decreased - 1;
                        calculate_min_total_difficulty(diff, tau, n_decreased, n_increased)
                    };
                    let max = {
                        let n_increased = (n + 1) / 2;
                        let n_decreased = n - n_increased - 1;
                        calculate_max_total_difficulty(diff, tau, n_increased, n_decreased)
                    };
                    (min, max)
                }
                Ordering::Less => {
                    let min = {
                        let n_decreased = (n - k + 1) / 2;
                        let n_increased = n - n_decreased - 1;
                        calculate_min_total_difficulty(diff, tau, n_decreased, n_increased)
                    };
                    let max = {
                        let n_increased = (n - (k + 1) + 1) / 2 + (k + 1);
                        let n_decreased = n - n_increased - 1;
                        calculate_max_total_difficulty(diff, tau, n_increased, n_decreased)
                    };
                    (min, max)
                }
                Ordering::Greater => {
                    let min = {
                        let n_decreased = (n - (k + 1) + 1) / 2 + (k + 1);
                        let n_increased = n - n_decreased - 1;
                        calculate_min_total_difficulty(diff, tau, n_decreased, n_increased)
                    };
                    let max = {
                        let n_increased = (n - k + 1) / 2;
                        let n_decreased = n - n_increased - 1;
                        calculate_max_total_difficulty(diff, tau, n_increased, n_decreased)
                    };
                    (min, max)
                }
            };
            let total_difficulity_min = &unaligned_difficulty_calculated + &aligned_difficulty_min;
            let total_difficulity_max = &unaligned_difficulty_calculated + &aligned_difficulty_max;
            if total_difficulty < total_difficulity_min || total_difficulty > total_difficulity_max
            {
                let errmsg = format!(
                    "failed since total difficulty ({}) isn't in the range ({}+[{},{}]) \
                                during epochs ([{:#},{:#}])",
                    total_difficulty,
                    unaligned_difficulty_calculated,
                    aligned_difficulty_min,
                    aligned_difficulty_max,
                    start_epoch,
                    end_epoch
                );
                return Err(errmsg);
            }
        }
    }

    Ok(())
}

// Calculate the `k` which satisfied that `lhs * (tau ^ k) <= rhs <= lhs * (tau ^ (k+1))` and ` 0 <= k <= limit`.
//
// Ref: Page 18, 6.1 Variable Difficulty MMR in [FlyClient: Super-Light Clients for Cryptocurrencies].
//
// [FlyClient: Super-Light Clients for Cryptocurrencies]: https://eprint.iacr.org/2019/226.pdf
fn calculate_tau_exponent_when_increased(
    tau: u64,
    lhs: &U256,
    rhs: &U256,
    limit: u64,
) -> Option<u64> {
    let mut k = 0;
    let mut tmp = lhs.clone();
    let tau_u256 = U256::from(tau);
    for _ in 0..limit {
        tmp = tmp.saturating_mul(&tau_u256);
        if tmp >= *rhs {
            return Some(k);
        }
        k += 1;
    }
    None
}

// Calculate the `k` which satisfied that `lhs * (tau ^ (-k)) >= rhs >= lhs * (tau ^ (-k-1))` and ` 0 <= k <= limit`.
//
// Ref: Page 18, 6.1 Variable Difficulty MMR in [FlyClient: Super-Light Clients for Cryptocurrencies].
//
// [FlyClient: Super-Light Clients for Cryptocurrencies]: https://eprint.iacr.org/2019/226.pdf
fn calculate_tau_exponent_when_decreased(
    tau: u64,
    lhs: &U256,
    rhs: &U256,
    limit: u64,
) -> Option<u64> {
    let mut k = 0;
    let mut tmp = lhs.clone();
    for _ in 0..limit {
        tmp /= tau;
        if tmp <= *rhs {
            return Some(k);
        }
        k += 1;
    }
    None
}

// Calculate min total difficulty.
// - For the first part of the epochs, the epoch difficulty should be decreased.
// - For the last part of the epochs, the epoch difficulty should be increased.
fn calculate_min_total_difficulty(
    start_epoch_difficulty: &U256,
    tau: u64,
    epochs_count_decreased: u64,
    epochs_count_increased: u64,
) -> U256 {
    let mut curr = start_epoch_difficulty / tau;
    let mut total = U256::zero();
    let tau_u256 = U256::from(tau);
    for _ in 0..epochs_count_decreased {
        total += &curr;
        curr /= tau;
    }
    for _ in 0..epochs_count_increased {
        total += &curr;
        curr = curr.saturating_mul(&tau_u256);
    }
    total
}

// Calculate max total difficulty.
// - For the first part of the epochs, the epoch difficulty should be increased.
// - For the last part of the epochs, the epoch difficulty should be decreased.
fn calculate_max_total_difficulty(
    start_epoch_difficulty: &U256,
    tau: u64,
    epochs_count_increased: u64,
    epochs_count_decreased: u64,
) -> U256 {
    let mut curr = start_epoch_difficulty / tau;
    if curr == U256::zero() {
        curr = U256::one();
    }
    let mut total = U256::zero();
    let tau_u256 = U256::from(tau);
    for _ in 0..epochs_count_increased {
        total += &curr;
        curr = curr.saturating_mul(&tau_u256);
    }
    for _ in 0..epochs_count_decreased {
        total += &curr;
        curr /= tau;
    }
    total
}
