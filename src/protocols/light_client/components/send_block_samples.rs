use std::cmp::Ordering;

use ckb_constant::consensus::TAU;
use ckb_merkle_mountain_range::leaf_index_to_pos;
use ckb_network::{CKBProtocolContext, PeerIndex};
use ckb_types::{
    core::BlockNumber,
    packed,
    prelude::*,
    utilities::{
        compact_to_difficulty,
        merkle_mountain_range::{MMRProof, VerifiableHeader},
    },
    U256,
};
use log::{error, trace};

use super::super::{
    peers::ProveRequest, prelude::*, LastState, LightClientProtocol, ProveState, Status, StatusCode,
};
use crate::protocols::LAST_N_BLOCKS;

pub(crate) struct SendBlockSamplesProcess<'a> {
    message: packed::SendBlockSamplesReader<'a>,
    protocol: &'a mut LightClientProtocol,
    peer: PeerIndex,
    nc: &'a dyn CKBProtocolContext,
}

impl<'a> SendBlockSamplesProcess<'a> {
    pub(crate) fn new(
        message: packed::SendBlockSamplesReader<'a>,
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
        let last_total_difficulty = prove_request.get_total_difficulty();

        let chain_root = self.message.root().to_entity();
        let proof: MMRProof = self.message.proof().unpack();

        let mmr_activated_epoch = self.protocol.mmr_activated_epoch();
        // Check if the response is match the request.
        {
            let prev_request = prove_request.get_request();
            let difficulty_boundary: U256 = prev_request.difficulty_boundary().unpack();
            let mut difficulties: Vec<U256> = prev_request
                .difficulties()
                .into_iter()
                .map(|item| item.unpack())
                .collect();

            {
                // Check the first block in last-N blocks.
                let first_last_n_header = self
                    .message
                    .last_n_headers()
                    .iter()
                    .next()
                    .map(|inner| inner.to_entity())
                    .expect("checked: first last-N header should be existed");
                let verifiable_header = VerifiableHeader::new_from_header_with_chain_root(
                    first_last_n_header.clone(),
                    mmr_activated_epoch,
                );
                if !verifiable_header.is_valid(mmr_activated_epoch, None) {
                    let header = verifiable_header.header();
                    error!(
                        "failed: chain root is not valid for first last-N block#{} (hash: {:#x})",
                        header.number(),
                        header.hash()
                    );
                    return StatusCode::InvalidChainRootForSamples.into();
                }
                let compact_target = first_last_n_header.header().raw().compact_target();
                let block_difficulty = compact_to_difficulty(compact_target.unpack());
                let total_difficulty_before: U256 =
                    first_last_n_header.chain_root().total_difficulty().unpack();
                let total_difficulty = total_difficulty_before.saturating_add(&block_difficulty);

                // All total difficulties for sampled blocks should be less
                // than the total difficulty of any last-N blocks.
                if total_difficulty < difficulty_boundary {
                    difficulties = difficulties
                        .into_iter()
                        .take_while(|d| d < &total_difficulty)
                        .collect();
                }

                // Last-N blocks should be satisfied the follow condition.
                if self.message.last_n_headers().len() as u64 > LAST_N_BLOCKS
                    && total_difficulty < difficulty_boundary
                {
                    trace!(
                        "last_n_headers.len(): {}, total_difficulty: {}, difficulty_boundary: {}",
                        self.message.last_n_headers().len(),
                        total_difficulty,
                        difficulty_boundary,
                    );
                    error!(
                        "failed: total difficulty of any last-N blocks \
                        should be greater than the difficulty boundary \
                        if there are enough blocks",
                    );
                    return StatusCode::InvalidChainRootForSamples.into();
                }
            }

            for item in self.message.sampled_headers().iter() {
                let header_with_chain_root = item.to_entity();
                let verifiable_header = VerifiableHeader::new_from_header_with_chain_root(
                    header_with_chain_root.clone(),
                    mmr_activated_epoch,
                );
                let header = verifiable_header.header();
                // Chain root for any sampled blocks should be valid.
                if !verifiable_header.is_valid(mmr_activated_epoch, None) {
                    error!(
                        "failed: chain root is not valid for sampled block#{} (hash: {:#x})",
                        header.number(),
                        header.hash()
                    );
                    return StatusCode::InvalidChainRootForSamples.into();
                }
                let compact_target = header_with_chain_root.header().raw().compact_target();
                let block_difficulty = compact_to_difficulty(compact_target.unpack());
                let total_difficulty_lhs: U256 = header_with_chain_root
                    .chain_root()
                    .total_difficulty()
                    .unpack();
                let total_difficulty_rhs = total_difficulty_lhs.saturating_add(&block_difficulty);

                let mut is_valid = false;
                // Total difficulty for any sampled blocks should be valid.
                while let Some(curr_difficulty) = difficulties.first().cloned() {
                    if curr_difficulty < total_difficulty_lhs {
                        // Current difficulty has no sample.
                        difficulties.remove(0);
                        continue;
                    } else if curr_difficulty > total_difficulty_rhs {
                        break;
                    } else {
                        // Current difficulty has one sample, and the sample is current block.
                        difficulties.remove(0);
                        is_valid = true;
                    }
                }

                if !is_valid {
                    error!(
                        "failed: total difficulty is not valid for sampled block#{}, \
                        hash is {:#x}, difficulty range is [{},{}].",
                        header.number(),
                        header.hash(),
                        total_difficulty_lhs,
                        total_difficulty_rhs,
                    );
                    return StatusCode::InvalidTotalDifficultyForSamples.into();
                }
            }
        }

        let reorg_last_n_headers = self
            .message
            .reorg_last_n_headers()
            .iter()
            .map(|header| header.to_entity().header().into_view())
            .collect::<Vec<_>>();
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
        trace!(
            "peer {}: reorg_last_n_headers: {}, sampled_headers: {}, last_n_headers: {}",
            self.peer,
            reorg_last_n_headers.len(),
            sampled_headers.len(),
            last_n_headers.len()
        );

        // Check epoch difficulties.
        let failed_to_verify_tau = if prove_request.if_skip_check_tau() {
            trace!("peer {} skip checking TAU since the flag is set", self.peer);
            false
        } else if !sampled_headers.is_empty() {
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
                let start_epoch_difficulty = start_block_difficulty * start_epoch.length();
                let end_epoch_difficulty = end_block_difficulty * end_epoch.length();

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
                            end_epoch_difficulty_min /= tau;
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
        };

        // Check POW.
        let pow_engine = self.protocol.pow_engine();
        for header in reorg_last_n_headers
            .iter()
            .chain(sampled_headers.iter())
            .chain(last_n_headers.iter())
        {
            if !pow_engine.verify(&header.data()) {
                let errmsg = format!(
                    "failed to verify nonce for block#{}, hash: {:#x}",
                    header.number(),
                    header.hash()
                );
                return StatusCode::InvalidNonce.with_context(errmsg);
            }
        }

        if let Some(header) = reorg_last_n_headers.iter().last() {
            let start_number: BlockNumber = prove_request.get_request().start_number().unpack();
            if header.number() != start_number - 1 {
                let errmsg = format!(
                    "failed to verify reorg last block number for block#{}, hash: {:#x}",
                    header.number(),
                    header.hash()
                );
                return StatusCode::InvalidReorgHeaders.with_context(errmsg);
            }
        }
        // Check parent hashes for the continuous headers.
        for headers in reorg_last_n_headers.windows(2) {
            if headers[0].hash() != headers[1].parent_hash() {
                let errmsg = format!(
                    "failed to verify parent hash for block#{}, hash: {:#x}",
                    headers[1].number(),
                    headers[1].hash()
                );
                return StatusCode::InvalidParentHash.with_context(errmsg);
            }
        }
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

        // Verify MMR proof
        let digests_with_positions = {
            let res = reorg_last_n_headers
                .iter()
                .chain(sampled_headers.iter())
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
            trace!("peer {}: verify mmr proof passed", self.peer);
        } else {
            error!("peer {}: verify mmr proof failed", self.peer);
            return StatusCode::FailedToVerifyTheProof.into();
        }
        let expected_root_hash = chain_root.calc_mmr_hash();
        let check_extra_hash_result =
            last_header.is_valid(mmr_activated_epoch, Some(&expected_root_hash));
        if check_extra_hash_result {
            trace!(
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

        // If no sampled headers, we can skip the check for total difficulty.
        if !sampled_headers.is_empty() {
            // Check total difficulty.
            if let Some(prove_state) = peer_state.get_prove_state() {
                let prev_last_header = prove_state.get_last_header();
                let prev_total_difficulty = prove_state.get_total_difficulty();
                if let Err(msg) = verify_total_difficulty(
                    prev_last_header,
                    prev_total_difficulty,
                    last_header,
                    last_total_difficulty,
                ) {
                    return StatusCode::InvalidTotalDifficulty.with_context(msg);
                }
            }
        }

        // Failed to verify TAU, ask for new sampled headers.
        if failed_to_verify_tau {
            if let Some(content) = self.protocol.build_prove_request_content(
                &peer_state,
                last_header,
                last_total_difficulty,
            ) {
                let mut prove_request = ProveRequest::new(
                    LastState::new(last_header.clone(), last_total_difficulty.clone()),
                    content.clone(),
                );
                prove_request.skip_check_tau();
                self.protocol
                    .peers()
                    .submit_prove_request(self.peer, prove_request);

                let message = packed::LightClientMessage::new_builder()
                    .set(content)
                    .build();
                self.nc.reply(self.peer, &message);
            } else {
                log::warn!("peer {}, build prove request failed", self.peer);
            }
        } else {
            let prove_state = ProveState::new_from_request(
                prove_request.to_owned(),
                reorg_last_n_headers,
                last_n_headers,
            );
            self.protocol
                .peers()
                .commit_prove_state(self.peer, prove_state);
        }

        trace!("block proof verify passed");
        Status::ok()
    }
}

#[derive(Debug, Clone)]
pub(crate) enum EpochDifficultyTrend {
    Unchanged,
    Increased { start: U256, end: U256 },
    Decreased { start: U256, end: U256 },
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum EstimatedLimit {
    Min,
    Max,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum EpochCountGroupByTrend {
    Increased(u64),
    Decreased(u64),
}

#[derive(Debug, Clone)]
pub(crate) struct EpochDifficultyTrendDetails {
    pub(crate) start: EpochCountGroupByTrend,
    pub(crate) end: EpochCountGroupByTrend,
}

impl EpochDifficultyTrend {
    pub(crate) fn new(start_epoch_difficulty: &U256, end_epoch_difficulty: &U256) -> Self {
        match start_epoch_difficulty.cmp(end_epoch_difficulty) {
            Ordering::Equal => Self::Unchanged,
            Ordering::Less => Self::Increased {
                start: start_epoch_difficulty.clone(),
                end: end_epoch_difficulty.clone(),
            },
            Ordering::Greater => Self::Decreased {
                start: start_epoch_difficulty.clone(),
                end: end_epoch_difficulty.clone(),
            },
        }
    }

    // Calculate the `k` which satisfied that
    // - `0 <= k < limit`;
    // - If the epoch difficulty was
    //   - unchanged: `k = 0`.
    //   - increased: `lhs * (tau ^ k) < rhs <= lhs * (tau ^ (k+1))`.
    //   - decreased: `lhs * (tau ^ (-k)) > rhs >= lhs * (tau ^ (-k-1))`.
    //
    // Ref: Page 18, 6.1 Variable Difficulty MMR in [FlyClient: Super-Light Clients for Cryptocurrencies].
    //
    // [FlyClient: Super-Light Clients for Cryptocurrencies]: https://eprint.iacr.org/2019/226.pdf
    pub(crate) fn calculate_tau_exponent(&self, tau: u64, limit: u64) -> Option<u64> {
        match self {
            Self::Unchanged => Some(0),
            Self::Increased { ref start, ref end } => {
                let mut tmp = start.clone();
                let tau_u256 = U256::from(tau);
                for k in 0..limit {
                    tmp = tmp.saturating_mul(&tau_u256);
                    if tmp >= *end {
                        return Some(k);
                    }
                }
                None
            }

            Self::Decreased { ref start, ref end } => {
                let mut tmp = start.clone();
                for k in 0..limit {
                    tmp /= tau;
                    if tmp <= *end {
                        return Some(k);
                    }
                }
                None
            }
        }
    }

    // Split the epochs into two parts base on the trend of their difficulty changed,
    // then calculate the length of each parts.
    //
    // ### Note
    //
    // - To estimate:
    //   - the minimum limit, decreasing the epoch difficulty at first, then increasing.
    //   - the maximum limit, increasing the epoch difficulty at first, then decreasing.
    //
    // - Both parts of epochs exclude the start block and the end block.
    pub(crate) fn split_epochs(
        &self,
        limit: EstimatedLimit,
        n: u64,
        k: u64,
    ) -> EpochDifficultyTrendDetails {
        let (increased, decreased) = match (limit, self) {
            (EstimatedLimit::Min, Self::Unchanged) => {
                let decreased = (n + 1) / 2;
                let increased = n - decreased;
                (increased, decreased)
            }
            (EstimatedLimit::Max, Self::Unchanged) => {
                let increased = (n + 1) / 2;
                let decreased = n - increased;
                (increased, decreased)
            }
            (EstimatedLimit::Min, Self::Increased { .. }) => {
                let decreased = (n - k + 1) / 2;
                let increased = n - decreased;
                (increased, decreased)
            }
            (EstimatedLimit::Max, Self::Increased { .. }) => {
                let increased = (n - k + 1) / 2 + k;
                let decreased = n - increased;
                (increased, decreased)
            }
            (EstimatedLimit::Min, Self::Decreased { .. }) => {
                let decreased = (n - k + 1) / 2 + k;
                let increased = n - decreased;
                (increased, decreased)
            }
            (EstimatedLimit::Max, Self::Decreased { .. }) => {
                let increased = (n - k + 1) / 2;
                let decreased = n - increased;
                (increased, decreased)
            }
        };
        match limit {
            EstimatedLimit::Min => EpochDifficultyTrendDetails {
                start: EpochCountGroupByTrend::Decreased(decreased),
                end: EpochCountGroupByTrend::Increased(increased),
            },
            EstimatedLimit::Max => EpochDifficultyTrendDetails {
                start: EpochCountGroupByTrend::Increased(increased),
                end: EpochCountGroupByTrend::Decreased(decreased),
            },
        }
    }

    // Calculate the limit of total difficulty.
    pub(crate) fn calculate_total_difficulty_limit(
        &self,
        start_epoch_difficulty: &U256,
        tau: u64,
        details: &EpochDifficultyTrendDetails,
    ) -> U256 {
        let mut curr = start_epoch_difficulty.clone();
        let mut total = U256::zero();
        let tau_u256 = U256::from(tau);
        for group in &[details.start, details.end] {
            match group {
                EpochCountGroupByTrend::Decreased(epochs_count) => {
                    let state = "decreased";
                    for index in 0..*epochs_count {
                        curr /= tau;
                        total = total.checked_add(&curr).unwrap_or_else(|| {
                            panic!(
                                "overflow when calculate the limit of total difficulty, \
                                total: {}, current: {}, index: {}/{}, tau: {}, \
                                state: {}, trend: {:?}, details: {:?}",
                                total, curr, index, epochs_count, tau, state, self, details
                            );
                        })
                    }
                }
                EpochCountGroupByTrend::Increased(epochs_count) => {
                    let state = "increased";
                    for index in 0..*epochs_count {
                        curr = curr.saturating_mul(&tau_u256);
                        total = total.checked_add(&curr).unwrap_or_else(|| {
                            panic!(
                                "overflow when calculate the limit of total difficulty, \
                                total: {}, current: {}, index: {}/{}, tau: {}, \
                                state: {}, trend: {:?}, details: {:?}",
                                total, curr, index, epochs_count, tau, state, self, details
                            );
                        })
                    }
                }
            }
        }
        total
    }
}

impl EpochCountGroupByTrend {
    pub(crate) fn subtract1(self) -> Self {
        match self {
            Self::Increased(count) => Self::Increased(count - 1),
            Self::Decreased(count) => Self::Decreased(count - 1),
        }
    }

    pub(crate) fn epochs_count(self) -> u64 {
        match self {
            Self::Increased(count) | Self::Decreased(count) => count,
        }
    }
}

impl EpochDifficultyTrendDetails {
    pub(crate) fn remove_last_epoch(self) -> Self {
        let Self { start, end } = self;
        if end.epochs_count() == 0 {
            Self {
                start: start.subtract1(),
                end,
            }
        } else {
            Self {
                start,
                end: end.subtract1(),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn total_epochs_count(&self) -> u64 {
        self.start.epochs_count() + self.end.epochs_count()
    }
}

pub fn verify_total_difficulty(
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
        let epoch_difficulty_trend =
            EpochDifficultyTrend::new(&start_epoch_difficulty, &end_epoch_difficulty);

        let tau = TAU;

        // Step-1 Check the magnitude of the difficulty changes.
        let k = epoch_difficulty_trend
            .calculate_tau_exponent(tau, epochs_switch_count)
            .ok_or_else(|| {
                format!(
                    "failed since the epoch difficulty changed \
                    too fast ({}->{}) during epochs ([{},{}])",
                    start_epoch_difficulty, end_epoch_difficulty, start_epoch, end_epoch
                )
            })?;

        // Step-2 Check the range of total difficulty.
        let start_epoch_blocks_count = start_epoch.length() - start_epoch.index() - 1;
        let end_epoch_blocks_count = end_epoch.index() + 1;
        let unaligned_difficulty_calculated = &start_block_difficulty * start_epoch_blocks_count
            + &end_block_difficulty * end_epoch_blocks_count;
        if epochs_switch_count == 1 {
            if total_difficulty != unaligned_difficulty_calculated {
                let errmsg = format!(
                    "failed since total difficulty is {} \
                    but the calculated is {} (= {} * {} + {} * {}) \
                    during epochs ([{:#},{:#}])",
                    total_difficulty,
                    unaligned_difficulty_calculated,
                    start_block_difficulty,
                    start_epoch_blocks_count,
                    end_block_difficulty,
                    end_epoch_blocks_count,
                    start_epoch,
                    end_epoch
                );
                return Err(errmsg);
            }
        } else {
            // `k < n` was checked in Step-1.
            // `n / 2 >= 1` was checked since the above branch.
            let n = epochs_switch_count;
            let diff = &start_epoch_difficulty;
            let aligned_difficulty_min = {
                let details = epoch_difficulty_trend
                    .split_epochs(EstimatedLimit::Min, n, k)
                    .remove_last_epoch();
                epoch_difficulty_trend.calculate_total_difficulty_limit(diff, tau, &details)
            };
            let aligned_difficulty_max = {
                let details = epoch_difficulty_trend
                    .split_epochs(EstimatedLimit::Max, n, k)
                    .remove_last_epoch();
                epoch_difficulty_trend.calculate_total_difficulty_limit(diff, tau, &details)
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

#[cfg(test)]
mod tests {
    use ckb_types::{u256, U256};

    use super::{EpochDifficultyTrend, EstimatedLimit};

    #[test]
    fn test_calculate_tau_exponent() {
        let tau = 2;
        let limit_min = 2;
        let tau_u256 = U256::from(tau);
        let testcases = [
            // Unchanged & Increased / Decreased a few
            (u256!("0x100"), u256!("0x7f"), 1),
            (u256!("0x100"), u256!("0x80"), 0),
            (u256!("0x100"), u256!("0xff"), 0),
            (u256!("0x100"), u256!("0x100"), 0),
            (u256!("0x100"), u256!("0x101"), 0),
            (u256!("0x100"), u256!("0x200"), 0),
            (u256!("0x100"), u256!("0x201"), 1),
            // Increased a lot
            (u256!("0xff"), u256!("0x1000"), 4),
            (u256!("0x100"), u256!("0xfff"), 3),
            (u256!("0x100"), u256!("0x1000"), 3),
            (u256!("0x100"), u256!("0x1001"), 4),
            (u256!("0x101"), u256!("0x1000"), 3),
            // Decreased a lot
            (u256!("0x1000"), u256!("0xff"), 4),
            (u256!("0xfff"), u256!("0x100"), 3),
            (u256!("0x1000"), u256!("0x100"), 3),
            (u256!("0x1001"), u256!("0x100"), 3),
            (u256!("0x1000"), u256!("0x101"), 3),
        ];
        for (diff_start, diff_end, k) in testcases {
            let trend = EpochDifficultyTrend::new(&diff_start, &diff_end);
            for limit in limit_min..=(limit_min + k + 5) {
                let actual = trend.calculate_tau_exponent(tau, limit);
                let expected = if k == 0 || limit > k { Some(k) } else { None };
                assert_eq!(
                    actual, expected,
                    "{:#x} -> {:#x} (limit: {}, tau: {}) expect {:?} but got {:?}",
                    diff_start, diff_end, limit, tau, expected, actual
                );
            }
            let diff_end_scope = {
                let mut tmp = diff_start.clone();
                match trend {
                    EpochDifficultyTrend::Unchanged => (diff_end == tmp, tmp.clone(), tmp),
                    EpochDifficultyTrend::Increased { .. } => {
                        for _ in 0..k {
                            tmp = tmp.saturating_mul(&tau_u256);
                        }
                        let diff_end_lt = tmp.clone();
                        let diff_end_ge = tmp.saturating_mul(&tau_u256);
                        let in_scope = diff_end_lt < diff_end && diff_end <= diff_end_ge;
                        (in_scope, diff_end_lt, diff_end_ge)
                    }
                    EpochDifficultyTrend::Decreased { .. } => {
                        for _ in 0..k {
                            tmp /= tau;
                        }
                        let diff_end_gt = tmp.clone();
                        let diff_end_le = tmp / tau;
                        let in_scope = diff_end_gt > diff_end && diff_end >= diff_end_le;
                        (in_scope, diff_end_gt, diff_end_le)
                    }
                }
            };
            assert!(
                diff_end_scope.0,
                "{:#x} -> {:#x} got a incorrect scope ({:#x}, {:#x}]",
                diff_start, diff_end, diff_end_scope.1, diff_end_scope.2,
            );
        }
    }

    #[test]
    fn test_split_epochs() {
        let tau = 2;
        let testcases = [
            // Unchanged
            (u256!("0x100"), u256!("0x100")),
            // Increased
            (u256!("0x100"), u256!("0x1000")),
            // Decreased
            (u256!("0x1000"), u256!("0x100")),
        ];
        for (diff_start, diff_end) in testcases {
            let trend = EpochDifficultyTrend::new(&diff_start, &diff_end);
            let k = trend.calculate_tau_exponent(tau, u64::MAX).unwrap();
            let n_min = if k < 2 { 2 } else { k + 1 };
            for n in n_min..=(n_min + 10) {
                for limit in [EstimatedLimit::Min, EstimatedLimit::Max] {
                    let details = trend.split_epochs(limit, n, k);
                    let total_epochs_count = details.total_epochs_count();
                    assert_eq!(
                        total_epochs_count, n,
                        "{:#x} -> {:#x} (n: {}, k: {}, {:?}) \
                        total epochs count should be `n` but got {}",
                        diff_start, diff_end, n, k, limit, total_epochs_count,
                    );
                    let start_epochs_count = details.start.epochs_count();
                    let end_epochs_count = details.end.epochs_count();
                    let check_counts = {
                        let remainder = (n - k) % 2;
                        match trend {
                            EpochDifficultyTrend::Unchanged => {
                                start_epochs_count == end_epochs_count + remainder
                            }
                            EpochDifficultyTrend::Increased { .. } => match limit {
                                EstimatedLimit::Min => {
                                    start_epochs_count + k == end_epochs_count + remainder
                                }
                                EstimatedLimit::Max => {
                                    start_epochs_count == end_epochs_count + k + remainder
                                }
                            },
                            EpochDifficultyTrend::Decreased { .. } => match limit {
                                EstimatedLimit::Min => {
                                    start_epochs_count == end_epochs_count + k + remainder
                                }
                                EstimatedLimit::Max => {
                                    start_epochs_count + k == end_epochs_count + remainder
                                }
                            },
                        }
                    };
                    assert!(
                        check_counts,
                        "{:#x} -> {:#x} (n: {}, k: {}, {:?}) \
                        epochs count (start: {}, end: {}) is incorrect",
                        diff_start, diff_end, n, k, limit, start_epochs_count, end_epochs_count,
                    );
                    let total_epochs_count_without_last_epoch =
                        details.clone().remove_last_epoch().total_epochs_count();
                    assert_eq!(
                        total_epochs_count_without_last_epoch,
                        n - 1,
                        "{:#x} -> {:#x} (n: {}, k: {}, {:?}) \
                        total epochs count without last epoch should be `n-1` but got {}",
                        diff_start,
                        diff_end,
                        n,
                        k,
                        limit,
                        total_epochs_count_without_last_epoch,
                    );
                }
            }
        }
    }

    #[test]
    fn test_calculate_total_difficulty_limit() {
        let tau = 2;
        let testcases = [
            // Unchanged
            (u256!("0x100"), u256!("0x100")),
            // Increased
            (u256!("0x100"), u256!("0x1000")),
            // Decreased
            (u256!("0x1000"), u256!("0x100")),
        ];
        for (diff_start, diff_end) in testcases {
            let trend = EpochDifficultyTrend::new(&diff_start, &diff_end);
            let k = trend.calculate_tau_exponent(tau, u64::MAX).unwrap();
            let n_min = if k < 2 { 2 } else { k + 1 };
            for n in n_min..=(n_min + 10) {
                for limit in [EstimatedLimit::Min, EstimatedLimit::Max] {
                    let details = trend.split_epochs(limit, n, k).remove_last_epoch();
                    let actual = trend.calculate_total_difficulty_limit(&diff_start, tau, &details);
                    let expected = {
                        let start_epochs_count = details.start.epochs_count();
                        let end_epochs_count = details.end.epochs_count();
                        let mut curr = diff_start.clone();
                        let mut total = U256::zero();
                        match limit {
                            EstimatedLimit::Min => {
                                for _ in 0..start_epochs_count {
                                    curr /= tau;
                                    total += &curr;
                                }
                                for _ in 0..end_epochs_count {
                                    curr *= tau;
                                    total += &curr;
                                }
                            }
                            EstimatedLimit::Max => {
                                for _ in 0..start_epochs_count {
                                    curr *= tau;
                                    total += &curr;
                                }
                                for _ in 0..end_epochs_count {
                                    curr /= tau;
                                    total += &curr;
                                }
                            }
                        }
                        total
                    };
                    assert_eq!(
                        actual, expected,
                        "{:#x} -> {:#x} (tau: {}, n: {}, k: {}, {:?}) \
                        total difficulty expected {:#x} but got {:#x}",
                        diff_start, diff_end, tau, n, k, limit, expected, actual,
                    );
                }
            }
        }
    }
}
