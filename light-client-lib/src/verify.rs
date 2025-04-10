use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    sync::Arc,
};

use byteorder::{ByteOrder, LittleEndian};
use ckb_chain_spec::consensus::Consensus;
use ckb_dao_utils::{extract_dao_data, DaoError};
use ckb_error::Error;
use ckb_script::TxVerifyEnv;
use ckb_traits::{CellDataProvider, ExtensionProvider, HeaderFieldsProvider, HeaderProvider};
use ckb_tx_pool::error::Reject;
use ckb_types::{
    bytes::Bytes,
    core::{
        cell::{CellMeta, CellProvider, CellStatus, ResolvedTransaction},
        error::OutPointError,
        Capacity, Cycle, DepType, FeeRate, HeaderView, ScriptHashType, TransactionView,
    },
    packed::{Byte32, CellOutput, OutPoint, OutPointVec, Script, WitnessArgs},
    prelude::{Entity, Unpack},
};
use ckb_verification::{
    CapacityVerifier, NonContextualTransactionVerifier, ScriptVerifier,
    TimeRelativeTransactionVerifier,
};

/// A FeeCalculator for transactions, adapted from `DaoCalculator` in `ckb-dao`
pub struct FeeCalculator<DL> {
    consensus: Arc<Consensus>,
    data_loader: Arc<DL>,
}

impl<DL: CellDataProvider + HeaderProvider> FeeCalculator<DL> {
    /// Creates a new `FeeCalculator`.
    pub fn new(consensus: Arc<Consensus>, data_loader: Arc<DL>) -> Self {
        FeeCalculator {
            consensus,
            data_loader,
        }
    }

    /// Returns the total transactions fee of `rtx`.
    pub fn transaction_fee(&self, rtx: &ResolvedTransaction) -> Result<Capacity, DaoError> {
        let maximum_withdraw = self.transaction_maximum_withdraw(rtx)?;
        rtx.transaction
            .outputs_capacity()
            .and_then(|y| maximum_withdraw.safe_sub(y))
            .map_err(Into::into)
    }

    fn transaction_maximum_withdraw(
        &self,
        rtx: &ResolvedTransaction,
    ) -> Result<Capacity, DaoError> {
        let header_deps: HashSet<Byte32> = rtx.transaction.header_deps_iter().collect();
        rtx.resolved_inputs.iter().enumerate().try_fold(
            Capacity::zero(),
            |capacities, (i, cell_meta)| {
                let capacity: Result<Capacity, DaoError> = {
                    let output = &cell_meta.cell_output;
                    let is_dao_type_script = |type_script: Script| {
                        Into::<u8>::into(type_script.hash_type())
                            == Into::<u8>::into(ScriptHashType::Type)
                            && type_script.code_hash() == self.consensus.dao_type_hash()
                    };
                    let is_withdrawing_input =
                        |cell_meta: &CellMeta| match self.data_loader.load_cell_data(cell_meta) {
                            Some(data) => data.len() == 8 && LittleEndian::read_u64(&data) > 0,
                            None => false,
                        };
                    if output
                        .type_()
                        .to_opt()
                        .map(is_dao_type_script)
                        .unwrap_or(false)
                        && is_withdrawing_input(cell_meta)
                    {
                        let withdrawing_header_hash = cell_meta
                            .transaction_info
                            .as_ref()
                            .map(|info| &info.block_hash)
                            .filter(|hash| header_deps.contains(hash))
                            .ok_or(DaoError::InvalidOutPoint)?;
                        let deposit_header_hash = rtx
                            .transaction
                            .witnesses()
                            .get(i)
                            .ok_or(DaoError::InvalidOutPoint)
                            .and_then(|witness_data| {
                                // dao contract stores header deps index as u64 in the input_type field of WitnessArgs
                                let witness = WitnessArgs::from_slice(&Unpack::<Bytes>::unpack(
                                    &witness_data,
                                ))
                                .map_err(|_| DaoError::InvalidDaoFormat)?;
                                let header_deps_index_data: Option<Bytes> = witness
                                    .input_type()
                                    .to_opt()
                                    .map(|witness| witness.unpack());
                                if header_deps_index_data.is_none()
                                    || header_deps_index_data.clone().map(|data| data.len())
                                        != Some(8)
                                {
                                    return Err(DaoError::InvalidDaoFormat);
                                }
                                Ok(LittleEndian::read_u64(&header_deps_index_data.unwrap()))
                            })
                            .and_then(|header_dep_index| {
                                rtx.transaction
                                    .header_deps()
                                    .get(header_dep_index as usize)
                                    .and_then(|hash| header_deps.get(&hash))
                                    .ok_or(DaoError::InvalidOutPoint)
                            })?;
                        self.calculate_maximum_withdraw(
                            output,
                            Capacity::bytes(cell_meta.data_bytes as usize)?,
                            deposit_header_hash,
                            withdrawing_header_hash,
                        )
                    } else {
                        Ok(output.capacity().unpack())
                    }
                };
                capacity.and_then(|c| c.safe_add(capacities).map_err(Into::into))
            },
        )
    }

    /// Calculate maximum withdraw capacity of a deposited dao output
    pub fn calculate_maximum_withdraw(
        &self,
        output: &CellOutput,
        output_data_capacity: Capacity,
        deposit_header_hash: &Byte32,
        withdrawing_header_hash: &Byte32,
    ) -> Result<Capacity, DaoError> {
        let deposit_header = self
            .data_loader
            .get_header(deposit_header_hash)
            .ok_or(DaoError::InvalidHeader)?;
        let withdrawing_header = self
            .data_loader
            .get_header(withdrawing_header_hash)
            .ok_or(DaoError::InvalidHeader)?;
        if deposit_header.number() >= withdrawing_header.number() {
            return Err(DaoError::InvalidOutPoint);
        }

        let (deposit_ar, _, _, _) = extract_dao_data(deposit_header.dao());
        let (withdrawing_ar, _, _, _) = extract_dao_data(withdrawing_header.dao());

        let occupied_capacity = output.occupied_capacity(output_data_capacity)?;
        let output_capacity: Capacity = output.capacity().unpack();
        let counted_capacity = output_capacity.safe_sub(occupied_capacity)?;
        let withdraw_counted_capacity = u128::from(counted_capacity.as_u64())
            * u128::from(withdrawing_ar)
            / u128::from(deposit_ar);
        let withdraw_capacity =
            Capacity::shannons(withdraw_counted_capacity as u64).safe_add(occupied_capacity)?;
        Ok(withdraw_capacity)
    }
}

/// Used to verify if a transaction meets the lowest fee rate
pub struct MinFeeVerifier<DL> {
    min_fee_rate: FeeRate,
    resolved_tx: Arc<ResolvedTransaction>,
    fee_calculator: FeeCalculator<DL>,
}
impl<DL: CellDataProvider + HeaderProvider> MinFeeVerifier<DL> {
    /// Creates a new `MinFeeVerifier`.
    pub fn new(
        min_fee_rate: FeeRate,
        resolved_tx: Arc<ResolvedTransaction>,
        consensus: Arc<Consensus>,
        data_loader: Arc<DL>,
    ) -> Self {
        Self {
            min_fee_rate,
            resolved_tx,
            fee_calculator: FeeCalculator::new(consensus, data_loader),
        }
    }
    /// Verify if the transaction meets the lowest fee rate set by `min_fee_rate`
    pub fn verify(&self) -> Result<(), Error> {
        let fee = self.fee_calculator.transaction_fee(&self.resolved_tx)?;
        let tx_size = self
            .resolved_tx
            .transaction
            .data()
            .serialized_size_in_block();
        let min_fee = self.min_fee_rate.fee(tx_size as u64);
        if fee < min_fee {
            return Err(
                Reject::LowFeeRate(self.min_fee_rate, min_fee.as_u64(), fee.as_u64()).into(),
            );
        }
        Ok(())
    }
}
/// Light client can only verify non-cellbase transaction,
/// can not reuse the `ContextualTransactionVerifier` in ckb_verification crate which is used to verify cellbase also.
pub struct ContextualTransactionVerifier<T>
where
    T: CellDataProvider + HeaderProvider + ExtensionProvider + Send + Sync + Clone + 'static,
{
    pub(crate) time_relative: TimeRelativeTransactionVerifier<T>,
    pub(crate) capacity: CapacityVerifier,
    pub(crate) script: ScriptVerifier<T>,
    pub(crate) min_fee_rate: MinFeeVerifier<T>,
}

impl<T> ContextualTransactionVerifier<T>
where
    T: CellDataProvider
        + HeaderFieldsProvider
        + CellProvider
        + HeaderProvider
        + ExtensionProvider
        + Send
        + Sync
        + Clone
        + 'static,
{
    /// Creates a new ContextualTransactionVerifier
    pub fn new(
        rtx: Arc<ResolvedTransaction>,
        consensus: Arc<Consensus>,
        swc: &T,
        tx_env: Arc<TxVerifyEnv>,
    ) -> Self {
        ContextualTransactionVerifier {
            time_relative: TimeRelativeTransactionVerifier::new(
                Arc::clone(&rtx),
                Arc::clone(&consensus),
                swc.clone(),
                Arc::clone(&tx_env),
            ),
            script: ScriptVerifier::new(
                Arc::clone(&rtx),
                swc.clone(),
                Arc::clone(&consensus),
                Arc::clone(&tx_env),
            ),
            capacity: CapacityVerifier::new(Arc::clone(&rtx), consensus.dao_type_hash()),
            min_fee_rate: MinFeeVerifier::new(
                FeeRate(1_0000_0000),
                Arc::clone(&rtx),
                Arc::clone(&consensus),
                swc.clone().into(),
            ),
        }
    }

    pub fn verify(&self, max_cycles: Cycle) -> Result<Cycle, Error> {
        self.time_relative.verify()?;
        self.capacity.verify()?;
        self.min_fee_rate.verify()?;
        self.script.verify(max_cycles)
    }
}

pub fn verify_tx<T>(
    transaction: TransactionView,
    swc: &T,
    consensus: Arc<Consensus>,
    tip_header: &HeaderView,
) -> Result<Cycle, Error>
where
    T: CellDataProvider
        + HeaderFieldsProvider
        + HeaderProvider
        + ExtensionProvider
        + CellProvider
        + Send
        + Sync
        + Clone
        + 'static,
{
    NonContextualTransactionVerifier::new(&transaction, &consensus).verify()?;
    let rtx = resolve_tx(swc, transaction)?;
    let tx_env = TxVerifyEnv::new_submit(tip_header);
    ContextualTransactionVerifier::new(Arc::new(rtx), Arc::clone(&consensus), swc, Arc::new(tx_env))
        .verify(consensus.max_block_cycles())
}

pub(crate) fn resolve_tx<T>(
    swc: &T,
    transaction: TransactionView,
) -> Result<ResolvedTransaction, OutPointError>
where
    T: CellDataProvider
        + HeaderFieldsProvider
        + HeaderProvider
        + ExtensionProvider
        + Send
        + Sync
        + Clone
        + CellProvider
        + 'static,
{
    let (mut resolved_inputs, mut resolved_cell_deps, mut resolved_dep_groups) = (
        Vec::with_capacity(transaction.inputs().len()),
        Vec::with_capacity(transaction.cell_deps().len()),
        Vec::new(),
    );
    let mut current_inputs = HashSet::new();

    let mut resolved_cells: HashMap<(OutPoint, bool), CellMeta> = HashMap::new();
    let mut resolve_cell =
        |out_point: &OutPoint, eager_load: bool| -> Result<CellMeta, OutPointError> {
            match resolved_cells.entry((out_point.clone(), eager_load)) {
                Entry::Occupied(entry) => Ok(entry.get().clone()),
                Entry::Vacant(entry) => {
                    let cell_status = swc.cell(out_point, eager_load);
                    match cell_status {
                        CellStatus::Dead => Err(OutPointError::Dead(out_point.clone())),
                        CellStatus::Unknown => Err(OutPointError::Unknown(out_point.clone())),
                        CellStatus::Live(cell_meta) => {
                            entry.insert(cell_meta.clone());
                            Ok(cell_meta)
                        }
                    }
                }
            }
        };

    for out_point in transaction.input_pts_iter() {
        if !current_inputs.insert(out_point.to_owned()) {
            return Err(OutPointError::Dead(out_point));
        }
        resolved_inputs.push(resolve_cell(&out_point, false)?);
    }

    for cell_dep in transaction.cell_deps_iter() {
        if cell_dep.dep_type() == DepType::DepGroup.into() {
            let outpoint = cell_dep.out_point();
            let dep_group = resolve_cell(&outpoint, true)?;
            let data = dep_group
                .mem_cell_data
                .as_ref()
                .expect("Load cell meta must with data");
            let sub_out_points =
                parse_dep_group_data(data).map_err(|_| OutPointError::InvalidDepGroup(outpoint))?;

            for sub_out_point in sub_out_points.into_iter() {
                resolved_cell_deps.push(resolve_cell(&sub_out_point, false)?);
            }
            resolved_dep_groups.push(dep_group);
        } else {
            resolved_cell_deps.push(resolve_cell(&cell_dep.out_point(), false)?);
        }
    }

    Ok(ResolvedTransaction {
        transaction,
        resolved_inputs,
        resolved_cell_deps,
        resolved_dep_groups,
    })
}

fn parse_dep_group_data(slice: &[u8]) -> Result<OutPointVec, String> {
    if slice.is_empty() {
        Err("data is empty".to_owned())
    } else {
        match OutPointVec::from_slice(slice) {
            Ok(v) => {
                if v.is_empty() {
                    Err("dep group is empty".to_owned())
                } else {
                    Ok(v)
                }
            }
            Err(err) => Err(err.to_string()),
        }
    }
}
