use std::sync::Arc;

use crate::{
    storage::StorageWithChainData,
    tests::{prelude::*, utils::MockChain},
    verify::verify_tx,
};
use ckb_jsonrpc_types::Transaction;
use ckb_types::{
    packed::{self},
    prelude::{IntoHeaderView, IntoTransactionView as _},
};

#[test]
fn non_contextual_transaction_verifier() {
    let chain = MockChain::new_with_default_pow("non_contextual_transaction_verifier");
    let storage = chain.client_storage();
    let consensus = Arc::new(chain.consensus().clone());
    let swc =
        StorageWithChainData::new(storage.to_owned(), chain.create_peers(), Default::default());

    // duplicate cell deps base on a valid transaction
    // https://pudge.explorer.nervos.org/transaction/0xf34f4eaac4a662927fb52d4cb608e603150b9e0678a0f5ed941e3cfd5b68fb30
    let transaction: packed::Transaction = serde_json::from_str::<Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}, {"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap().into();
    let error = verify_tx(
        transaction.into_view(),
        &swc,
        Arc::clone(&consensus),
        &swc.storage().get_last_state().1.into_view(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("DuplicateCellDeps"));

    // insufficient cell capacity
    let transaction: packed::Transaction = serde_json::from_str::<Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb6113","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap().into();
    let error = verify_tx(
        transaction.into_view(),
        &swc,
        consensus,
        &swc.storage().get_last_state().1.into_view(),
    )
    .unwrap_err();
    assert!(error.to_string().contains("InsufficientCellCapacity"));
}
