use std::collections::HashMap;

use ckb_chain_spec::{consensus::Consensus, ChainSpec};
use ckb_jsonrpc_types::{Block, Script, Transaction};
use ckb_resource::Resource;
use ckb_types::packed;

use crate::{storage::Storage, verify::verify_tx};

pub fn setup(prefix: &str) -> (Storage, Consensus) {
    let tmp_dir = tempfile::Builder::new().prefix(prefix).tempdir().unwrap();
    let storage = Storage::new(tmp_dir.path().to_str().unwrap());
    let chain_spec = ChainSpec::load_from(&Resource::bundled("specs/testnet.toml".to_string()))
        .expect("load spec should be OK");
    let consensus = chain_spec
        .build_consensus()
        .expect("build consensus should be OK");
    storage.init_genesis_block(consensus.genesis_block().data());
    (storage, consensus)
}

#[test]
fn verify_valid_transaction() {
    let (storage, consensus) = setup("verify_valid_transaction");
    // https://pudge.explorer.nervos.org/address/ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsq0l2z2v9305wm7rs5gqrpsf507ey8wj3tggtl4sj
    let script: packed::Script = serde_json::from_str::<Script>(r#"{"code_hash": "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type": "type","args": "0xff5094c2c5f476fc38510018609a3fd921dd28ad"}"#).unwrap().into();
    let mut scripts = HashMap::new();
    scripts.insert(script, 0);
    storage.update_filter_scripts(scripts);

    // https://pudge.explorer.nervos.org/block/261
    let block: packed::Block = serde_json::from_str::<Block>(r#"{"header":{"compact_target":"0x1e015555","dao":"0x18f067d6835aa12e81d52889fd862300aa4aa421700c0000003ef78768fcfe06","epoch":"0x3e80105000000","extra_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","nonce":"0x32daf82076f991d5b69674ed257385eb","number":"0x105","parent_hash":"0xe883cd26172309608574ab5e7fad5dbdb4c82d6dcbac407f3d81b4b50f46f513","proposals_hash":"0x0000000000000000000000000000000000000000000000000000000000000000","timestamp":"0x1723baeb815","transactions_root":"0xf7250b8db808b34d96276a5b146a93b14372ff58abe4eb8927c6955446bca748","version":"0x0"},"proposals":[],"transactions":[{"cell_deps":[],"header_deps":[],"inputs":[{"previous_output":{"index":"0xffffffff","tx_hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"since":"0x105"}],"outputs":[{"capacity":"0x2ecbd5b8aa","lock":{"args":"0xda648442dbb7347e467d1d09da13e5cd3a0ef0e1","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x"],"version":"0x0","witnesses":["0x5d0000000c00000055000000490000001000000030000000310000009bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce80114000000da648442dbb7347e467d1d09da13e5cd3a0ef0e104000000deadbeef"]},{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}],"uncles":[]}"#).unwrap().into();
    storage.filter_block(block);

    // https://pudge.explorer.nervos.org/transaction/0xf34f4eaac4a662927fb52d4cb608e603150b9e0678a0f5ed941e3cfd5b68fb30
    let transaction: packed::Transaction = serde_json::from_str::<Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap().into();

    let result = verify_tx(transaction.into_view(), &storage, &consensus).unwrap();
    assert_eq!(1682789, result);
}

#[test]
fn non_contextual_transaction_verifier() {
    let (storage, consensus) = setup("non_contextual_transaction_verifier");
    // duplicate cell deps base on a valid transaction
    // https://pudge.explorer.nervos.org/transaction/0xf34f4eaac4a662927fb52d4cb608e603150b9e0678a0f5ed941e3cfd5b68fb30
    let transaction: packed::Transaction = serde_json::from_str::<Transaction>(r#"{"cell_deps":[{"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}, {"dep_type":"dep_group","out_point":{"index":"0x0","tx_hash":"0xf8de3bb47d055cdf460d93a2a6e1b05f7432f9777c8c474abf4eec1d4aee5d37"}}],"header_deps":[],"inputs":[{"previous_output":{"index":"0x7","tx_hash":"0x8f8c79eb6671709633fe6a46de93c0fedc9c1b8a6527a18d3983879542635c9f"},"since":"0x0"}],"outputs":[{"capacity":"0x470de4df820000","lock":{"args":"0xff5094c2c5f476fc38510018609a3fd921dd28ad","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null},{"capacity":"0xb61134e5a35e800","lock":{"args":"0x64257f00b6b63e987609fa9be2d0c86d351020fb","code_hash":"0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8","hash_type":"type"},"type":null}],"outputs_data":["0x","0x"],"version":"0x0","witnesses":["0x5500000010000000550000005500000041000000af34b54bebf8c5971da6a880f2df5a186c3f8d0b5c9a1fe1a90c95b8a4fb89ef3bab1ccec13797dcb3fee80400f953227dd7741227e08032e3598e16ccdaa49c00"]}"#).unwrap().into();
    let error = verify_tx(transaction.into_view(), &storage, &consensus).unwrap_err();
    assert!(error.to_string().contains("DuplicateCellDeps"));
}
