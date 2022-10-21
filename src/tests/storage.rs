use ckb_types::packed::Script;

use crate::storage;
use crate::tests::utils::new_storage;

#[test]
fn test_forget_update_min_filtred_number() {
    let storage = new_storage("forget_update_min_filtred_block");
    storage.update_min_filtered_block_number(66);
    storage.update_filter_scripts(vec![
        storage::ScriptStatus {
            script: Script::default(),
            script_type: storage::ScriptType::Lock,
            block_number: 33,
        },
        storage::ScriptStatus {
            script: Script::default(),
            script_type: storage::ScriptType::Type,
            block_number: 44,
        },
    ]);
    assert_eq!(storage.get_min_filtered_block_number(), 33);
}
