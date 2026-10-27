use wasm_bindgen_test::wasm_bindgen_test;
use web_sys::js_sys::{Int32Array, SharedArrayBuffer, Uint8Array};

use crate::{read_command_payload, write_command_with_payload, InputCommand, OutputCommand};

#[wasm_bindgen_test]
fn checked_worker_capability_and_legacy_command_bytes() {
    use crate::{
        require_checked_scan_worker, DbCommandRequest, IteratorDirection, IteratorStart,
        CHECKED_SCAN_WORKER_VERSION,
    };
    let old_payload = bincode::serialize(&true).unwrap();
    assert_eq!(old_payload, vec![1]);
    let old_version = bincode::deserialize::<u8>(&old_payload).unwrap();
    assert!(require_checked_scan_worker(old_version).is_err());
    assert!(require_checked_scan_worker(0).is_err());
    assert!(require_checked_scan_worker(CHECKED_SCAN_WORKER_VERSION).is_ok());
    let commands = [
        DbCommandRequest::Read { keys: vec![] },
        DbCommandRequest::Put { kvs: vec![] },
        DbCommandRequest::Delete { keys: vec![] },
        DbCommandRequest::Iterator {
            start: IteratorStart::After(vec![10]),
            direction: IteratorDirection::Forward,
            limit: 2,
        },
        DbCommandRequest::IteratorKey {
            start: IteratorStart::After(vec![10]),
            direction: IteratorDirection::Forward,
            limit: 2,
        },
        DbCommandRequest::Batch { operations: vec![] },
        DbCommandRequest::CheckedIterator {
            start: IteratorStart::After(vec![10]),
            direction: IteratorDirection::Forward,
            limit: 2,
        },
        DbCommandRequest::LegacyIterator {
            start: IteratorStart::After(vec![10]),
            direction: IteratorDirection::Forward,
            limit: 2,
        },
    ];
    for (tag, command) in commands.iter().enumerate() {
        let bytes = bincode::serialize(command).unwrap();
        assert_eq!(&bytes[..4], &(tag as u32).to_le_bytes());
        assert!(bincode::deserialize::<DbCommandRequest>(&bytes).is_ok());
    }
}

#[allow(unused)]
#[wasm_bindgen_test]
fn test_command_conversion() {
    assert_eq!(InputCommand::DbRequest as i32, 2);
    assert_eq!(OutputCommand::DbResponse as i32, 2);
    assert!(InputCommand::try_from(20 as i32).is_ok());
    assert!(OutputCommand::try_from(20 as i32).is_ok());
}

#[allow(unused)]
#[wasm_bindgen_test]
fn test_command_write() {
    let arr_buf = SharedArrayBuffer::new(100);
    let i32arr = Int32Array::new(&arr_buf);
    let u8arr = Uint8Array::new(&arr_buf);
    write_command_with_payload(
        InputCommand::DbRequest as i32,
        vec![1, 2, 3, 4],
        &i32arr,
        &u8arr,
    )
    .unwrap();
    assert_eq!(i32arr.get_index(0), InputCommand::DbRequest as i32);
    let mut buf = vec![0u8; 100];
    u8arr.copy_to(&mut buf);
    let result =
        bincode::deserialize::<Vec<i32>>(&buf[8..i32arr.get_index(1) as usize + 8]).unwrap();
    assert_eq!(result, vec![1, 2, 3, 4]);
}

#[allow(unused)]
#[wasm_bindgen_test]
fn test_command_read() {
    let arr_buf = SharedArrayBuffer::new(100);
    let i32arr = Int32Array::new(&arr_buf);
    let u8arr = Uint8Array::new(&arr_buf);
    let buf = bincode::serialize(&vec![1, 2, 3, 4]).unwrap();
    i32arr.set_index(1, buf.len() as i32);
    u8arr.subarray(8, 8 + buf.len() as u32).copy_from(&buf);
    let decoded = read_command_payload::<Vec<i32>>(&i32arr, &u8arr).unwrap();
    assert_eq!(decoded, vec![1, 2, 3, 4]);
}
