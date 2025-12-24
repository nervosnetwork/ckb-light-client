use std::cell::RefCell;
use std::str::FromStr;

use db::{handle_db_command, open_database};
use idb::{Database, Transaction};
use light_client_db_common::{read_command_payload, write_command_with_payload, DbCommandRequest};
use light_client_db_common::{InputCommand, OutputCommand};
use log::{debug, info};
use util::{wait_for_command, wait_for_command_sync};
use wasm_bindgen::{prelude::wasm_bindgen, JsCast, JsValue};
use web_sys::js_sys::{Int32Array, SharedArrayBuffer, Uint8Array};

mod db;
mod util;

thread_local! {
    static INPUT_BUFFER: RefCell<Option<SharedArrayBuffer>> = const { RefCell::new(None) };
    static OUTPUT_BUFFER: RefCell<Option<SharedArrayBuffer>> = const { RefCell::new(None) };
    pub(crate) static GLOBAL_TRANSACTION: RefCell<Option<Transaction>> = const { RefCell::new(None) };
}
#[wasm_bindgen]
/// Set `SharedArrayBuffer` used for communicating with light client worker. This must be called before executing `main_loop`
/// input - The buffer used for sending data from light client worker to db worker
/// output - The buffer used for sending data from db worker to light client worker
pub fn set_shared_array(input: JsValue, output: JsValue) {
    console_error_panic_hook::set_once();
    INPUT_BUFFER.with(|v| {
        *v.borrow_mut() = Some(
            input
                .dyn_into()
                .expect("input buffer must be a SharedArrayBuffer"),
        );
    });
    OUTPUT_BUFFER.with(|v| {
        *v.borrow_mut() = Some(
            output
                .dyn_into()
                .expect("output buffer must be a SharedArrayBuffer"),
        );
    });
}

const STORE_NAME: &str = "main-store";

#[wasm_bindgen]
/// Enter the main loop of db worker. Once entered, db worker will read commands from input buffer (previously set by set_shared_array), handle it, and write response to output buffer.
/// log_level - Level of logs, such as `debug`, `info`.
pub async fn main_loop(log_level: &str) {
    wasm_logger::init(wasm_logger::Config::new(
        log::Level::from_str(log_level).expect("Invalid log level"),
    ));

    let (input_i32_arr, input_u8_arr) = INPUT_BUFFER.with(|x| {
        let binding = x.borrow();
        let buf = binding.as_ref().unwrap();
        (Int32Array::new(buf), Uint8Array::new(buf))
    });
    let (output_i32_arr, output_u8_arr) = OUTPUT_BUFFER.with(|x| {
        let binding = x.borrow();
        let buf = binding.as_ref().unwrap();
        (Int32Array::new(buf), Uint8Array::new(buf))
    });

    let mut db: Option<Database> = None;

    loop {
        let cmd = wait_for_command(&input_i32_arr, InputCommand::Waiting)
            .await
            .expect("Unable to wait for command");
        // Clean it to avoid infinite loop
        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
        log::trace!("Received input command: {:?}", cmd);
        match cmd {
            InputCommand::OpenDatabase => {
                let database_name =
                    read_command_payload::<String>(&input_i32_arr, &input_u8_arr).unwrap();
                match open_database(&database_name).await {
                    Ok(o) => {
                        db = Some(o);
                        write_command_with_payload(
                            OutputCommand::OpenDatabaseResponse as i32,
                            true,
                            &output_i32_arr,
                            &output_u8_arr,
                        )
                        .unwrap();
                    }
                    Err(err) => write_command_with_payload(
                        OutputCommand::Error as i32,
                        format!("{:?}", err),
                        &output_i32_arr,
                        &output_u8_arr,
                    )
                    .unwrap(),
                }
            }
            InputCommand::DbRequest => {
                let db_cmd = read_command_payload(&input_i32_arr, &input_u8_arr).unwrap();
                let db = db.as_ref().expect("Database not opened yet");
                let result = handle_db_command(
                    db,
                    STORE_NAME,
                    db_cmd,
                    |buf| {
                        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
                        debug!("Invoking request take while with args {:?}", buf);
                        write_command_with_payload(
                            OutputCommand::RequestTakeWhile as i32,
                            buf,
                            &output_i32_arr,
                            &output_u8_arr,
                        )
                        .unwrap();
                        // Sync wait here, so transaction of IndexedDB won't be commited (it will be commited once control flow was returned from sync call stack)
                        wait_for_command_sync(&input_i32_arr, InputCommand::Waiting).unwrap();
                        let result =
                            read_command_payload::<bool>(&input_i32_arr, &input_u8_arr).unwrap();
                        debug!("Received take while result {}", result);
                        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
                        result
                    },
                    |buf, store| {
                        let buf = buf.to_vec();
                        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
                        log::trace!("Invoking request filter_map with args {:?}", buf);
                        write_command_with_payload(
                            OutputCommand::RequestFilterMap as i32,
                            buf,
                            &output_i32_arr,
                            &output_u8_arr,
                        )
                        .unwrap();
                        let input_i32_arr = input_i32_arr.clone();
                        let input_u8_arr = input_u8_arr.clone();
                        let output_i32_arr = output_i32_arr.clone();
                        let output_u8_arr = output_u8_arr.clone();

                        async move {
                            let result = loop {
                                let store = store.clone();
                                match wait_for_command_sync(&input_i32_arr, InputCommand::Waiting)
                                    .unwrap()
                                {
                                    InputCommand::Waiting => {},
                                    s @ (InputCommand::OpenDatabase
                                    | InputCommand::Shutdown
                                    | InputCommand::ResponseTakeWhile) => {
                                        log::warn!(
                                            "Unreachable branch at light-client-db-worker: {:?}",
                                            s
                                        );
                                        unreachable!()
                                    }
                                    // Allow calling other db requests in filter map call
                                    InputCommand::DbRequest => {
                                        let db_cmd: DbCommandRequest =
                                            read_command_payload(&input_i32_arr, &input_u8_arr)
                                                .unwrap();
                                        debug!(
                                            "Received DbCommandRequest\
                                         when waiting for ResponseTakeWhile: {:?}",
                                            db_cmd
                                        );
                                        let db_result = handle_db_command(
                                            db,
                                            STORE_NAME,
                                            db_cmd,
                                            |_| panic!("Can't call take while in filter map"),
                                            |_, _| async {
                                                panic!("Can't call filter map in filter map")
                                            },
                                            Some(store),
                                        )
                                        .await;
                                        log::trace!(
                                            "db command result at filter map: {:?}",
                                            db_result
                                        );
                                        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
                                        match db_result {
                                            Ok(o) => write_command_with_payload(
                                                OutputCommand::DbResponse as i32,
                                                &o,
                                                &output_i32_arr,
                                                &output_u8_arr,
                                            )
                                            .unwrap(),
                                            Err(e) => write_command_with_payload(
                                                OutputCommand::Error as i32,
                                                format!("{:?}", e),
                                                &output_i32_arr,
                                                &output_u8_arr,
                                            )
                                            .unwrap(),
                                        };
                                    }
                                    InputCommand::ResponseFilterMap => {
                                        let result = read_command_payload::<Option<Vec<u8>>>(
                                            &input_i32_arr,
                                            &input_u8_arr,
                                        )
                                        .unwrap();
                                        log::trace!("Received filter map result {:?}", result);

                                        break result;
                                    }
                                }
                            };
                            input_i32_arr.set_index(0, InputCommand::Waiting as i32);
                            result
                        }
                    },
                    None,
                )
                .await;
                debug!("db command result: {:?}", result);
                match result {
                    Ok(o) => write_command_with_payload(
                        OutputCommand::DbResponse as i32,
                        &o,
                        &output_i32_arr,
                        &output_u8_arr,
                    )
                    .unwrap(),
                    Err(e) => write_command_with_payload(
                        OutputCommand::Error as i32,
                        format!("{:?}", e),
                        &output_i32_arr,
                        &output_u8_arr,
                    )
                    .unwrap(),
                };
            }
            InputCommand::Shutdown => break,
            InputCommand::Waiting => continue,
            InputCommand::ResponseTakeWhile | InputCommand::ResponseFilterMap => unreachable!(),
        }
    }
    info!("Db worker main loop exited");
}
