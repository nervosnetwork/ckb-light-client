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
    match input.dyn_into::<SharedArrayBuffer>() {
        Ok(buf) => INPUT_BUFFER.with(|v| *v.borrow_mut() = Some(buf)),
        Err(_) => log::error!("input buffer must be a SharedArrayBuffer"),
    }
    match output.dyn_into::<SharedArrayBuffer>() {
        Ok(buf) => OUTPUT_BUFFER.with(|v| *v.borrow_mut() = Some(buf)),
        Err(_) => log::error!("output buffer must be a SharedArrayBuffer"),
    }
}

const STORE_NAME: &str = "main-store";

#[wasm_bindgen]
/// Enter the main loop of db worker. Once entered, db worker will read commands from input buffer (previously set by set_shared_array), handle it, and write response to output buffer.
/// log_level - Level of logs, such as `debug`, `info`.
pub async fn main_loop(log_level: &str) {
    let log_level = match log::Level::from_str(log_level) {
        Ok(log_level) => log_level,
        Err(_) => {
            log::warn!("invalid log level: {log_level}, using info");
            log::Level::Info
        }
    };
    wasm_logger::init(wasm_logger::Config::new(log_level));

    let input_buffers = INPUT_BUFFER.with(|x| {
        x.borrow()
            .as_ref()
            .map(|buf| (Int32Array::new(buf), Uint8Array::new(buf)))
    });
    let Some((input_i32_arr, input_u8_arr)) = input_buffers else {
        log::error!("input shared array buffer is not set");
        return;
    };
    let output_buffers = OUTPUT_BUFFER.with(|x| {
        x.borrow()
            .as_ref()
            .map(|buf| (Int32Array::new(buf), Uint8Array::new(buf)))
    });
    let Some((output_i32_arr, output_u8_arr)) = output_buffers else {
        log::error!("output shared array buffer is not set");
        return;
    };

    let mut db: Option<Database> = None;

    loop {
        let cmd = match wait_for_command(&input_i32_arr, InputCommand::Waiting).await {
            Ok(cmd) => cmd,
            Err(err) => {
                log::error!("failed to wait for command: {err:?}");
                break;
            }
        };
        // Clean it to avoid infinite loop
        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
        log::trace!("Received input command: {:?}", cmd);
        match cmd {
            InputCommand::OpenDatabase => {
                let database_name =
                    match read_command_payload::<String>(&input_i32_arr, &input_u8_arr) {
                        Ok(database_name) => database_name,
                        Err(err) => {
                            log::error!("failed to read open-database payload: {err:?}");
                            if let Err(write_err) = write_command_with_payload(
                                OutputCommand::Error as i32,
                                format!("{err:?}"),
                                &output_i32_arr,
                                &output_u8_arr,
                            ) {
                                log::error!(
                                    "failed to write open-database error response: {write_err:?}"
                                );
                            }
                            continue;
                        }
                    };
                match open_database(&database_name).await {
                    Ok(o) => {
                        db = Some(o);
                        if let Err(err) = write_command_with_payload(
                            OutputCommand::OpenDatabaseResponse as i32,
                            true,
                            &output_i32_arr,
                            &output_u8_arr,
                        ) {
                            log::error!("failed to write open-database response: {err:?}");
                        }
                    }
                    Err(err) => {
                        if let Err(write_err) = write_command_with_payload(
                            OutputCommand::Error as i32,
                            format!("{:?}", err),
                            &output_i32_arr,
                            &output_u8_arr,
                        ) {
                            log::error!(
                                "failed to write open-database error response: {write_err:?}"
                            );
                        }
                    }
                }
            }
            InputCommand::DbRequest => {
                let db_cmd = match read_command_payload(&input_i32_arr, &input_u8_arr) {
                    Ok(db_cmd) => db_cmd,
                    Err(err) => {
                        log::error!("failed to read db-request payload: {err:?}");
                        if let Err(write_err) = write_command_with_payload(
                            OutputCommand::Error as i32,
                            format!("{err:?}"),
                            &output_i32_arr,
                            &output_u8_arr,
                        ) {
                            log::error!("failed to write db-request error response: {write_err:?}");
                        }
                        continue;
                    }
                };
                let Some(db) = db.as_ref() else {
                    log::error!("database is not opened yet");
                    if let Err(err) = write_command_with_payload(
                        OutputCommand::Error as i32,
                        "database is not opened yet",
                        &output_i32_arr,
                        &output_u8_arr,
                    ) {
                        log::error!("failed to write database-not-opened response: {err:?}");
                    }
                    continue;
                };
                let result = handle_db_command(
                    db,
                    STORE_NAME,
                    db_cmd,
                    |buf| {
                        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
                        debug!("Invoking request take while with args {:?}", buf);
                        if let Err(err) = write_command_with_payload(
                            OutputCommand::RequestTakeWhile as i32,
                            buf,
                            &output_i32_arr,
                            &output_u8_arr,
                        ) {
                            log::error!("failed to request take-while: {err:?}");
                            return false;
                        }
                        // Sync wait here, so transaction of IndexedDB won't be commited (it will be commited once control flow was returned from sync call stack)
                        if let Err(err) =
                            wait_for_command_sync(&input_i32_arr, InputCommand::Waiting)
                        {
                            log::error!("failed to wait for take-while response: {err:?}");
                            return false;
                        }
                        let result = match read_command_payload::<bool>(
                            &input_i32_arr,
                            &input_u8_arr,
                        ) {
                            Ok(result) => result,
                            Err(err) => {
                                log::error!("failed to read take-while response: {err:?}");
                                false
                            }
                        };
                        debug!("Received take while result {}", result);
                        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
                        result
                    },
                    |buf, value, store| {
                        let buf = buf.to_vec();
                        let value = value.to_vec();
                        input_i32_arr.set_index(0, InputCommand::Waiting as i32);
                        log::trace!(
                            "Invoking request filter_map with args key={:?}, value={:?}",
                            buf,
                            value
                        );
                        let write_result = write_command_with_payload(
                            OutputCommand::RequestFilterMap as i32,
                            (buf.clone(), value.clone()),
                            &output_i32_arr,
                            &output_u8_arr,
                        );
                        let input_i32_arr = input_i32_arr.clone();
                        let input_u8_arr = input_u8_arr.clone();
                        let output_i32_arr = output_i32_arr.clone();
                        let output_u8_arr = output_u8_arr.clone();

                        async move {
                            if let Err(err) = write_result {
                                log::error!("failed to request filter-map: {err:?}");
                                return None;
                            }
                            let result = loop {
                                let store = store.clone();
                                let input_command = match wait_for_command_sync(
                                    &input_i32_arr,
                                    InputCommand::Waiting,
                                ) {
                                    Ok(input_command) => input_command,
                                    Err(err) => {
                                        log::error!(
                                            "failed to wait for filter-map command: {err:?}"
                                        );
                                        break None;
                                    }
                                };
                                match input_command {
                                    s @ (InputCommand::Waiting
                                    | InputCommand::OpenDatabase
                                    | InputCommand::Shutdown
                                    | InputCommand::ResponseTakeWhile) => {
                                        log::warn!(
                                            "Unexpected branch at light-client-db-worker: {:?}",
                                            s
                                        );
                                        break None;
                                    }
                                    // Allow calling other db requests in filter map call
                                    InputCommand::DbRequest => {
                                        let db_cmd: DbCommandRequest = match read_command_payload(
                                            &input_i32_arr,
                                            &input_u8_arr,
                                        ) {
                                            Ok(db_cmd) => db_cmd,
                                            Err(err) => {
                                                log::error!(
                                                    "failed to read nested db-request payload: {err:?}"
                                                );
                                                input_i32_arr
                                                    .set_index(0, InputCommand::Waiting as i32);
                                                if let Err(write_err) = write_command_with_payload(
                                                    OutputCommand::Error as i32,
                                                    format!("{err:?}"),
                                                    &output_i32_arr,
                                                    &output_u8_arr,
                                                ) {
                                                    log::error!(
                                                        "failed to write nested db-request error response: {write_err:?}"
                                                    );
                                                }
                                                continue;
                                            }
                                        };
                                        debug!(
                                            "Received DbCommandRequest\
                                         when waiting for ResponseTakeWhile: {:?}",
                                            db_cmd
                                        );
                                        let db_result = handle_db_command(
                                            db,
                                            STORE_NAME,
                                            db_cmd,
                                            |_| {
                                                log::error!(
                                                    "take-while is not supported in filter-map"
                                                );
                                                false
                                            },
                                            |_, _, _| async {
                                                log::error!(
                                                    "filter-map is not supported in filter-map"
                                                );
                                                None
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
                                            Ok(o) => {
                                                if let Err(err) = write_command_with_payload(
                                                    OutputCommand::DbResponse as i32,
                                                    &o,
                                                    &output_i32_arr,
                                                    &output_u8_arr,
                                                ) {
                                                    log::error!(
                                                        "failed to write nested db response: {err:?}"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                if let Err(err) = write_command_with_payload(
                                                    OutputCommand::Error as i32,
                                                    format!("{:?}", e),
                                                    &output_i32_arr,
                                                    &output_u8_arr,
                                                ) {
                                                    log::error!(
                                                        "failed to write nested db error response: {err:?}"
                                                    );
                                                }
                                            }
                                        };
                                    }
                                    InputCommand::ResponseFilterMap => {
                                        let result = match read_command_payload::<Option<Vec<u8>>>(
                                            &input_i32_arr,
                                            &input_u8_arr,
                                        ) {
                                            Ok(result) => result,
                                            Err(err) => {
                                                log::error!(
                                                    "failed to read filter-map response: {err:?}"
                                                );
                                                None
                                            }
                                        };
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
                    Ok(o) => {
                        if let Err(err) = write_command_with_payload(
                            OutputCommand::DbResponse as i32,
                            &o,
                            &output_i32_arr,
                            &output_u8_arr,
                        ) {
                            log::error!("failed to write db response: {err:?}");
                        }
                    }
                    Err(e) => {
                        if let Err(err) = write_command_with_payload(
                            OutputCommand::Error as i32,
                            format!("{:?}", e),
                            &output_i32_arr,
                            &output_u8_arr,
                        ) {
                            log::error!("failed to write db error response: {err:?}");
                        }
                    }
                };
            }
            InputCommand::Shutdown => break,
            InputCommand::Waiting => continue,
            InputCommand::ResponseTakeWhile | InputCommand::ResponseFilterMap => {
                log::warn!("unexpected input command from the light client");
            }
        }
    }
    info!("Db worker main loop exited");
}
