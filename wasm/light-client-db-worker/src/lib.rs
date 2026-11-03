use std::cell::RefCell;
use std::str::FromStr;

use db::{handle_db_command, open_database};
use idb::{Database, Transaction};
use light_client_db_common::{read_command_payload, write_command_with_payload, DbCommandRequest};
use light_client_db_common::{InputCommand, OutputCommand};
use log::{debug, info};
use serde::{de::DeserializeOwned, Serialize};
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

#[derive(Clone)]
struct CommandChannel {
    input_i32: Int32Array,
    input_u8: Uint8Array,
    output_i32: Int32Array,
    output_u8: Uint8Array,
}

impl CommandChannel {
    fn read<T: DeserializeOwned>(&self) -> anyhow::Result<T> {
        read_command_payload(&self.input_i32, &self.input_u8)
    }

    fn write<T: Serialize>(&self, cmd: OutputCommand, data: T) -> bool {
        let cmd_id = cmd as i32;
        match write_command_with_payload(cmd_id, data, &self.output_i32, &self.output_u8) {
            Ok(()) => true,
            Err(err) => {
                log::error!("failed to write response {cmd_id}: {err:?}");
                false
            }
        }
    }

    fn reset_input(&self) {
        self.input_i32.set_index(0, InputCommand::Waiting as i32);
    }

    fn wait_sync(&self, holding: InputCommand) -> anyhow::Result<InputCommand> {
        wait_for_command_sync(&self.input_i32, holding)
    }

    async fn wait(&self, holding: InputCommand) -> anyhow::Result<InputCommand> {
        wait_for_command(&self.input_i32, holding).await
    }
}

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
    let Some((input_i32, input_u8)) = input_buffers else {
        log::error!("input shared array buffer is not set");
        return;
    };
    let output_buffers = OUTPUT_BUFFER.with(|x| {
        x.borrow()
            .as_ref()
            .map(|buf| (Int32Array::new(buf), Uint8Array::new(buf)))
    });
    let Some((output_i32, output_u8)) = output_buffers else {
        log::error!("output shared array buffer is not set");
        return;
    };
    let channel = CommandChannel {
        input_i32,
        input_u8,
        output_i32,
        output_u8,
    };

    let mut db: Option<Database> = None;

    loop {
        let cmd = match channel.wait(InputCommand::Waiting).await {
            Ok(cmd) => cmd,
            Err(err) => {
                log::error!("failed to wait for command: {err:?}");
                break;
            }
        };
        // Clean it to avoid infinite loop
        channel.reset_input();
        log::trace!("Received input command: {:?}", cmd);
        match cmd {
            InputCommand::OpenDatabase => {
                let database_name = match channel.read::<String>() {
                    Ok(database_name) => database_name,
                    Err(err) => {
                        log::error!("failed to read open-database payload: {err:?}");
                        channel.write(OutputCommand::Error, format!("{err:?}"));
                        continue;
                    }
                };
                match open_database(&database_name).await {
                    Ok(o) => {
                        db = Some(o);
                        channel.write(OutputCommand::OpenDatabaseResponse, true);
                    }
                    Err(err) => {
                        channel.write(OutputCommand::Error, format!("{err:?}"));
                    }
                }
            }
            InputCommand::DbRequest => {
                let db_cmd = match channel.read() {
                    Ok(db_cmd) => db_cmd,
                    Err(err) => {
                        log::error!("failed to read db-request payload: {err:?}");
                        channel.write(OutputCommand::Error, format!("{err:?}"));
                        continue;
                    }
                };
                let Some(db) = db.as_ref() else {
                    log::error!("database is not opened yet");
                    channel.write(OutputCommand::Error, "database is not opened yet");
                    continue;
                };
                let result = handle_db_command(
                    db,
                    STORE_NAME,
                    db_cmd,
                    |buf| {
                        channel.reset_input();
                        debug!("Invoking request take while with args {:?}", buf);
                        if !channel.write(OutputCommand::RequestTakeWhile, buf) {
                            return false;
                        }
                        // Sync wait here, so transaction of IndexedDB won't be commited (it will be commited once control flow was returned from sync call stack)
                        if let Err(err) = channel.wait_sync(InputCommand::Waiting) {
                            log::error!("failed to wait for take-while response: {err:?}");
                            return false;
                        }
                        let result = match channel.read::<bool>() {
                            Ok(result) => result,
                            Err(err) => {
                                log::error!("failed to read take-while response: {err:?}");
                                false
                            }
                        };
                        debug!("Received take while result {}", result);
                        channel.reset_input();
                        result
                    },
                    |buf, value, store| {
                        let buf = buf.to_vec();
                        let value = value.to_vec();
                        channel.reset_input();
                        log::trace!(
                            "Invoking request filter_map with args key={:?}, value={:?}",
                            buf,
                            value
                        );
                        let write_result =
                            channel.write(OutputCommand::RequestFilterMap, (buf, value));
                        let channel = channel.clone();

                        async move {
                            if !write_result {
                                return None;
                            }
                            let result = loop {
                                let store = store.clone();
                                let input_command =
                                    match channel.wait_sync(InputCommand::Waiting) {
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
                                        let db_cmd: DbCommandRequest = match channel.read() {
                                            Ok(db_cmd) => db_cmd,
                                            Err(err) => {
                                                log::error!(
                                                    "failed to read nested db-request payload: {err:?}"
                                                );
                                                channel.reset_input();
                                                channel.write(
                                                    OutputCommand::Error,
                                                    format!("{err:?}"),
                                                );
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
                                        channel.reset_input();
                                        match db_result {
                                            Ok(o) => {
                                                channel.write(OutputCommand::DbResponse, &o);
                                            }
                                            Err(e) => {
                                                channel.write(
                                                    OutputCommand::Error,
                                                    format!("{:?}", e),
                                                );
                                            }
                                        }
                                    }
                                    InputCommand::ResponseFilterMap => {
                                        let result = match channel.read::<Option<Vec<u8>>>() {
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
                            channel.reset_input();
                            result
                        }
                    },
                    None,
                )
                .await;
                debug!("db command result: {:?}", result);
                match result {
                    Ok(o) => {
                        channel.write(OutputCommand::DbResponse, &o);
                    }
                    Err(e) => {
                        channel.write(OutputCommand::Error, format!("{:?}", e));
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
