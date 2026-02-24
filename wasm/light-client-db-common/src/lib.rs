use anyhow::anyhow;
use anyhow::Context;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use web_sys::js_sys::{Atomics, Int32Array, Uint8Array};

#[cfg(test)]
pub mod tests;

#[derive(Serialize, Deserialize, Debug)]
/// Represent a key-value pair
pub struct KVPair {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Direction for iteration (forward or backward)
#[derive(Serialize, Deserialize, Default, Debug, Clone, Copy, PartialEq, Eq)]
pub enum IteratorDirection {
    #[default]
    Forward,
    Reverse,
}

/// Specifies where to start iteration
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum IteratorStart {
    /// Start from the specified key (inclusive)
    From(Vec<u8>),
    /// Start after the specified key (exclusive, skips the first match)
    After(Vec<u8>),
}

impl IteratorStart {
    /// Get the key bytes
    pub fn key(&self) -> &[u8] {
        match self {
            IteratorStart::From(key) => key,
            IteratorStart::After(key) => key,
        }
    }

    /// Returns true if the first matching entry should be skipped
    pub fn should_skip_first(&self) -> bool {
        matches!(self, IteratorStart::After(_))
    }
}

#[derive(Serialize, Deserialize, Debug)]
/// Response of DbCommandRequest. For details, please refer to the doc of DbCommandRequest
pub enum DbCommandResponse {
    Read { values: Vec<Option<Vec<u8>>> },
    Put,
    Delete,
    Iterator { kvs: Vec<KVPair> },
    IteratorKey { keys: Vec<Vec<u8>> },
}

#[derive(Deserialize, Serialize, Debug)]
/// Represent a database command
pub enum DbCommandRequest {
    /// Read the value corresponding to a series of keys
    /// Input: A series of keys
    /// Output: A series of values corresponding to keys, None if the key wasn't found in database
    Read { keys: Vec<Vec<u8>> },
    /// Write a series of key-value pairs into database
    /// Input: A series of key-value pairs
    /// Output: None
    Put { kvs: Vec<KVPair> },
    /// Remove a series of entries from database
    /// Input: Keys to remove
    /// Output: None
    Delete { keys: Vec<Vec<u8>> },
    /// Gets at most `limit` entries, keep fetching until `take_while` evals to false
    /// Output: Key value pairs fetched
    Iterator {
        start: IteratorStart,
        direction: IteratorDirection,
        limit: usize,
    },
    /// Similar to `Iterator`, but only keys are returned
    IteratorKey {
        start: IteratorStart,
        direction: IteratorDirection,
        limit: usize,
    },
}
#[repr(i32)]
#[derive(Debug)]
/// Represent a 4-byte command which will be put in input buffer
pub enum InputCommand {
    /// Indicates that there is no command and light client is waiting for next call
    /// Payload: None
    Waiting = 0,
    /// Open database,
    /// Payload: database name (string), bincode encoded
    OpenDatabase = 1,
    /// Execute a database command
    /// Payload: DbCommandRequest, bincode encoded
    DbRequest = 2,
    /// Shutdown db worker, exiting main loop
    /// Payload: None
    /// Note: There won't be a response for [`crate::InputCommand::Shutdown`]
    Shutdown = 3,
    /// Used for response from take_while, not for users
    /// Payload: result of the call, in bool, bincode-encoded
    ResponseTakeWhile = 20,
    /// Used for response from filter_map, not for users
    /// Payload: result of the call, in Option<Vec<u8>>, bincode-encoded
    ResponseFilterMap = 21,
}

impl TryFrom<i32> for InputCommand {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Waiting),
            1 => Ok(Self::OpenDatabase),
            2 => Ok(Self::DbRequest),
            3 => Ok(Self::Shutdown),
            20 => Ok(Self::ResponseTakeWhile),
            21 => Ok(Self::ResponseFilterMap),
            s => Err(anyhow!("Invalid command: {}", s)),
        }
    }
}

#[repr(i32)]
#[derive(Debug)]
/// Represent a 4-byte command which will be put in output buffer
pub enum OutputCommand {
    /// Waiting for db worker to handle the command
    /// Payload: None
    Waiting = 0,
    /// Successful response of OpenDatabase
    /// Payload: None
    OpenDatabaseResponse = 1,
    /// Successful response of DbRequest
    /// Payload: bincode-encoded DbCommandResponse
    DbResponse = 2,
    /// Error of OpenDatabaseRequest or DbRequest
    /// Payload: bincode-encoded string
    Error = 10,
    /// DbWorker wants to call take_while
    /// Payload: bincode-encoded bytes, argument of take_while
    RequestTakeWhile = 20,
    /// DbWorker wants to call filter_map
    /// Payload: bincode-encoded bytes, argument of filter_map
    RequestFilterMap = 21,
}

impl TryFrom<i32> for OutputCommand {
    type Error = anyhow::Error;

    fn try_from(value: i32) -> Result<Self, <OutputCommand as TryFrom<i32>>::Error> {
        match value {
            0 => Ok(Self::Waiting),
            1 => Ok(Self::OpenDatabaseResponse),
            2 => Ok(Self::DbResponse),
            10 => Ok(Self::Error),
            20 => Ok(Self::RequestTakeWhile),
            21 => Ok(Self::RequestFilterMap),
            s => Err(anyhow!("Invalid command: {}", s)),
        }
    }
}
/// Convert IteratorDirection to idb::CursorDirection
pub fn iterator_direction_to_idb(dir: IteratorDirection) -> idb::CursorDirection {
    match dir {
        IteratorDirection::Forward => idb::CursorDirection::NextUnique,
        IteratorDirection::Reverse => idb::CursorDirection::PrevUnique,
    }
}
/// Fill a input buffer/output buffer with a [`crate::InputCommand`]/[`crate::OutputCommand`] and the buffer
/// The buffer would be in 4byte command + 4byte payload length + payload
///
/// cmd: Command in i32
/// data: The payload of command
/// i32arr: Int32Array view of the buffer
/// u8arr: Uint8Array view of the buffer
pub fn write_command_with_payload<T: Serialize>(
    cmd: i32,
    data: T,
    i32arr: &Int32Array,
    u8arr: &Uint8Array,
) -> anyhow::Result<()> {
    let result_buf = bincode::serialize(&data)
        .with_context(|| anyhow!("Failed to serialize command payload"))?;

    i32arr.set_index(1, result_buf.len() as i32);
    u8arr
        .subarray(8, 8 + result_buf.len() as u32)
        .copy_from(&result_buf);
    i32arr.set_index(0, cmd);
    Atomics::notify(i32arr, 0).map_err(|e| anyhow!("Failed to notify: {e:?}"))?;
    Ok(())
}

/// Fill a input buffer/output buffer with a [`crate::InputCommand`]/[`crate::OutputCommand`] and the buffer
/// The buffer would be in 4byte command + 4byte payload length + payload. The payload will be encoded in JSON.
///
/// cmd: Command in i32
/// data: The payload of command
/// i32arr: Int32Array view of the buffer
/// u8arr: Uint8Array view of the buffer
pub fn write_command_with_payload_json<T: Serialize>(
    cmd: i32,
    data: T,
    i32arr: &Int32Array,
    u8arr: &Uint8Array,
) -> anyhow::Result<()> {
    let result_buf = serde_json::to_vec(&data)
        .with_context(|| anyhow!("Failed to serialize command payload"))?;

    i32arr.set_index(1, result_buf.len() as i32);
    u8arr
        .subarray(8, 8 + result_buf.len() as u32)
        .copy_from(&result_buf);
    i32arr.set_index(0, cmd);
    Atomics::notify(i32arr, 0).map_err(|e| anyhow!("Failed to notify: {e:?}"))?;
    Ok(())
}

/// Read the payload from the given input buffer/output buffer
/// i32arr: Int32Array view of the buffer
/// u8arr: Uint8Array view of the buffer
pub fn read_command_payload<T: DeserializeOwned>(
    i32arr: &Int32Array,
    u8arr: &Uint8Array,
) -> anyhow::Result<T> {
    let length = i32arr.get_index(1) as u32;
    let mut buf = vec![0u8; length as usize];
    u8arr.subarray(8, 8 + length).copy_to(&mut buf);

    let result =
        bincode::deserialize::<T>(&buf).with_context(|| anyhow!("Failed to decode command"))?;
    Ok(result)
}
