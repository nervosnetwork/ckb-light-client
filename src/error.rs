use std::{fmt, result};

use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("config error: {0}")]
    Config(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("runtime error: {0}")]
    Runtime(String),

    #[error("db error: {0}")]
    Db(#[from] rocksdb::Error),
}

pub type Result<T> = result::Result<T, Error>;

impl Error {
    pub(crate) fn config<T: fmt::Display>(inner: T) -> Self {
        Self::Config(inner.to_string())
    }
    pub(crate) fn argument_should_exist(name: &str) -> Self {
        Self::Config(format!("argument {} should exist", name))
    }
    pub(crate) fn storage<T: fmt::Display>(inner: T) -> Self {
        Self::Storage(inner.to_string())
    }
    pub(crate) fn runtime<T: fmt::Display>(inner: T) -> Self {
        Self::Runtime(inner.to_string())
    }
}
