use std::{fs, path::Path};

use path_clean::PathClean as _;

use crate::error::{Error, Result};

pub(crate) fn create_directory<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    fs::create_dir_all(path.to_path_buf().clean()).map_err(|err| {
        let errmsg = format!(
            "failed to create directory {} since {}",
            path.display(),
            err
        );
        Error::config(errmsg)
    })
}

pub(crate) fn need_directory<P: AsRef<Path>>(path: P) -> Result<()> {
    let path = path.as_ref();
    if path.exists() {
        if !path.is_dir() {
            let errmsg = format!("the path [{}] exists but not a directory", path.display());
            return Err(Error::config(errmsg));
        }
    } else {
        create_directory(path)?;
    }
    Ok(())
}
