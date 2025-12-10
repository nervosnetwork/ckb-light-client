use std::process::Command;
use vergen_gitcl::{Emitter, GitclBuilder};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let gitcl = GitclBuilder::default()
        .sha(true)
        .dirty(true)
        .build()?;

    Emitter::default()
        .add_instructions(&gitcl)?
        .emit()?;

    // Check if git working directory is dirty and create a suffix
    let is_dirty = Command::new("git")
        .args(["diff-index", "--quiet", "HEAD", "--"])
        .status()
        .map(|status| !status.success())
        .unwrap_or(false);

    let dirty_suffix = if is_dirty { "-dirty" } else { "" };
    println!("cargo:rustc-env=GIT_DIRTY_SUFFIX={}", dirty_suffix);

    // Generate build timestamp without nanoseconds
    let timestamp = if let Ok(epoch) = std::env::var("SOURCE_DATE_EPOCH") {
        if let Ok(seconds) = epoch.parse::<i64>() {
            chrono::DateTime::from_timestamp(seconds, 0)
                .map(|dt| dt.format("%Y-%m-%dT%H:%M:%SZ").to_string())
                .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string())
        } else {
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
        }
    } else {
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
    };
    println!("cargo:rustc-env=VERGEN_BUILD_TIMESTAMP={}", timestamp);

    Ok(())
}
