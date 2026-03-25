use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SourceLoadError {
    #[error("failed to read source file {path}: {reason}")]
    SourceRead { path: PathBuf, reason: String },

    #[error("failed to read remote cache directory {path}: {reason}")]
    CacheDirRead { path: PathBuf, reason: String },

    #[error("failed to read remote cache directory entry in {path}: {reason}")]
    CacheDirEntryRead { path: PathBuf, reason: String },
}
