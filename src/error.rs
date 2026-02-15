use std::path::PathBuf;

use crate::adapters::lock::LockError;
use crate::adapters::lookup_sources::LookupSourceLoadError;
use crate::adapters::path::PathResolutionError;
use crate::core::config::ConfigError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum KidoboError {
    #[error("command `{command}` is not implemented yet")]
    UnimplementedCommand { command: &'static str },

    #[error("failed to initialize logger: {reason}")]
    LoggerInit { reason: String },

    #[error("failed to install SIGINT handler: {reason}")]
    SignalHandlerInstall { reason: String },

    #[error("operation interrupted by SIGINT")]
    Interrupted,

    #[error("path resolution failed: {source}")]
    PathResolution {
        #[from]
        source: PathResolutionError,
    },

    #[error("config file does not exist: {path}")]
    MissingConfigFile { path: PathBuf },

    #[error("failed to read config file {path}: {reason}")]
    ConfigRead { path: PathBuf, reason: String },

    #[error("config parse/validation failed: {source}")]
    ConfigParse {
        #[from]
        source: ConfigError,
    },

    #[error("failed to read lookup targets file {path}: {reason}")]
    LookupTargetFileRead { path: PathBuf, reason: String },

    #[error("lookup failed for {count} invalid target(s)")]
    LookupInvalidTargets { count: usize },

    #[error("lookup source loading failed: {source}")]
    LookupSourceLoad {
        #[from]
        source: LookupSourceLoadError,
    },

    #[error("lock operation failed: {source}")]
    Lock {
        #[from]
        source: LockError,
    },
}

impl KidoboError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Interrupted => 130,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::KidoboError;

    #[test]
    fn interrupted_maps_to_130() {
        assert_eq!(KidoboError::Interrupted.exit_code(), 130);
    }

    #[test]
    fn non_interrupted_maps_to_1() {
        let err = KidoboError::UnimplementedCommand { command: "sync" };
        assert_eq!(err.exit_code(), 1);
    }
}
