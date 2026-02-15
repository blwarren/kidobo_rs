use std::path::PathBuf;

use crate::adapters::path::PathResolutionError;
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
}

impl KidoboError {
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Interrupted => 130,
            _ => 1,
        }
    }
}
