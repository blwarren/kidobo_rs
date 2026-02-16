#![forbid(unsafe_code)]
#![deny(clippy::disallowed_methods)]

pub mod adapters;
pub mod cli;
pub mod core;
pub mod error;
pub mod logging;

use std::process::ExitCode;

pub fn run() -> ExitCode {
    cli::run()
}
