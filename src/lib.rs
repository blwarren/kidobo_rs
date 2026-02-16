#![forbid(unsafe_code)]
#![deny(clippy::disallowed_methods)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::todo,
        clippy::unimplemented,
        clippy::dbg_macro,
        clippy::suspicious_command_arg_space,
        clippy::indexing_slicing,
        clippy::print_stdout,
        clippy::print_stderr
    )
)]

pub mod adapters;
pub mod cli;
pub mod core;
pub mod error;
pub mod logging;

use std::process::ExitCode;

pub fn run() -> ExitCode {
    cli::run()
}
