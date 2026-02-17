#![forbid(unsafe_code)]
#![deny(dead_code)]
#![deny(clippy::all)]
#![warn(clippy::pedantic)]
#![allow(
    clippy::match_same_arms,
    clippy::must_use_candidate,
    clippy::needless_raw_string_hashes,
    clippy::missing_errors_doc,
    clippy::single_match_else,
    clippy::struct_field_names,
    clippy::unreadable_literal
)]
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
        clippy::print_stderr,
        clippy::panic_in_result_fn,
        clippy::needless_pass_by_value,
        clippy::trivially_copy_pass_by_ref,
        clippy::format_push_string,
        clippy::uninlined_format_args,
        clippy::inefficient_to_string,
        clippy::to_string_in_format_args,
        clippy::implicit_clone
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
