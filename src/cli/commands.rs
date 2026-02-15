use crate::cli::args::Command;
use crate::error::KidoboError;

pub fn dispatch(command: Command) -> Result<(), KidoboError> {
    match command {
        Command::Init => Err(KidoboError::UnimplementedCommand { command: "init" }),
        Command::Doctor => Err(KidoboError::UnimplementedCommand { command: "doctor" }),
        Command::Sync => Err(KidoboError::UnimplementedCommand { command: "sync" }),
        Command::Flush => Err(KidoboError::UnimplementedCommand { command: "flush" }),
        Command::Lookup { .. } => Err(KidoboError::UnimplementedCommand { command: "lookup" }),
    }
}
