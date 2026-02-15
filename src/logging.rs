use log::LevelFilter;

use crate::error::KidoboError;

pub fn init(level: LevelFilter) -> Result<(), KidoboError> {
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level);
    builder.format_timestamp_secs();
    builder.try_init().map_err(|err| KidoboError::LoggerInit {
        reason: err.to_string(),
    })
}
