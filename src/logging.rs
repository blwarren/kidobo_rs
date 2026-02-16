use std::io::Write;

use env_logger::WriteStyle;
use log::LevelFilter;

use crate::error::KidoboError;

pub fn init(level: LevelFilter) -> Result<(), KidoboError> {
    let mut builder = env_logger::Builder::new();
    builder.filter_level(level);
    builder.write_style(WriteStyle::Never);
    builder.format(|buf, record| writeln!(buf, "level={} msg={}", record.level(), record.args()));
    builder.try_init().map_err(|err| KidoboError::LoggerInit {
        reason: err.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use log::LevelFilter;

    use super::init;
    use crate::error::KidoboError;

    #[test]
    fn repeated_init_reports_logger_init_error() {
        let _ = init(LevelFilter::Off);

        let err = init(LevelFilter::Off).expect_err("second init must fail");
        match err {
            KidoboError::LoggerInit { reason } => assert!(!reason.is_empty()),
            _ => panic!("expected logger init error"),
        }
    }
}
