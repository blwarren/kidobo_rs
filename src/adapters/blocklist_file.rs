use std::fs;
use std::path::Path;
use std::time::UNIX_EPOCH;

use log::warn;

use crate::adapters::limited_io::{read_to_string_with_limit, write_string_atomic};
use crate::core::blocklist::InvalidBlocklistLine;
pub use crate::core::blocklist::canonicalize_blocklist;
use crate::core::network::{CanonicalCidr, parse_ip_cidr_strict};
use crate::error::KidoboError;

pub const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;
const BLOCKLIST_FAST_STATE_VERSION: &str = "v1";
const BLOCKLIST_FAST_STATE_READ_LIMIT: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlocklistNormalizeResult {
    MissingBlocklist,
    SkippedUnchanged,
    Checked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BlocklistFastState {
    byte_len: u64,
    modified_nanos: u128,
}

impl BlocklistFastState {
    fn capture(path: &Path) -> Option<Self> {
        let metadata = fs::metadata(path).ok()?;
        let modified = metadata.modified().ok()?;
        let since_epoch = modified.duration_since(UNIX_EPOCH).ok()?;

        Some(Self {
            byte_len: metadata.len(),
            modified_nanos: since_epoch.as_nanos(),
        })
    }

    fn parse(contents: &str) -> Option<Self> {
        let mut parts = contents.split_whitespace();
        let version = parts.next()?;
        if version != BLOCKLIST_FAST_STATE_VERSION {
            return None;
        }

        let byte_len = parts.next()?.parse::<u64>().ok()?;
        let modified_nanos = parts.next()?.parse::<u128>().ok()?;
        if parts.next().is_some() {
            return None;
        }

        Some(Self {
            byte_len,
            modified_nanos,
        })
    }

    fn serialize(self) -> String {
        format!(
            "{} {} {}\n",
            BLOCKLIST_FAST_STATE_VERSION, self.byte_len, self.modified_nanos
        )
    }
}

pub fn write_blocklist_lines<S: AsRef<str>>(path: &Path, lines: &[S]) -> Result<(), KidoboError> {
    let mut contents = lines
        .iter()
        .map(AsRef::as_ref)
        .collect::<Vec<_>>()
        .join("\n");
    if !contents.is_empty() {
        contents.push('\n');
    }

    write_string_atomic(path, &contents).map_err(|err| KidoboError::BlocklistWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

pub fn ensure_blocklist_parent(path: &Path) -> Result<(), KidoboError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| KidoboError::BlocklistWrite {
            path: parent.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    Ok(())
}

pub fn normalize_local_blocklist(path: &Path) -> Result<(), KidoboError> {
    if !path.exists() {
        return Ok(());
    }

    let original = read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
        KidoboError::BlocklistRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    let normalized =
        canonicalize_blocklist(&original).map_err(|err| map_invalid_blocklist_line(path, err))?;

    if normalized != original {
        write_string_atomic(path, &normalized).map_err(|err| KidoboError::BlocklistWrite {
            path: path.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    Ok(())
}

pub fn normalize_local_blocklist_with_fast_state(
    blocklist_path: &Path,
    fast_state_path: &Path,
) -> Result<BlocklistNormalizeResult, KidoboError> {
    if !blocklist_path.exists() {
        return Ok(BlocklistNormalizeResult::MissingBlocklist);
    }

    let current_state = BlocklistFastState::capture(blocklist_path);
    let cached_state = read_blocklist_fast_state(fast_state_path);
    if current_state
        .zip(cached_state)
        .is_some_and(|(current, cached)| current == cached)
    {
        return Ok(BlocklistNormalizeResult::SkippedUnchanged);
    }

    normalize_local_blocklist(blocklist_path)?;

    if let Some(final_state) = BlocklistFastState::capture(blocklist_path)
        && let Err(err) = write_blocklist_fast_state(fast_state_path, final_state)
    {
        warn!(
            "best-effort blocklist fast-state write failed for {} ({err})",
            fast_state_path.display()
        );
    }

    Ok(BlocklistNormalizeResult::Checked)
}

fn read_blocklist_fast_state(path: &Path) -> Option<BlocklistFastState> {
    let contents = read_to_string_with_limit(path, BLOCKLIST_FAST_STATE_READ_LIMIT).ok()?;
    BlocklistFastState::parse(&contents)
}

fn write_blocklist_fast_state(
    path: &Path,
    state: BlocklistFastState,
) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    write_string_atomic(path, &state.serialize())
}

#[derive(Debug)]
pub struct BlocklistFile {
    pub lines: Vec<BlocklistLine>,
    pub has_content: bool,
    pub trailing_newline: bool,
}

impl BlocklistFile {
    pub fn load(path: &Path) -> Result<Self, KidoboError> {
        if !path.exists() {
            return Ok(Self {
                lines: Vec::new(),
                has_content: false,
                trailing_newline: false,
            });
        }

        let contents = read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
            KidoboError::BlocklistRead {
                path: path.to_path_buf(),
                reason: err.to_string(),
            }
        })?;

        let mut lines = Vec::new();
        let mut in_header = true;
        for (idx, line) in contents.lines().enumerate() {
            lines.push(
                BlocklistLine::new(line, idx + 1, &mut in_header)
                    .map_err(|err| map_invalid_blocklist_line(path, err))?,
            );
        }

        Ok(Self {
            lines,
            has_content: !contents.is_empty(),
            trailing_newline: contents.ends_with('\n'),
        })
    }

    #[cfg(test)]
    pub fn contains_canonical(&self, canonical: CanonicalCidr) -> bool {
        self.lines
            .iter()
            .any(|line| line.canonical == Some(canonical))
    }
}

#[derive(Debug)]
pub struct BlocklistLine {
    pub original: String,
    pub canonical: Option<CanonicalCidr>,
}

impl BlocklistLine {
    fn new(
        line: &str,
        line_number: usize,
        in_header: &mut bool,
    ) -> Result<Self, InvalidBlocklistLine> {
        let trimmed = line.trim();
        let canonical = if *in_header {
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                *in_header = false;
                parse_local_blocklist_entry(line, line_number)?
            }
        } else {
            parse_local_blocklist_entry(line, line_number)?
        };

        Ok(Self {
            original: line.to_string(),
            canonical,
        })
    }
}

fn parse_local_blocklist_entry(
    line: &str,
    line_number: usize,
) -> Result<Option<CanonicalCidr>, InvalidBlocklistLine> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return Ok(None);
    }

    parse_ip_cidr_strict(trimmed)
        .map(Some)
        .ok_or_else(|| InvalidBlocklistLine {
            line_number,
            content: line.to_string(),
        })
}

fn map_invalid_blocklist_line(path: &Path, err: InvalidBlocklistLine) -> KidoboError {
    KidoboError::BlocklistParseLine {
        path: path.to_path_buf(),
        line: err.line_number,
        content: err.content,
    }
}
