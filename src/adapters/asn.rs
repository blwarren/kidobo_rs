use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use thiserror::Error;

use crate::adapters::command_runner::{
    CommandExecutor, CommandRequest, ProcessStatus, SystemCommandExecutor,
};
use crate::core::network::{CanonicalCidr, parse_ip_cidr_token};

const ASN_CACHE_FILE_READ_LIMIT: usize = 8 * 1024 * 1024;
const ASN_CACHE_FILE_WRITE_HEADER: &str = "# kidobo-asn-cache-v1";
const DEFAULT_BGPQ4_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum AsnError {
    #[error("invalid ASN token `{input}`")]
    InvalidAsnToken { input: String },

    #[error("failed to resolve ASN {asn} prefixes via bgpq4: {reason}")]
    ResolveFailed { asn: u32, reason: String },

    #[error("ASN cache read failed at {path}: {reason}")]
    CacheRead { path: PathBuf, reason: String },

    #[error("ASN cache write failed at {path}: {reason}")]
    CacheWrite { path: PathBuf, reason: String },
}

pub trait AsnPrefixResolver {
    fn resolve_prefixes(&self, asn: u32) -> Result<Vec<CanonicalCidr>, AsnError>;
}

#[derive(Debug, Clone, Copy)]
pub struct Bgpq4AsnPrefixResolver<E: CommandExecutor> {
    executor: E,
    timeout: Duration,
}

impl Bgpq4AsnPrefixResolver<SystemCommandExecutor> {
    pub fn with_default_timeout() -> Self {
        Self {
            executor: SystemCommandExecutor,
            timeout: DEFAULT_BGPQ4_TIMEOUT,
        }
    }
}

impl<E: CommandExecutor> Bgpq4AsnPrefixResolver<E> {
    pub fn new(executor: E, timeout: Duration) -> Self {
        Self { executor, timeout }
    }

    fn run_bgpq4(&self, asn: u32, family_flag: &str) -> Result<Vec<CanonicalCidr>, AsnError> {
        let asn_token = format!("AS{asn}");
        let request = CommandRequest {
            program: "bgpq4".to_string(),
            args: vec![
                family_flag.to_string(),
                "-F".to_string(),
                "%n/%l\n".to_string(),
                asn_token,
            ],
            timeout: self.timeout,
        };

        let command = format!("{} {}", request.program, request.args.join(" "));
        let result = self
            .executor
            .execute(&request)
            .map_err(|err| AsnError::ResolveFailed {
                asn,
                reason: err.to_string(),
            })?;

        if result.status != ProcessStatus::Exited(0) {
            let stderr = result.stderr.trim();
            return Err(AsnError::ResolveFailed {
                asn,
                reason: if stderr.is_empty() {
                    format!("{command} exited with {:?}", result.status)
                } else {
                    format!("{command} failed: {stderr}")
                },
            });
        }

        Ok(parse_cidrs_from_bgpq4_output(&result.stdout))
    }
}

impl<E: CommandExecutor> AsnPrefixResolver for Bgpq4AsnPrefixResolver<E> {
    fn resolve_prefixes(&self, asn: u32) -> Result<Vec<CanonicalCidr>, AsnError> {
        let mut prefixes = self.run_bgpq4(asn, "-4")?;
        prefixes.extend(self.run_bgpq4(asn, "-6")?);
        prefixes.sort_unstable();
        prefixes.dedup();
        Ok(prefixes)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedAsnPrefixes {
    pub prefixes: Vec<CanonicalCidr>,
    pub stale: bool,
}

pub fn normalize_asn_tokens<I, S>(tokens: I) -> Result<Vec<u32>, AsnError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut normalized = Vec::new();
    for token in tokens {
        normalized.push(parse_asn_token(token.as_ref())?);
    }
    normalized.sort_unstable();
    normalized.dedup();
    Ok(normalized)
}

pub fn parse_asn_token(input: &str) -> Result<u32, AsnError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(AsnError::InvalidAsnToken {
            input: input.to_string(),
        });
    }

    let normalized = trimmed
        .strip_prefix("AS")
        .or_else(|| trimmed.strip_prefix("as"))
        .unwrap_or(trimmed);

    let asn = normalized
        .parse::<u32>()
        .ok()
        .filter(|value| *value > 0)
        .ok_or_else(|| AsnError::InvalidAsnToken {
            input: input.to_string(),
        })?;

    Ok(asn)
}

pub fn load_asn_prefixes_with_cache(
    asn: u32,
    cache_dir: &Path,
    stale_after: Duration,
    resolver: &dyn AsnPrefixResolver,
) -> Result<CachedAsnPrefixes, AsnError> {
    let cache_file = asn_cache_file(cache_dir, asn);
    let cache_state = read_asn_cache_file(&cache_file)?;

    if cache_state
        .as_ref()
        .is_some_and(|state| !state_is_stale(state.modified, stale_after))
    {
        return Ok(CachedAsnPrefixes {
            prefixes: cache_state.map_or_else(Vec::new, |state| state.prefixes),
            stale: false,
        });
    }

    match resolver.resolve_prefixes(asn) {
        Ok(prefixes) => {
            write_asn_cache_file(&cache_file, &prefixes)?;
            Ok(CachedAsnPrefixes {
                prefixes,
                stale: false,
            })
        }
        Err(err) => {
            if let Some(stale) = cache_state {
                Ok(CachedAsnPrefixes {
                    prefixes: stale.prefixes,
                    stale: true,
                })
            } else {
                Err(err)
            }
        }
    }
}

pub fn delete_asn_cache_file(asn: u32, cache_dir: &Path) -> Result<bool, AsnError> {
    let path = asn_cache_file(cache_dir, asn);
    if !path.exists() {
        return Ok(false);
    }

    fs::remove_file(&path).map_err(|err| AsnError::CacheWrite {
        path: path.clone(),
        reason: err.to_string(),
    })?;
    Ok(true)
}

#[derive(Debug)]
struct AsnCacheState {
    modified: SystemTime,
    prefixes: Vec<CanonicalCidr>,
}

fn asn_cache_file(cache_dir: &Path, asn: u32) -> PathBuf {
    cache_dir.join(format!("as{asn}.iplist"))
}

fn state_is_stale(modified: SystemTime, stale_after: Duration) -> bool {
    SystemTime::now()
        .duration_since(modified)
        .map_or(true, |age| age >= stale_after)
}

fn read_asn_cache_file(path: &Path) -> Result<Option<AsnCacheState>, AsnError> {
    if !path.exists() {
        return Ok(None);
    }

    let metadata = fs::metadata(path).map_err(|err| AsnError::CacheRead {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;
    let modified = metadata.modified().map_err(|err| AsnError::CacheRead {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })?;
    let contents =
        crate::adapters::limited_io::read_to_string_with_limit(path, ASN_CACHE_FILE_READ_LIMIT)
            .map_err(|err| AsnError::CacheRead {
                path: path.to_path_buf(),
                reason: err.to_string(),
            })?;

    let mut prefixes = parse_cidrs_from_bgpq4_output(&contents);
    prefixes.sort_unstable();
    prefixes.dedup();

    Ok(Some(AsnCacheState { modified, prefixes }))
}

fn write_asn_cache_file(path: &Path, prefixes: &[CanonicalCidr]) -> Result<(), AsnError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| AsnError::CacheWrite {
            path: parent.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    let mut output = String::new();
    output.push_str(ASN_CACHE_FILE_WRITE_HEADER);
    output.push('\n');
    for prefix in prefixes {
        output.push_str(&prefix.to_string());
        output.push('\n');
    }

    fs::write(path, output).map_err(|err| AsnError::CacheWrite {
        path: path.to_path_buf(),
        reason: err.to_string(),
    })
}

fn parse_cidrs_from_bgpq4_output(contents: &str) -> Vec<CanonicalCidr> {
    contents
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                None
            } else {
                parse_ip_cidr_token(trimmed)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::fs;
    use std::time::Duration;

    use tempfile::TempDir;

    use super::{
        AsnError, AsnPrefixResolver, CachedAsnPrefixes, delete_asn_cache_file,
        load_asn_prefixes_with_cache, normalize_asn_tokens, parse_asn_token,
    };
    use crate::core::network::{CanonicalCidr, Ipv4Cidr};

    struct MockResolver {
        responses: VecDeque<Result<Vec<CanonicalCidr>, AsnError>>,
    }

    impl MockResolver {
        fn new(responses: Vec<Result<Vec<CanonicalCidr>, AsnError>>) -> Self {
            Self {
                responses: VecDeque::from(responses),
            }
        }
    }

    impl AsnPrefixResolver for std::sync::Mutex<MockResolver> {
        fn resolve_prefixes(&self, _asn: u32) -> Result<Vec<CanonicalCidr>, AsnError> {
            self.lock()
                .expect("lock")
                .responses
                .pop_front()
                .expect("response")
        }
    }

    #[test]
    fn parse_asn_token_accepts_bare_and_as_prefixed() {
        assert_eq!(parse_asn_token("213412").expect("parse"), 213412);
        assert_eq!(parse_asn_token("AS213412").expect("parse"), 213412);
        assert_eq!(parse_asn_token("as213412").expect("parse"), 213412);
    }

    #[test]
    fn normalize_asn_tokens_dedupes_and_sorts() {
        let values = normalize_asn_tokens(["AS64513", "64512", "64513"]).expect("normalize");
        assert_eq!(values, vec![64512, 64513]);
    }

    #[test]
    fn parse_asn_token_rejects_invalid_values() {
        let err = parse_asn_token("AS0").expect_err("must fail");
        assert!(matches!(err, AsnError::InvalidAsnToken { .. }));
    }

    #[test]
    fn cache_load_uses_fresh_cache_without_resolve() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        fs::write(cache_dir.join("as64512.iplist"), "203.0.113.0/24\n").expect("write");
        let resolver = std::sync::Mutex::new(MockResolver::new(vec![]));

        let loaded = load_asn_prefixes_with_cache(
            64512,
            cache_dir,
            Duration::from_secs(24 * 60 * 60),
            &resolver,
        )
        .expect("load");

        assert_eq!(
            loaded,
            CachedAsnPrefixes {
                prefixes: vec![CanonicalCidr::V4(Ipv4Cidr::from_parts(0xcb007100, 24))],
                stale: false
            }
        );
    }

    #[test]
    fn cache_load_falls_back_to_stale_when_refresh_fails() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        fs::write(cache_dir.join("as64512.iplist"), "203.0.113.0/24\n").expect("write");
        let resolver =
            std::sync::Mutex::new(MockResolver::new(vec![Err(AsnError::ResolveFailed {
                asn: 64512,
                reason: "boom".to_string(),
            })]));

        let loaded =
            load_asn_prefixes_with_cache(64512, cache_dir, Duration::from_secs(0), &resolver)
                .expect("load");
        assert!(loaded.stale);
        assert_eq!(loaded.prefixes.len(), 1);
    }

    #[test]
    fn cache_file_delete_is_best_effort_for_missing_files() {
        let temp = TempDir::new().expect("tempdir");
        assert!(!delete_asn_cache_file(64512, temp.path()).expect("delete"));
        fs::write(temp.path().join("as64512.iplist"), "203.0.113.0/24\n").expect("write");
        assert!(delete_asn_cache_file(64512, temp.path()).expect("delete"));
    }
}
