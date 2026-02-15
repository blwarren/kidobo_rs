use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use log::warn;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::core::network::{CanonicalCidr, parse_ip_cidr_non_strict};

pub const DEFAULT_MAX_HTTP_BODY_BYTES: usize = 32 * 1024 * 1024;
pub const ENV_KIDOBO_MAX_HTTP_BODY_BYTES: &str = "KIDOBO_MAX_HTTP_BODY_BYTES";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachePaths {
    pub iplist_path: PathBuf,
    pub meta_path: PathBuf,
    pub raw_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteCacheMetadata {
    pub url: String,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub sha256_raw: String,
    pub sha256_iplist: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheSource {
    Network,
    CacheNotModified,
    FallbackCache,
    Empty,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedIplist {
    pub iplist: String,
    pub source: CacheSource,
    pub metadata: Option<RemoteCacheMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub url: String,
    pub if_none_match: Option<String>,
    pub if_modified_since: Option<String>,
    pub max_body_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HttpClientError {
    #[error("http client request failed: {reason}")]
    Request { reason: String },
}

pub trait HttpClient {
    fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError>;
}

#[derive(Debug, Error)]
pub enum HttpCacheError {
    #[error("failed to create cache directory {path}: {reason}")]
    CreateCacheDir { path: PathBuf, reason: String },

    #[error("failed to write iplist cache {path}: {reason}")]
    WriteIplist { path: PathBuf, reason: String },

    #[error("failed to write metadata cache {path}: {reason}")]
    WriteMetadata { path: PathBuf, reason: String },

    #[error("failed to write raw cache {path}: {reason}")]
    WriteRaw { path: PathBuf, reason: String },

    #[error("failed to read iplist cache {path}: {reason}")]
    ReadIplist { path: PathBuf, reason: String },

    #[error("failed to read metadata cache {path}: {reason}")]
    ReadMetadata { path: PathBuf, reason: String },

    #[error("failed to parse metadata cache {path}: {reason}")]
    ParseMetadata { path: PathBuf, reason: String },
}

pub fn url_hash_prefix(url: &str) -> String {
    let digest = Sha256::digest(url.as_bytes());
    hex_lower(&digest)[..16].to_string()
}

pub fn cache_paths_for_url(cache_dir: &Path, url: &str) -> CachePaths {
    let hash = url_hash_prefix(url);
    CachePaths {
        iplist_path: cache_dir.join(format!("{hash}.iplist")),
        meta_path: cache_dir.join(format!("{hash}.meta.json")),
        raw_path: cache_dir.join(format!("{hash}.raw")),
    }
}

pub fn max_http_body_bytes(env: &BTreeMap<String, String>) -> usize {
    env.get(ENV_KIDOBO_MAX_HTTP_BODY_BYTES)
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_MAX_HTTP_BODY_BYTES)
}

pub fn normalize_remote_text(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut normalized = Vec::new();

    for line in text.lines() {
        let without_bom = line.trim_start_matches('\u{feff}').trim();
        if without_bom.is_empty() || without_bom.starts_with('#') {
            continue;
        }

        let token = match without_bom.split_whitespace().next() {
            Some(token) => token,
            None => continue,
        };

        if let Some(cidr) = parse_ip_cidr_non_strict(token) {
            normalized.push(canonical_to_string(cidr));
        }
    }

    normalized.join("\n")
}

pub fn fetch_iplist_with_cache(
    client: &dyn HttpClient,
    url: &str,
    cache_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Result<CachedIplist, HttpCacheError> {
    let max_bytes = max_http_body_bytes(env);
    let cache_paths = cache_paths_for_url(cache_dir, url);

    let cached_iplist = read_optional_iplist(&cache_paths)?;
    let cached_meta = read_optional_metadata(&cache_paths)?;

    let conditional_request = HttpRequest {
        url: url.to_string(),
        if_none_match: cached_meta.as_ref().and_then(|meta| meta.etag.clone()),
        if_modified_since: cached_meta
            .as_ref()
            .and_then(|meta| meta.last_modified.clone()),
        max_body_bytes: max_bytes,
    };

    let response = match client.fetch(conditional_request) {
        Ok(response) => response,
        Err(err) => {
            warn!("remote fetch failed for {url}: {err}");
            return Ok(cache_fallback(cached_iplist, cached_meta));
        }
    };

    if response.status == 304 {
        if let Some(iplist) = cached_iplist {
            return Ok(CachedIplist {
                iplist,
                source: CacheSource::CacheNotModified,
                metadata: cached_meta,
            });
        }

        let unconditional = HttpRequest {
            url: url.to_string(),
            if_none_match: None,
            if_modified_since: None,
            max_body_bytes: max_bytes,
        };

        let response = match client.fetch(unconditional) {
            Ok(response) => response,
            Err(err) => {
                warn!("remote refetch failed for {url} after 304 without cache: {err}");
                return Ok(CachedIplist {
                    iplist: String::new(),
                    source: CacheSource::Empty,
                    metadata: None,
                });
            }
        };

        return handle_network_response(response, url, &cache_paths, max_bytes, None, None);
    }

    handle_network_response(
        response,
        url,
        &cache_paths,
        max_bytes,
        cached_iplist,
        cached_meta,
    )
}

fn handle_network_response(
    response: HttpResponse,
    url: &str,
    cache_paths: &CachePaths,
    max_bytes: usize,
    cached_iplist: Option<String>,
    cached_meta: Option<RemoteCacheMetadata>,
) -> Result<CachedIplist, HttpCacheError> {
    if !(200..300).contains(&response.status) {
        warn!(
            "remote fetch failed for {url}: unexpected status {}",
            response.status
        );
        return Ok(cache_fallback(cached_iplist, cached_meta));
    }

    if response.body.len() > max_bytes {
        warn!(
            "remote fetch failed for {url}: body size {} exceeds max {} bytes",
            response.body.len(),
            max_bytes
        );
        return Ok(cache_fallback(cached_iplist, cached_meta));
    }

    let normalized = normalize_remote_text(&response.body);
    let metadata = RemoteCacheMetadata {
        url: url.to_string(),
        etag: response.etag,
        last_modified: response.last_modified,
        sha256_raw: sha256_hex(&response.body),
        sha256_iplist: sha256_hex(normalized.as_bytes()),
    };

    persist_cache(cache_paths, &normalized, &response.body, &metadata)?;

    Ok(CachedIplist {
        iplist: normalized,
        source: CacheSource::Network,
        metadata: Some(metadata),
    })
}

fn persist_cache(
    paths: &CachePaths,
    iplist: &str,
    raw: &[u8],
    meta: &RemoteCacheMetadata,
) -> Result<(), HttpCacheError> {
    if let Some(parent) = paths.iplist_path.parent() {
        fs::create_dir_all(parent).map_err(|err| HttpCacheError::CreateCacheDir {
            path: parent.to_path_buf(),
            reason: err.to_string(),
        })?;
    }

    fs::write(&paths.iplist_path, iplist).map_err(|err| HttpCacheError::WriteIplist {
        path: paths.iplist_path.clone(),
        reason: err.to_string(),
    })?;

    let meta_json =
        serde_json::to_vec_pretty(meta).map_err(|err| HttpCacheError::WriteMetadata {
            path: paths.meta_path.clone(),
            reason: err.to_string(),
        })?;

    fs::write(&paths.meta_path, meta_json).map_err(|err| HttpCacheError::WriteMetadata {
        path: paths.meta_path.clone(),
        reason: err.to_string(),
    })?;

    fs::write(&paths.raw_path, raw).map_err(|err| HttpCacheError::WriteRaw {
        path: paths.raw_path.clone(),
        reason: err.to_string(),
    })?;

    Ok(())
}

fn read_optional_iplist(paths: &CachePaths) -> Result<Option<String>, HttpCacheError> {
    if !paths.iplist_path.exists() {
        return Ok(None);
    }

    let iplist =
        fs::read_to_string(&paths.iplist_path).map_err(|err| HttpCacheError::ReadIplist {
            path: paths.iplist_path.clone(),
            reason: err.to_string(),
        })?;

    Ok(Some(iplist))
}

fn read_optional_metadata(
    paths: &CachePaths,
) -> Result<Option<RemoteCacheMetadata>, HttpCacheError> {
    if !paths.meta_path.exists() {
        return Ok(None);
    }

    let contents =
        fs::read_to_string(&paths.meta_path).map_err(|err| HttpCacheError::ReadMetadata {
            path: paths.meta_path.clone(),
            reason: err.to_string(),
        })?;

    let metadata =
        serde_json::from_str(&contents).map_err(|err| HttpCacheError::ParseMetadata {
            path: paths.meta_path.clone(),
            reason: err.to_string(),
        })?;

    Ok(Some(metadata))
}

fn cache_fallback(
    cached_iplist: Option<String>,
    cached_meta: Option<RemoteCacheMetadata>,
) -> CachedIplist {
    if let Some(iplist) = cached_iplist {
        CachedIplist {
            iplist,
            source: CacheSource::FallbackCache,
            metadata: cached_meta,
        }
    } else {
        CachedIplist {
            iplist: String::new(),
            source: CacheSource::Empty,
            metadata: cached_meta,
        }
    }
}

fn canonical_to_string(cidr: CanonicalCidr) -> String {
    match cidr {
        CanonicalCidr::V4(value) => value.to_string(),
        CanonicalCidr::V6(value) => value.to_string(),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_lower(&digest)
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::{Path, PathBuf};

    use tempfile::TempDir;

    use super::{
        CacheSource, HttpClient, HttpClientError, HttpRequest, HttpResponse, RemoteCacheMetadata,
        cache_paths_for_url, fetch_iplist_with_cache, max_http_body_bytes, normalize_remote_text,
        url_hash_prefix,
    };

    struct MockHttpClient {
        responses: RefCell<VecDeque<Result<HttpResponse, HttpClientError>>>,
        requests: RefCell<Vec<HttpRequest>>,
    }

    impl MockHttpClient {
        fn new(responses: Vec<Result<HttpResponse, HttpClientError>>) -> Self {
            Self {
                responses: RefCell::new(VecDeque::from(responses)),
                requests: RefCell::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<HttpRequest> {
            self.requests.borrow().clone()
        }
    }

    impl HttpClient for MockHttpClient {
        fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            self.requests.borrow_mut().push(request);
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("queued response")
        }
    }

    #[test]
    fn url_hash_is_first_16_hex_of_sha256() {
        assert_eq!(
            url_hash_prefix("https://example.com/feed.txt"),
            "8d1ab0f09e05f237"
        );
    }

    #[test]
    fn cache_paths_use_hash_suffixes() {
        let paths = cache_paths_for_url(Path::new("/cache/remote"), "https://example.com/feed.txt");
        assert_eq!(
            paths.iplist_path,
            PathBuf::from("/cache/remote/8d1ab0f09e05f237.iplist")
        );
        assert_eq!(
            paths.meta_path,
            PathBuf::from("/cache/remote/8d1ab0f09e05f237.meta.json")
        );
        assert_eq!(
            paths.raw_path,
            PathBuf::from("/cache/remote/8d1ab0f09e05f237.raw")
        );
    }

    #[test]
    fn max_body_bytes_env_override_is_supported() {
        let mut env = BTreeMap::new();
        env.insert(
            "KIDOBO_MAX_HTTP_BODY_BYTES".to_string(),
            "12345".to_string(),
        );
        assert_eq!(max_http_body_bytes(&env), 12345);

        env.insert(
            "KIDOBO_MAX_HTTP_BODY_BYTES".to_string(),
            "invalid".to_string(),
        );
        assert_eq!(
            max_http_body_bytes(&env),
            super::DEFAULT_MAX_HTTP_BODY_BYTES
        );
    }

    #[test]
    fn normalization_filters_and_canonicalizes_lines() {
        let raw = b"\xEF\xBB\xBF 10.0.0.5 \n# comment\ninvalid\n2001:db8::1 trailing\n";
        let normalized = normalize_remote_text(raw);
        assert_eq!(normalized, "10.0.0.5/32\n2001:db8::1/128");
    }

    #[test]
    fn sends_conditional_headers_from_metadata() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(cache_dir, url);

        fs::create_dir_all(cache_dir).expect("mkdir");
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");

        let metadata = RemoteCacheMetadata {
            url: url.to_string(),
            etag: Some("etag-1".to_string()),
            last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
            sha256_raw: "raw".to_string(),
            sha256_iplist: "iplist".to_string(),
        };
        fs::write(
            &paths.meta_path,
            serde_json::to_vec_pretty(&metadata).expect("json"),
        )
        .expect("write meta");

        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: 304,
            body: Vec::new(),
            etag: None,
            last_modified: None,
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");
        assert_eq!(result.source, CacheSource::CacheNotModified);

        let requests = client.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].if_none_match.as_deref(), Some("etag-1"));
        assert_eq!(
            requests[0].if_modified_since.as_deref(),
            Some("Mon, 01 Jan 2024 00:00:00 GMT")
        );
    }

    #[test]
    fn status_304_without_cache_triggers_unconditional_refetch() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";

        let client = MockHttpClient::new(vec![
            Ok(HttpResponse {
                status: 304,
                body: Vec::new(),
                etag: None,
                last_modified: None,
            }),
            Ok(HttpResponse {
                status: 200,
                body: b"198.51.100.7".to_vec(),
                etag: Some("etag-2".to_string()),
                last_modified: Some("Tue, 02 Jan 2024 00:00:00 GMT".to_string()),
            }),
        ]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");
        assert_eq!(result.source, CacheSource::Network);
        assert_eq!(result.iplist, "198.51.100.7/32");

        let requests = client.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].if_none_match, None);
        assert_eq!(requests[1].if_modified_since, None);

        let paths = cache_paths_for_url(cache_dir, url);
        assert!(paths.iplist_path.exists());
        assert!(paths.meta_path.exists());
        assert!(paths.raw_path.exists());
    }

    #[test]
    fn network_error_falls_back_to_cache() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";
        let paths = cache_paths_for_url(cache_dir, url);

        fs::create_dir_all(cache_dir).expect("mkdir");
        fs::write(&paths.iplist_path, "10.0.0.0/24\n").expect("write cache");

        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result =
            fetch_iplist_with_cache(&client, url, cache_dir, &BTreeMap::new()).expect("fetch");
        assert_eq!(result.source, CacheSource::FallbackCache);
        assert_eq!(result.iplist, "10.0.0.0/24\n");
    }

    #[test]
    fn body_size_cap_enforced() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();
        let url = "https://example.com/feed.txt";

        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: 200,
            body: b"10.0.0.1\n".to_vec(),
            etag: None,
            last_modified: None,
        })]);

        let mut env = BTreeMap::new();
        env.insert("KIDOBO_MAX_HTTP_BODY_BYTES".to_string(), "1".to_string());

        let result = fetch_iplist_with_cache(&client, url, cache_dir, &env).expect("fetch");
        assert_eq!(result.source, CacheSource::Empty);
        assert!(result.iplist.is_empty());
    }
}
