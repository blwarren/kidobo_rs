use std::path::Path;

use log::warn;
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::adapters::hash::sha256_hex;
use crate::adapters::http_cache::{HttpClient, HttpResponse};
use crate::adapters::http_fetch::{
    dispatch_conditional_fetch_result, fetch_with_conditional_cache,
};
use crate::adapters::limited_io::{read_bytes_with_limit, write_bytes_atomic};

pub struct CachedFetchRequest<'a> {
    pub client: &'a dyn HttpClient,
    pub url: &'a str,
    pub max_body_bytes: usize,
    pub cached_etag: Option<String>,
    pub cached_last_modified: Option<String>,
    pub has_usable_cache: bool,
    pub log_subject: &'a str,
    pub missing_response_warning: &'a str,
}

#[derive(Debug, Error)]
pub enum WriteJsonError {
    #[error("failed to serialize JSON: {reason}")]
    Serialize { reason: String },

    #[error("failed to write JSON file: {reason}")]
    Write { reason: String },
}

pub fn run_cached_fetch<T, E, FCacheNotModified, FFallback, FNetwork>(
    request: CachedFetchRequest<'_>,
    on_cache_not_modified: FCacheNotModified,
    on_fallback_cache: FFallback,
    on_network: FNetwork,
) -> Result<T, E>
where
    FCacheNotModified: FnOnce() -> Result<T, E>,
    FFallback: FnOnce() -> Result<T, E>,
    FNetwork: FnOnce(HttpResponse) -> Result<T, E>,
{
    let result = fetch_with_conditional_cache(
        request.client,
        request.url,
        request.max_body_bytes,
        request.cached_etag,
        request.cached_last_modified,
        request.has_usable_cache,
        request.log_subject,
    );

    dispatch_conditional_fetch_result(
        result,
        request.missing_response_warning,
        on_cache_not_modified,
        on_fallback_cache,
        on_network,
    )
}

pub fn read_optional_bytes_lossy(
    path: &Path,
    read_limit: usize,
    description: &str,
) -> Option<Vec<u8>> {
    if !path.exists() {
        return None;
    }

    match read_bytes_with_limit(path, read_limit) {
        Ok(contents) => Some(contents),
        Err(err) => {
            warn!("failed to read {description} {}: {err}", path.display());
            None
        }
    }
}

pub fn read_optional_json_lossy<T>(path: &Path, read_limit: usize, description: &str) -> Option<T>
where
    T: DeserializeOwned,
{
    let bytes = read_optional_bytes_lossy(path, read_limit, description)?;

    match serde_json::from_slice::<T>(&bytes) {
        Ok(parsed) => Some(parsed),
        Err(err) => {
            warn!(
                "failed to parse {description} {} as JSON: {err}",
                path.display()
            );
            None
        }
    }
}

pub fn read_validated_bytes_lossy(
    path: &Path,
    read_limit: usize,
    description: &str,
    expected_sha256: Option<&str>,
    mismatch_subject: &str,
    ignored_label: &str,
) -> Option<Vec<u8>> {
    let bytes = read_optional_bytes_lossy(path, read_limit, description)?;

    if let Some(expected_sha256) = expected_sha256 {
        let actual_hash = sha256_hex(&bytes);
        if actual_hash != expected_sha256 {
            warn!(
                "{mismatch_subject} hash mismatch for {}: ignoring cached {ignored_label}",
                path.display()
            );
            return None;
        }
    }

    Some(bytes)
}

pub fn write_bytes_atomic_in_cache(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    ensure_parent_dir(path)?;
    write_bytes_atomic(path, bytes)
}

pub fn write_json_pretty_atomic<T>(path: &Path, value: &T) -> Result<(), WriteJsonError>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).map_err(|err| WriteJsonError::Serialize {
        reason: err.to_string(),
    })?;
    write_bytes_atomic_in_cache(path, &bytes).map_err(|err| WriteJsonError::Write {
        reason: err.to_string(),
    })
}

fn ensure_parent_dir(path: &Path) -> Result<(), std::io::Error> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::fs;

    use reqwest::StatusCode;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    use super::{
        CachedFetchRequest, read_optional_json_lossy, read_validated_bytes_lossy, run_cached_fetch,
        write_bytes_atomic_in_cache, write_json_pretty_atomic,
    };
    use crate::adapters::http_cache::{HttpClient, HttpClientError, HttpRequest, HttpResponse};
    use crate::adapters::limited_io::read_bytes_with_limit;

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

    #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
    struct SampleJson {
        value: String,
    }

    #[test]
    fn returns_network_response_for_successful_fetch() {
        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::OK,
            body: b"body".to_vec(),
            etag: Some("etag-1".to_string()),
            last_modified: None,
        })]);

        let result = run_cached_fetch(
            CachedFetchRequest {
                client: &client,
                url: "https://example.com/feed.txt",
                max_body_bytes: 1024,
                cached_etag: None,
                cached_last_modified: None,
                has_usable_cache: false,
                log_subject: "remote source",
                missing_response_warning: "missing response",
            },
            || Ok::<String, String>("cache-not-modified".to_string()),
            || Ok("fallback".to_string()),
            |response| Ok(String::from_utf8_lossy(&response.body).to_string()),
        )
        .expect("fetch result");

        assert_eq!(result, "body");
        assert_eq!(client.requests().len(), 1);
    }

    #[test]
    fn returns_cache_not_modified_when_304_has_usable_cache() {
        let client = MockHttpClient::new(vec![Ok(HttpResponse {
            status: StatusCode::NOT_MODIFIED,
            body: Vec::new(),
            etag: None,
            last_modified: None,
        })]);

        let result = run_cached_fetch(
            CachedFetchRequest {
                client: &client,
                url: "https://example.com/feed.txt",
                max_body_bytes: 1024,
                cached_etag: Some("etag-1".to_string()),
                cached_last_modified: None,
                has_usable_cache: true,
                log_subject: "remote source",
                missing_response_warning: "missing response",
            },
            || Ok::<String, String>("cache-not-modified".to_string()),
            || Ok("fallback".to_string()),
            |_| Ok("network".to_string()),
        )
        .expect("fetch result");

        assert_eq!(result, "cache-not-modified");
        assert_eq!(client.requests().len(), 1);
    }

    #[test]
    fn refetches_when_304_does_not_have_usable_cache() {
        let client = MockHttpClient::new(vec![
            Ok(HttpResponse {
                status: StatusCode::NOT_MODIFIED,
                body: Vec::new(),
                etag: None,
                last_modified: None,
            }),
            Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"network".to_vec(),
                etag: None,
                last_modified: None,
            }),
        ]);

        let result = run_cached_fetch(
            CachedFetchRequest {
                client: &client,
                url: "https://example.com/feed.txt",
                max_body_bytes: 1024,
                cached_etag: Some("etag-1".to_string()),
                cached_last_modified: Some("Mon, 01 Jan 2024 00:00:00 GMT".to_string()),
                has_usable_cache: false,
                log_subject: "remote source",
                missing_response_warning: "missing response",
            },
            || Ok::<String, String>("cache-not-modified".to_string()),
            || Ok("fallback".to_string()),
            |response| Ok(String::from_utf8_lossy(&response.body).to_string()),
        )
        .expect("fetch result");

        assert_eq!(result, "network");
        let requests = client.requests();
        assert_eq!(requests.len(), 2);
        assert_eq!(requests[1].if_none_match, None);
        assert_eq!(requests[1].if_modified_since, None);
    }

    #[test]
    fn falls_back_when_network_fetch_fails() {
        let client = MockHttpClient::new(vec![Err(HttpClientError::Request {
            reason: "offline".to_string(),
        })]);

        let result = run_cached_fetch(
            CachedFetchRequest {
                client: &client,
                url: "https://example.com/feed.txt",
                max_body_bytes: 1024,
                cached_etag: None,
                cached_last_modified: None,
                has_usable_cache: false,
                log_subject: "remote source",
                missing_response_warning: "missing response",
            },
            || Ok::<String, String>("cache-not-modified".to_string()),
            || Ok("fallback".to_string()),
            |_| Ok("network".to_string()),
        )
        .expect("fetch result");

        assert_eq!(result, "fallback");
    }

    #[test]
    fn invalid_hash_blocks_cached_bytes() {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("raw.json");
        fs::write(&path, b"raw-body").expect("write raw");

        let result = read_validated_bytes_lossy(
            &path,
            1024,
            "raw cache file",
            Some("not-the-right-hash"),
            "raw cache",
            "body",
        );

        assert!(result.is_none());
    }

    #[test]
    fn writes_and_reads_cache_helpers() {
        let temp = TempDir::new().expect("tempdir");
        let raw_path = temp.path().join("cache/raw.bin");
        let json_path = temp.path().join("cache/meta.json");

        write_bytes_atomic_in_cache(&raw_path, b"payload").expect("write bytes");
        write_json_pretty_atomic(
            &json_path,
            &SampleJson {
                value: "ok".to_string(),
            },
        )
        .expect("write json");

        let json = read_optional_json_lossy::<SampleJson>(&json_path, 1024, "json cache file")
            .expect("read json");

        assert_eq!(
            read_bytes_with_limit(&raw_path, 1024).expect("read raw"),
            b"payload"
        );
        assert_eq!(
            json,
            SampleJson {
                value: "ok".to_string()
            }
        );
    }
}
