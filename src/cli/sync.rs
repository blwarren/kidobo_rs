use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use log::{error, info, warn};

use crate::adapters::command_runner::SudoCommandRunner;
use crate::adapters::config::load_config_from_file;
use crate::adapters::github_meta::load_github_meta_safelist;
use crate::adapters::http_cache::{HttpClient, ReqwestHttpClient, fetch_iplist_with_cache};
use crate::adapters::ipset::{
    IpsetCommandRunner, IpsetFamily, IpsetSetSpec, atomic_replace_ipset_values, ensure_ipset_exists,
};
use crate::adapters::iptables::{
    ChainAction, FirewallCommandRunner, ensure_firewall_wiring_for_families,
};
use crate::adapters::limited_io::read_to_string_with_limit;
use crate::adapters::lock::acquire_non_blocking;
use crate::adapters::path::{PathResolutionInput, ResolvedPaths, resolve_paths};
use crate::cli::blocklist::{BlocklistNormalizeResult, normalize_local_blocklist_with_fast_state};
use crate::core::config::{Config, FirewallAction};
use crate::core::network::{CanonicalCidr, parse_lines_non_strict};
use crate::core::sync::compute_effective_blocklists;
use crate::error::KidoboError;

const MAX_REMOTE_FETCH_WORKERS: usize = 5;
const BLOCKLIST_READ_LIMIT: usize = 16 * 1024 * 1024;
const BLOCKLIST_FAST_STATE_FILE: &str = "blocklist-normalize.fast-state";
#[cfg(test)]
const RESTORE_SCRIPT_READ_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncSummary {
    pub ipv4_entries: usize,
    pub ipv6_entries: usize,
}

pub fn run_sync_command() -> Result<(), KidoboError> {
    let path_input = PathResolutionInput::from_process(None);
    let paths = resolve_paths(&path_input)?;
    let config = load_config_from_file(&paths.config_file)?;

    let _lock = acquire_non_blocking(&paths.lock_file)?;

    let http_client = ReqwestHttpClient::with_timeout(Duration::from_secs(u64::from(
        config.remote.timeout_secs.get(),
    )));
    let sudo_runner = SudoCommandRunner::default();

    let summary = run_sync_with_dependencies(
        &paths,
        &config,
        &path_input.env,
        &http_client,
        &sudo_runner,
        &sudo_runner,
    )?;

    info!(
        "sync completed: ipv4_entries={} ipv6_entries={}",
        summary.ipv4_entries, summary.ipv6_entries
    );

    Ok(())
}

pub(crate) fn run_sync_with_dependencies(
    paths: &ResolvedPaths,
    config: &Config,
    env: &BTreeMap<String, String>,
    http_client: &(dyn HttpClient + Sync),
    ipset_runner: &dyn IpsetCommandRunner,
    firewall_runner: &dyn FirewallCommandRunner,
) -> Result<SyncSummary, KidoboError> {
    let ipv4_spec = ipv4_set_spec(config);
    let ipv6_spec = ipv6_set_spec(config);

    ensure_ipset_exists(ipset_runner, &ipv4_spec)?;
    if config.ipset.enable_ipv6 {
        ensure_ipset_exists(ipset_runner, &ipv6_spec)?;
    }

    ensure_firewall_wiring_for_families(
        firewall_runner,
        &config.ipset.set_name,
        &config.ipset.set_name_v6,
        config.ipset.enable_ipv6,
        chain_action(config),
    )?;

    let fast_state_path = paths.cache_dir.join(BLOCKLIST_FAST_STATE_FILE);
    let normalize_result =
        normalize_local_blocklist_with_fast_state(&paths.blocklist_file, &fast_state_path)?;
    if normalize_result == BlocklistNormalizeResult::SkippedUnchanged {
        info!(
            "sync blocklist normalization skipped: unchanged path={}",
            paths.blocklist_file.display()
        );
    }

    let internal = load_internal_blocklist(&paths.blocklist_file)?;
    let remote = fetch_remote_networks_concurrently(
        &config.remote.urls,
        http_client,
        &paths.remote_cache_dir,
        env,
    );

    let mut safelist = config.safe.ips.clone();

    if config.safe.include_github_meta {
        match load_github_meta_safelist(
            http_client,
            &paths.remote_cache_dir,
            &config.safe.github_meta_url,
            &config.safe.github_meta_category_mode(),
            env,
        ) {
            Ok(github) => safelist.extend(github.networks),
            Err(err) => warn!("github meta safelist load failed softly: {err}"),
        }
    }

    let internal_count = internal.len();
    let remote_count = remote.len();
    let safelist_count = safelist.len();

    let mut candidates = internal;
    candidates.extend(remote);

    let effective = compute_effective_blocklists(&candidates, &safelist, config.ipset.enable_ipv6);

    if config.ipset.enable_ipv6 {
        ensure_within_maxelem(&ipv6_spec, effective.ipv6.len())?;
        atomic_replace_ipset_values(ipset_runner, &ipv6_spec, &effective.ipv6)?;
    }
    ensure_within_maxelem(&ipv4_spec, effective.ipv4.len())?;
    atomic_replace_ipset_values(ipset_runner, &ipv4_spec, &effective.ipv4)?;

    info!(
        "sync source counts: internal={internal_count} remote={remote_count} safelist={safelist_count}"
    );
    info!(
        "sync final ipset counts: ipv4={pv4} ipv6={pv6}",
        pv4 = effective.ipv4.len(),
        pv6 = effective.ipv6.len()
    );

    Ok(SyncSummary {
        ipv4_entries: effective.ipv4.len(),
        ipv6_entries: effective.ipv6.len(),
    })
}

fn ipv4_set_spec(config: &Config) -> IpsetSetSpec {
    IpsetSetSpec {
        set_name: config.ipset.set_name.clone(),
        set_type: config.ipset.set_type.clone(),
        family: IpsetFamily::Inet,
        hashsize: config.ipset.hashsize.get(),
        maxelem: config.ipset.maxelem.get(),
        timeout: config.ipset.timeout,
    }
}

fn ipv6_set_spec(config: &Config) -> IpsetSetSpec {
    IpsetSetSpec {
        set_name: config.ipset.set_name_v6.clone(),
        set_type: config.ipset.set_type.clone(),
        family: IpsetFamily::Inet6,
        hashsize: config.ipset.hashsize.get(),
        maxelem: config.ipset.maxelem.get(),
        timeout: config.ipset.timeout,
    }
}

fn ensure_within_maxelem(spec: &IpsetSetSpec, entries: usize) -> Result<(), KidoboError> {
    if entries <= spec.maxelem as usize {
        return Ok(());
    }

    let family = match spec.family {
        IpsetFamily::Inet => "ipv4",
        IpsetFamily::Inet6 => "ipv6",
    };

    error!(
        "sync blocked: effective entry count exceeds maxelem: family={} set_name={} entries={} maxelem={}",
        family, spec.set_name, entries, spec.maxelem
    );

    Err(KidoboError::IpsetCapacityExceeded {
        family,
        set_name: spec.set_name.clone(),
        entries,
        maxelem: spec.maxelem,
    })
}

fn chain_action(config: &Config) -> ChainAction {
    match config.ipset.chain_action {
        FirewallAction::Drop => ChainAction::Drop,
        FirewallAction::Reject => ChainAction::Reject,
    }
}

fn load_internal_blocklist(path: &Path) -> Result<Vec<CanonicalCidr>, KidoboError> {
    if !path.exists() {
        return Ok(Vec::new());
    }

    let contents = read_to_string_with_limit(path, BLOCKLIST_READ_LIMIT).map_err(|err| {
        KidoboError::BlocklistRead {
            path: path.to_path_buf(),
            reason: err.to_string(),
        }
    })?;

    Ok(parse_lines_non_strict(contents.lines()))
}

fn fetch_remote_networks_concurrently<S: AsRef<str> + Sync>(
    urls: &[S],
    http_client: &(dyn HttpClient + Sync),
    cache_dir: &Path,
    env: &BTreeMap<String, String>,
) -> Vec<CanonicalCidr> {
    if urls.is_empty() {
        return Vec::new();
    }

    let worker_count = remote_fetch_worker_count(urls.len());
    let next_idx = AtomicUsize::new(0);
    let mut networks = Vec::new();

    thread::scope(|scope| {
        let mut handles = Vec::with_capacity(worker_count);
        for _ in 0..worker_count {
            handles.push(scope.spawn(|| {
                let mut local = Vec::new();
                loop {
                    let idx = next_idx.fetch_add(1, Ordering::Relaxed);
                    let Some(url) = urls.get(idx) else {
                        break;
                    };

                    let url = url.as_ref();
                    match fetch_iplist_with_cache(http_client, url, cache_dir, env) {
                        Ok(cached) => local.extend(cached.networks),
                        Err(err) => warn!("remote source fetch failed softly for {url}: {err}"),
                    }
                }
                local
            }));
        }

        for handle in handles {
            let local = match handle.join() {
                Ok(local) => local,
                Err(payload) => std::panic::resume_unwind(payload),
            };
            networks.extend(local);
        }
    });

    networks.sort_unstable();
    networks.dedup();
    networks
}

fn remote_fetch_worker_count(url_count: usize) -> usize {
    let cpu_parallelism = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    remote_fetch_worker_count_for(url_count, cpu_parallelism)
}

fn remote_fetch_worker_count_for(url_count: usize, cpu_parallelism: usize) -> usize {
    let cpu_budget = cpu_parallelism.max(1);
    let max_workers = MAX_REMOTE_FETCH_WORKERS.min(cpu_budget);
    url_count.min(max_workers.max(1))
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, VecDeque};
    use std::fs;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use reqwest::StatusCode;
    use tempfile::TempDir;

    use super::{
        MAX_REMOTE_FETCH_WORKERS, RESTORE_SCRIPT_READ_LIMIT, ensure_within_maxelem,
        fetch_remote_networks_concurrently, read_to_string_with_limit,
        remote_fetch_worker_count_for, run_sync_with_dependencies,
    };
    use crate::adapters::command_runner::{CommandResult, CommandRunnerError, ProcessStatus};
    use crate::adapters::http_cache::{HttpClient, HttpClientError, HttpRequest, HttpResponse};
    use crate::adapters::ipset::{IpsetCommandRunner, IpsetFamily, IpsetSetSpec};
    use crate::adapters::iptables::FirewallCommandRunner;
    use crate::adapters::path::ResolvedPaths;
    use crate::core::config::{
        CacheStaleAfterSecs, Config, FirewallAction, HashsizePow2, IpsetConfig, MaxElem,
        RemoteConfig, RemoteTimeoutSecs, SafeConfig,
    };
    use crate::core::network::parse_ip_cidr_token;
    use crate::error::KidoboError;

    struct MockHttpClient {
        responses: Mutex<BTreeMap<String, VecDeque<Result<HttpResponse, HttpClientError>>>>,
        events: Arc<Mutex<Vec<String>>>,
        in_flight: AtomicUsize,
        max_in_flight: AtomicUsize,
        delay_ms: u64,
    }

    impl MockHttpClient {
        fn new(
            responses: BTreeMap<String, VecDeque<Result<HttpResponse, HttpClientError>>>,
            events: Arc<Mutex<Vec<String>>>,
            delay_ms: u64,
        ) -> Self {
            Self {
                responses: Mutex::new(responses),
                events,
                in_flight: AtomicUsize::new(0),
                max_in_flight: AtomicUsize::new(0),
                delay_ms,
            }
        }

        fn max_in_flight(&self) -> usize {
            self.max_in_flight.load(Ordering::SeqCst)
        }

        fn update_max_in_flight(&self, current: usize) {
            let mut observed = self.max_in_flight.load(Ordering::SeqCst);
            while current > observed {
                match self.max_in_flight.compare_exchange(
                    observed,
                    current,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(next) => observed = next,
                }
            }
        }
    }

    impl HttpClient for MockHttpClient {
        fn fetch(&self, request: HttpRequest) -> Result<HttpResponse, HttpClientError> {
            {
                let mut events = self
                    .events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                events.push(format!("http:{}", request.url));
            }

            let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.update_max_in_flight(current);

            if self.delay_ms > 0 {
                thread::sleep(Duration::from_millis(self.delay_ms));
            }

            let response = {
                let mut guard = self
                    .responses
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let queue = guard
                    .get_mut(&request.url)
                    .expect("response queue for requested URL");
                queue.pop_front().expect("queued HTTP response")
            };

            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            response
        }
    }

    struct MockCommandRunner {
        events: Arc<Mutex<Vec<String>>>,
        restore_scripts: Mutex<Vec<String>>,
    }

    impl MockCommandRunner {
        fn new(events: Arc<Mutex<Vec<String>>>) -> Self {
            Self {
                events,
                restore_scripts: Mutex::new(Vec::new()),
            }
        }

        fn events(&self) -> Vec<String> {
            self.events
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
        }

        fn swap_targets(&self) -> Vec<String> {
            self.restore_scripts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter_map(|script| {
                    script
                        .lines()
                        .find(|line| line.starts_with("swap "))
                        .and_then(|line| line.split_whitespace().nth(2))
                        .map(ToString::to_string)
                })
                .collect()
        }

        fn entries_for_target_set(&self, target_set_name: &str) -> Vec<String> {
            let mut entries = self
                .restore_scripts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .iter()
                .filter_map(|script| {
                    let target = script
                        .lines()
                        .find(|line| line.starts_with("swap "))
                        .and_then(|line| line.split_whitespace().nth(2))?;
                    if target != target_set_name {
                        return None;
                    }

                    Some(
                        script
                            .lines()
                            .filter(|line| line.starts_with("add "))
                            .filter_map(|line| line.split_whitespace().nth(2))
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    )
                })
                .flatten()
                .collect::<Vec<_>>();
            entries.sort();
            entries
        }

        fn run_impl(&self, command: &str, args: &[&str]) -> CommandResult {
            {
                let mut events = self
                    .events
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                events.push(format!("cmd:{} {}", command, args.join(" ")));
            }

            if command == "ipset" && args.first() == Some(&"restore") && args.len() == 3 {
                let script =
                    read_to_string_with_limit(Path::new(args[2]), RESTORE_SCRIPT_READ_LIMIT)
                        .expect("restore script readable");
                self.restore_scripts
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push(script);
                return success();
            }

            match (command, args.first().copied()) {
                ("ipset", Some("list")) => CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "The set with the given name does not exist".to_string(),
                },
                ("ipset", Some("destroy")) => CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "The set with the given name does not exist".to_string(),
                },
                ("iptables" | "ip6tables", Some("-S")) => CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "No chain/target/match by that name".to_string(),
                },
                ("iptables" | "ip6tables", Some("-D")) => CommandResult {
                    status: ProcessStatus::Exited(1),
                    stdout: String::new(),
                    stderr: "Bad rule (does a matching rule exist in that chain?).".to_string(),
                },
                _ => success(),
            }
        }
    }

    impl IpsetCommandRunner for MockCommandRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.run_impl(command, args))
        }
    }

    impl FirewallCommandRunner for MockCommandRunner {
        fn run(&self, command: &str, args: &[&str]) -> Result<CommandResult, CommandRunnerError> {
            Ok(self.run_impl(command, args))
        }
    }

    fn success() -> CommandResult {
        CommandResult {
            status: ProcessStatus::Exited(0),
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    fn test_paths(root: &Path) -> ResolvedPaths {
        ResolvedPaths {
            config_dir: root.join("config"),
            config_file: root.join("config/config.toml"),
            data_dir: root.join("data"),
            blocklist_file: root.join("data/blocklist.txt"),
            cache_dir: root.join("cache"),
            remote_cache_dir: root.join("cache/remote"),
            lock_file: root.join("cache/sync.lock"),
        }
    }

    fn test_config(urls: Vec<String>) -> Config {
        Config {
            ipset: IpsetConfig {
                set_name: "kidobo".to_string(),
                set_name_v6: "kidobo-v6".to_string(),
                enable_ipv6: true,
                chain_action: FirewallAction::Drop,
                set_type: "hash:net".to_string(),
                hashsize: HashsizePow2::new(65536).expect("valid hashsize"),
                maxelem: MaxElem::new(500000).expect("valid maxelem"),
                timeout: 0,
            },
            safe: SafeConfig {
                ips: vec![parse_ip_cidr_token("10.0.0.0/25").expect("valid safe cidr")],
                include_github_meta: false,
                github_meta_url: "https://api.github.com/meta".to_string(),
                github_meta_categories: None,
            },
            remote: RemoteConfig {
                urls,
                timeout_secs: RemoteTimeoutSecs::new(30).expect("valid timeout"),
                cache_stale_after_secs: CacheStaleAfterSecs::new(86_400).expect("valid stale"),
            },
        }
    }

    fn test_config_with_ipv6(urls: Vec<String>, enable_ipv6: bool) -> Config {
        Config {
            ipset: IpsetConfig {
                set_name: "kidobo".to_string(),
                set_name_v6: "kidobo-v6".to_string(),
                enable_ipv6,
                chain_action: FirewallAction::Drop,
                set_type: "hash:net".to_string(),
                hashsize: HashsizePow2::new(65536).expect("valid hashsize"),
                maxelem: MaxElem::new(500000).expect("valid maxelem"),
                timeout: 0,
            },
            safe: SafeConfig {
                ips: Vec::new(),
                include_github_meta: false,
                github_meta_url: "https://api.github.com/meta".to_string(),
                github_meta_categories: None,
            },
            remote: RemoteConfig {
                urls,
                timeout_secs: RemoteTimeoutSecs::new(30).expect("valid timeout"),
                cache_stale_after_secs: CacheStaleAfterSecs::new(86_400).expect("valid stale"),
            },
        }
    }

    #[test]
    fn sync_orders_firewall_before_remote_fetch_and_restores_ipv6_first() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n2001:db8::/64\n").expect("write blocklist");

        let url_a = "https://example.com/a.txt".to_string();
        let url_b = "https://example.com/b.txt".to_string();
        let config = test_config(vec![url_a.clone(), url_b.clone()]);

        let events = Arc::new(Mutex::new(Vec::new()));

        let mut responses = BTreeMap::new();
        responses.insert(
            url_a.clone(),
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"198.51.100.7\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        );
        responses.insert(
            url_b.clone(),
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"2001:db8:1::/64\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        );

        let http_client = MockHttpClient::new(responses, Arc::clone(&events), 0);
        let runner = MockCommandRunner::new(Arc::clone(&events));

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        assert_eq!(summary.ipv4_entries, 2);
        assert_eq!(summary.ipv6_entries, 2);

        let events = events
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();

        let first_http = events
            .iter()
            .position(|entry| entry.starts_with("http:"))
            .expect("http event");
        let iptables_create = events
            .iter()
            .position(|entry| entry.contains("cmd:iptables -N kidobo-input"))
            .expect("iptables chain creation event");

        assert!(
            iptables_create < first_http,
            "firewall wiring must happen before remote fetch"
        );

        let swap_targets = runner.swap_targets();
        assert_eq!(swap_targets, vec!["kidobo-v6", "kidobo"]);
        assert!(
            events
                .iter()
                .all(|entry| !entry.starts_with("cmd:ipset add ")),
            "sync must populate sets via ipset restore script in one shot"
        );
    }

    #[test]
    fn remote_failures_are_soft_and_concurrency_is_bounded() {
        let temp = TempDir::new().expect("tempdir");
        let cache_dir = temp.path();

        let events = Arc::new(Mutex::new(Vec::new()));

        let urls = (0..8)
            .map(|idx| format!("https://example.com/{idx}.txt"))
            .collect::<Vec<_>>();

        let mut responses = BTreeMap::new();
        for (idx, url) in urls.iter().enumerate() {
            if idx == 3 {
                responses.insert(
                    url.clone(),
                    VecDeque::from([Err(HttpClientError::Request {
                        reason: "offline".to_string(),
                    })]),
                );
            } else {
                responses.insert(
                    url.clone(),
                    VecDeque::from([Ok(HttpResponse {
                        status: StatusCode::OK,
                        body: format!("198.51.100.{}\n", idx + 1).into_bytes(),
                        etag: None,
                        last_modified: None,
                    })]),
                );
            }
        }

        let http_client = MockHttpClient::new(responses, events, 25);

        let networks =
            fetch_remote_networks_concurrently(&urls, &http_client, cache_dir, &BTreeMap::new());

        assert_eq!(networks.len(), 7);
        assert!(http_client.max_in_flight() <= MAX_REMOTE_FETCH_WORKERS);
    }

    #[test]
    fn remote_worker_count_respects_cpu_budget() {
        assert_eq!(remote_fetch_worker_count_for(8, 1), 1);
        assert_eq!(remote_fetch_worker_count_for(8, 2), 2);
        assert_eq!(
            remote_fetch_worker_count_for(8, MAX_REMOTE_FETCH_WORKERS + 5),
            MAX_REMOTE_FETCH_WORKERS
        );
        assert_eq!(remote_fetch_worker_count_for(2, 8), 2);
    }

    #[test]
    fn minimal_behavioral_example_matches_architecture_contract() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n2001:db8::/32\n").expect("write blocklist");

        let url = "https://example.com/minimal.txt".to_string();
        let mut config = test_config(vec![url.clone()]);
        config.safe.ips = vec![parse_ip_cidr_token("10.0.0.0/25").expect("valid safe cidr")];

        let events = Arc::new(Mutex::new(Vec::new()));
        let responses = BTreeMap::from([(
            url,
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"10.0.0.128/25\n198.51.100.7\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        )]);

        let http_client = MockHttpClient::new(responses, Arc::clone(&events), 0);
        let runner = MockCommandRunner::new(Arc::clone(&events));

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        assert_eq!(summary.ipv4_entries, 2);
        assert_eq!(summary.ipv6_entries, 1);
        assert_eq!(
            runner.entries_for_target_set("kidobo"),
            vec!["10.0.0.128/25".to_string(), "198.51.100.7/32".to_string()]
        );
        assert_eq!(
            runner.entries_for_target_set("kidobo-v6"),
            vec!["2001:db8::/32".to_string()]
        );

        let events = runner.events();
        assert!(events.iter().any(|entry| {
            entry.contains("cmd:iptables -A kidobo-input -m set --match-set kidobo src -j DROP")
        }));
        assert!(events.iter().any(|entry| {
            entry.contains("cmd:ip6tables -A kidobo-input -m set --match-set kidobo-v6 src -j DROP")
        }));
    }

    #[test]
    fn sync_applies_reject_target_when_configured() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n").expect("write blocklist");

        let mut config = test_config(Vec::new());
        config.ipset.chain_action = FirewallAction::Reject;

        let events = Arc::new(Mutex::new(Vec::new()));
        let http_client = MockHttpClient::new(BTreeMap::new(), Arc::clone(&events), 0);
        let runner = MockCommandRunner::new(events);

        run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        let events = runner.events();
        assert!(events.iter().any(|entry| {
            entry.contains("cmd:iptables -A kidobo-input -m set --match-set kidobo src -j REJECT")
        }));
        assert!(events.iter().any(|entry| {
            entry.contains(
                "cmd:ip6tables -A kidobo-input -m set --match-set kidobo-v6 src -j REJECT",
            )
        }));
    }

    #[test]
    fn sync_respects_ipv6_disable_mode_end_to_end() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n2001:db8::/32\n").expect("write blocklist");

        let url = "https://example.com/ipv6-off.txt".to_string();
        let config = test_config_with_ipv6(vec![url.clone()], false);
        let events = Arc::new(Mutex::new(Vec::new()));
        let responses = BTreeMap::from([(
            url,
            VecDeque::from([Ok(HttpResponse {
                status: StatusCode::OK,
                body: b"198.51.100.7\n2001:db8:ffff::/48\n".to_vec(),
                etag: None,
                last_modified: None,
            })]),
        )]);

        let http_client = MockHttpClient::new(responses, Arc::clone(&events), 0);
        let runner = MockCommandRunner::new(events);

        let summary = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect("sync");

        assert_eq!(summary.ipv4_entries, 2);
        assert_eq!(summary.ipv6_entries, 0);
        assert_eq!(runner.swap_targets(), vec!["kidobo"]);
        assert_eq!(
            runner.entries_for_target_set("kidobo"),
            vec!["10.0.0.0/24".to_string(), "198.51.100.7/32".to_string()]
        );
        assert!(
            runner
                .events()
                .iter()
                .all(|entry| !entry.starts_with("cmd:ip6tables"))
        );
    }

    #[test]
    fn sync_fails_early_with_clear_error_when_effective_entries_exceed_maxelem() {
        let temp = TempDir::new().expect("tempdir");
        let paths = test_paths(temp.path());

        fs::create_dir_all(paths.blocklist_file.parent().expect("parent")).expect("mkdir data");
        fs::create_dir_all(&paths.remote_cache_dir).expect("mkdir cache");
        fs::write(&paths.blocklist_file, "10.0.0.0/24\n198.51.100.7\n").expect("write blocklist");

        let mut config = test_config_with_ipv6(Vec::new(), false);
        config.ipset.maxelem = MaxElem::new(1).expect("valid maxelem");

        let events = Arc::new(Mutex::new(Vec::new()));
        let http_client = MockHttpClient::new(BTreeMap::new(), events, 0);
        let runner = MockCommandRunner::new(Arc::new(Mutex::new(Vec::new())));

        let err = run_sync_with_dependencies(
            &paths,
            &config,
            &BTreeMap::new(),
            &http_client,
            &runner,
            &runner,
        )
        .expect_err("sync must fail");

        assert!(matches!(
            err,
            KidoboError::IpsetCapacityExceeded {
                family: "ipv4",
                ref set_name,
                entries: 2,
                maxelem: 1
            } if set_name == "kidobo"
        ));
        assert!(runner.swap_targets().is_empty());
    }

    #[test]
    fn ensure_within_maxelem_allows_equal_entry_count() {
        let spec = IpsetSetSpec {
            set_name: "kidobo".to_string(),
            set_type: "hash:net".to_string(),
            family: IpsetFamily::Inet,
            hashsize: 65536,
            maxelem: 2,
            timeout: 0,
        };

        ensure_within_maxelem(&spec, 2).expect("must pass");
    }
}
