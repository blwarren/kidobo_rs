use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use kidobo::adapters::config::load_config_from_file;
use kidobo::adapters::http_cache::{ReqwestHttpClient, fetch_iplist_with_cache};
use kidobo::adapters::limited_io::read_to_string_with_limit;
use kidobo::core::lookup::{LookupSourceEntry, run_lookup};
use kidobo::core::network::{
    CanonicalCidr, IntervalU32, Ipv4Cidr, Ipv6Cidr, ipv4_to_interval, merge_intervals_u32,
    parse_lines_non_strict, subtract_safelist_ipv4, subtract_safelist_ipv6,
};
use kidobo::core::sync::compute_effective_blocklists;

const BENCH_BLOCKLIST_READ_LIMIT: usize = 8 * 1024 * 1024;
const BENCH_REMOTE_IPLIST_READ_LIMIT: usize = 16 * 1024 * 1024;

fn generate_ipv4_cidrs(count: usize) -> Vec<Ipv4Cidr> {
    let mut cidrs = Vec::with_capacity(count);
    for i in 0..count {
        let idx = i as u32;
        let network = (10_u32 << 24) | ((idx & 0x00ff_ffff) << 8);
        cidrs.push(Ipv4Cidr::from_parts(network, 24));
    }
    cidrs
}

fn generate_ipv6_cidrs(count: usize) -> Vec<Ipv6Cidr> {
    let mut cidrs = Vec::with_capacity(count);
    for i in 0..count {
        let idx = i as u128;
        let network = 0x20010db8000000000000000000000000_u128 | (idx << 64);
        cidrs.push(Ipv6Cidr::from_parts(network, 64));
    }
    cidrs
}

fn generate_candidates(v4_count: usize, v6_count: usize) -> Vec<CanonicalCidr> {
    let mut out = Vec::with_capacity(v4_count + v6_count);
    out.extend(
        generate_ipv4_cidrs(v4_count)
            .into_iter()
            .map(CanonicalCidr::V4),
    );
    out.extend(
        generate_ipv6_cidrs(v6_count)
            .into_iter()
            .map(CanonicalCidr::V6),
    );
    out
}

fn deterministic_shuffle_u32(data: &mut [IntervalU32]) {
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for i in (1..data.len()).rev() {
        state ^= state << 7;
        state ^= state >> 9;
        state ^= state << 8;
        let j = (state as usize) % (i + 1);
        data.swap(i, j);
    }
}

fn generate_disjoint_intervals(count: usize) -> Vec<IntervalU32> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = (i as u32) * 4;
        out.push(IntervalU32 {
            start,
            end: start + 1,
        });
    }
    out
}

fn generate_overlapping_intervals(count: usize) -> Vec<IntervalU32> {
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let start = i as u32;
        out.push(IntervalU32 {
            start,
            end: start + 32,
        });
    }
    out
}

fn radix_sort_intervals_by_start_u32(intervals: &mut [IntervalU32]) {
    if intervals.len() < 2 {
        return;
    }

    let len = intervals.len();
    let mut src = intervals.to_vec();
    let mut dst = vec![IntervalU32 { start: 0, end: 0 }; len];
    let mut counts = vec![0_usize; 1 << 16];

    for shift in [0_u32, 16_u32] {
        counts.fill(0);

        for interval in &src {
            let bucket = ((interval.start >> shift) & 0xFFFF) as usize;
            counts[bucket] += 1;
        }

        let mut running = 0_usize;
        for count in &mut counts {
            let current = *count;
            *count = running;
            running += current;
        }

        for interval in &src {
            let bucket = ((interval.start >> shift) & 0xFFFF) as usize;
            let out_idx = counts[bucket];
            dst[out_idx] = *interval;
            counts[bucket] += 1;
        }

        std::mem::swap(&mut src, &mut dst);
    }

    intervals.copy_from_slice(&src);
}

fn merge_intervals_u32_radix(intervals: &[IntervalU32]) -> Vec<IntervalU32> {
    if intervals.is_empty() {
        return Vec::new();
    }

    let mut sorted = intervals.to_vec();
    radix_sort_intervals_by_start_u32(&mut sorted);

    let mut iter = sorted.into_iter();
    let Some(mut current) = iter.next() else {
        return Vec::new();
    };
    let mut merged = Vec::new();

    for interval in iter {
        if interval.start <= current.end.saturating_add(1) {
            current.end = current.end.max(interval.end);
        } else {
            merged.push(current);
            current = interval;
        }
    }

    merged.push(current);
    merged
}

fn generate_almost_sorted_intervals(count: usize) -> Vec<IntervalU32> {
    let mut out = generate_disjoint_intervals(count);
    if out.len() < 4 {
        return out;
    }

    let stride = 100_usize;
    for i in (stride..out.len()).step_by(stride) {
        out.swap(i - 1, i);
    }

    out
}

fn benchmark_merge_intervals_ipv4(c: &mut Criterion) {
    let mut group = c.benchmark_group("merge_intervals_ipv4");
    for size in [10_000_usize, 50_000_usize, 100_000_usize] {
        let disjoint_sorted = generate_disjoint_intervals(size);
        let disjoint_almost_sorted = generate_almost_sorted_intervals(size);
        let mut disjoint_shuffled = disjoint_sorted.clone();
        deterministic_shuffle_u32(&mut disjoint_shuffled);
        let overlap_sorted = generate_overlapping_intervals(size);

        group.throughput(Throughput::Elements(size as u64));
        group.bench_with_input(
            BenchmarkId::new("disjoint_sorted", size),
            &disjoint_sorted,
            |b, intervals| {
                b.iter(|| {
                    black_box(merge_intervals_u32(black_box(intervals)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("disjoint_sorted_radix", size),
            &disjoint_sorted,
            |b, intervals| {
                b.iter(|| {
                    black_box(merge_intervals_u32_radix(black_box(intervals)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("disjoint_almost_sorted", size),
            &disjoint_almost_sorted,
            |b, intervals| {
                b.iter(|| {
                    black_box(merge_intervals_u32(black_box(intervals)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("disjoint_almost_sorted_radix", size),
            &disjoint_almost_sorted,
            |b, intervals| {
                b.iter(|| {
                    black_box(merge_intervals_u32_radix(black_box(intervals)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("disjoint_shuffled", size),
            &disjoint_shuffled,
            |b, intervals| {
                b.iter(|| {
                    black_box(merge_intervals_u32(black_box(intervals)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("disjoint_shuffled_radix", size),
            &disjoint_shuffled,
            |b, intervals| {
                b.iter(|| {
                    black_box(merge_intervals_u32_radix(black_box(intervals)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("overlap_sorted", size),
            &overlap_sorted,
            |b, intervals| {
                b.iter(|| {
                    black_box(merge_intervals_u32(black_box(intervals)));
                });
            },
        );
        group.bench_with_input(
            BenchmarkId::new("overlap_sorted_radix", size),
            &overlap_sorted,
            |b, intervals| {
                b.iter(|| {
                    black_box(merge_intervals_u32_radix(black_box(intervals)));
                });
            },
        );
    }
    group.finish();
}

fn benchmark_effective_blocklists(c: &mut Criterion) {
    let mut group = c.benchmark_group("compute_effective_blocklists");
    for size in [5_000_usize, 20_000_usize] {
        let candidates = generate_candidates(size, size / 5);
        let safelist = candidates
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 11 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates.len() + safelist.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::from_parameter(size), &size, |b, _| {
            b.iter(|| {
                black_box(compute_effective_blocklists(
                    black_box(&candidates),
                    black_box(&safelist),
                    black_box(true),
                ));
            });
        });
    }
    group.finish();
}

fn benchmark_subtract_safelist(c: &mut Criterion) {
    let mut group = c.benchmark_group("subtract_safelist");

    for size in [10_000_usize, 50_000_usize] {
        let candidates_v4 = generate_ipv4_cidrs(size);
        let safelist_v4 = candidates_v4
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 7 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates_v4.len() + safelist_v4.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::new("ipv4", size), &size, |b, _| {
            b.iter(|| {
                black_box(subtract_safelist_ipv4(
                    black_box(&candidates_v4),
                    black_box(&safelist_v4),
                ));
            });
        });
    }

    for size in [2_000_usize, 10_000_usize] {
        let candidates_v6 = generate_ipv6_cidrs(size);
        let safelist_v6 = candidates_v6
            .iter()
            .copied()
            .enumerate()
            .filter_map(|(idx, cidr)| (idx % 9 == 0).then_some(cidr))
            .collect::<Vec<_>>();

        group.throughput(Throughput::Elements(
            (candidates_v6.len() + safelist_v6.len()) as u64,
        ));
        group.bench_with_input(BenchmarkId::new("ipv6", size), &size, |b, _| {
            b.iter(|| {
                black_box(subtract_safelist_ipv6(
                    black_box(&candidates_v6),
                    black_box(&safelist_v6),
                ));
            });
        });
    }

    group.finish();
}

fn benchmark_lookup(c: &mut Criterion) {
    let mut group = c.benchmark_group("run_lookup");
    for source_count in [10_000_usize, 25_000_usize] {
        let label: Arc<str> = Arc::from("bench:internal");
        let sources = generate_ipv4_cidrs(source_count)
            .into_iter()
            .map(|cidr| LookupSourceEntry {
                source_label: Arc::clone(&label),
                source_line: cidr.to_string(),
                cidr: CanonicalCidr::V4(cidr),
            })
            .collect::<Vec<_>>();

        let mut targets = Vec::with_capacity(4_000);
        for i in 0..2_000_u32 {
            let host = (10_u32 << 24) | ((i & 0xffff) << 8) | 7;
            targets.push(std::net::Ipv4Addr::from(host).to_string());
        }
        for i in 0..2_000_u32 {
            let host = (198_u32 << 24) | (51_u32 << 16) | ((i & 0xff) << 8) | (i & 0xff);
            targets.push(std::net::Ipv4Addr::from(host).to_string());
        }

        group.throughput(Throughput::Elements((sources.len() + targets.len()) as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(source_count),
            &source_count,
            |b, _| {
                b.iter(|| {
                    black_box(run_lookup(black_box(&targets), black_box(&sources)));
                });
            },
        );
    }
    group.finish();
}

#[derive(Clone)]
struct RealWorldDataset {
    candidates: Vec<CanonicalCidr>,
    safelist: Vec<CanonicalCidr>,
    ipv4_intervals: Vec<IntervalU32>,
    ipv4_intervals_by_source: Vec<Vec<IntervalU32>>,
}

fn repeat_vec<T: Clone>(values: &[T], scale: usize) -> Vec<T> {
    let mut out = Vec::with_capacity(values.len() * scale);
    for _ in 0..scale {
        out.extend_from_slice(values);
    }
    out
}

fn env_truthy(name: &str) -> bool {
    std::env::var(name).ok().is_some_and(|raw| {
        matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        )
    })
}

fn find_real_world_config(root: &Path) -> Option<PathBuf> {
    let root_config = root.join("config.toml");
    if root_config.exists() {
        return Some(root_config);
    }

    let nested = root.join("config/config.toml");
    if nested.exists() {
        return Some(nested);
    }

    None
}

fn fetch_remote_cache_from_config(root: &Path, config: &kidobo::core::config::Config) {
    if config.remote.urls.is_empty() {
        return;
    }

    if let Err(err) = fs::create_dir_all(root.join("cache/remote")) {
        eprintln!("real-world bench: failed to create remote cache dir: {err}");
        return;
    }

    let timeout = Duration::from_secs(u64::from(config.remote.timeout_secs.get()));
    let client = ReqwestHttpClient::with_timeout(timeout);
    let env_map: BTreeMap<String, String> = std::env::vars().collect();
    let mut fetched = 0_usize;
    let mut failed = 0_usize;

    for url in &config.remote.urls {
        match fetch_iplist_with_cache(&client, url, &root.join("cache/remote"), &env_map) {
            Ok(_) => fetched += 1,
            Err(err) => {
                failed += 1;
                eprintln!("real-world bench: remote fetch failed softly for {url}: {err}");
            }
        }
    }

    eprintln!(
        "real-world bench: remote fetch complete fetched={fetched} failed={failed} urls_total={}",
        config.remote.urls.len()
    );
}

fn load_real_world_dataset() -> Option<RealWorldDataset> {
    let root = std::env::var("KIDOBO_BENCH_ROOT")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(".local-scenarios/real"));

    let config_path = find_real_world_config(&root)?;
    let config = load_config_from_file(&config_path).ok()?;
    if env_truthy("KIDOBO_BENCH_FETCH_REMOTE") {
        fetch_remote_cache_from_config(&root, &config);
    }

    let blocklist_path = root.join("data/blocklist.txt");
    let blocklist_text =
        read_to_string_with_limit(&blocklist_path, BENCH_BLOCKLIST_READ_LIMIT).ok()?;
    let mut candidates = parse_lines_non_strict(blocklist_text.lines());
    let mut ipv4_intervals_by_source = Vec::new();
    let mut local_intervals = parse_lines_non_strict(blocklist_text.lines())
        .into_iter()
        .filter_map(|cidr| match cidr {
            CanonicalCidr::V4(v4) => Some(ipv4_to_interval(v4)),
            CanonicalCidr::V6(_) => None,
        })
        .collect::<Vec<_>>();
    local_intervals.sort_unstable();
    ipv4_intervals_by_source.push(local_intervals);

    let remote_cache_dir = root.join("cache/remote");
    if remote_cache_dir.is_dir() {
        let mut files = fs::read_dir(remote_cache_dir)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| path.extension().is_some_and(|ext| ext == "iplist"))
            .collect::<Vec<_>>();
        files.sort();
        for file in files {
            if let Ok(text) = read_to_string_with_limit(&file, BENCH_REMOTE_IPLIST_READ_LIMIT) {
                let parsed = parse_lines_non_strict(text.lines());
                let mut source_intervals = parsed
                    .iter()
                    .filter_map(|cidr| match cidr {
                        CanonicalCidr::V4(v4) => Some(ipv4_to_interval(*v4)),
                        CanonicalCidr::V6(_) => None,
                    })
                    .collect::<Vec<_>>();
                source_intervals.sort_unstable();
                ipv4_intervals_by_source.push(source_intervals);
                candidates.extend(parsed);
            }
        }
    }

    let ipv4_intervals = candidates
        .iter()
        .filter_map(|cidr| match cidr {
            CanonicalCidr::V4(v4) => Some(ipv4_to_interval(*v4)),
            CanonicalCidr::V6(_) => None,
        })
        .collect::<Vec<_>>();

    eprintln!(
        "real-world bench dataset: candidates={} safelist={} ipv4_intervals={}",
        candidates.len(),
        config.safe.ips.len(),
        ipv4_intervals.len()
    );

    Some(RealWorldDataset {
        candidates,
        safelist: config.safe.ips,
        ipv4_intervals,
        ipv4_intervals_by_source,
    })
}

fn benchmark_real_world(c: &mut Criterion) {
    let Some(dataset) = load_real_world_dataset() else {
        eprintln!(
            "Skipping real-world benches: set KIDOBO_BENCH_ROOT (default .local-scenarios/real)"
        );
        return;
    };

    let mut merge_group = c.benchmark_group("real_world_merge_intervals_ipv4");
    merge_group.throughput(Throughput::Elements(dataset.ipv4_intervals.len() as u64));
    let source_sorted_concat = dataset
        .ipv4_intervals_by_source
        .iter()
        .flatten()
        .copied()
        .collect::<Vec<_>>();
    merge_group.bench_function("as_loaded", |b| {
        b.iter(|| {
            black_box(merge_intervals_u32(black_box(&dataset.ipv4_intervals)));
        });
    });
    merge_group.bench_function("as_loaded_radix", |b| {
        b.iter(|| {
            black_box(merge_intervals_u32_radix(black_box(
                &dataset.ipv4_intervals,
            )));
        });
    });
    let mut sorted = dataset.ipv4_intervals.clone();
    sorted.sort_unstable();
    merge_group.bench_function("pre_sorted", |b| {
        b.iter(|| {
            black_box(merge_intervals_u32(black_box(&sorted)));
        });
    });
    merge_group.bench_function("pre_sorted_radix", |b| {
        b.iter(|| {
            black_box(merge_intervals_u32_radix(black_box(&sorted)));
        });
    });
    let mut shuffled = dataset.ipv4_intervals.clone();
    deterministic_shuffle_u32(&mut shuffled);
    merge_group.bench_function("shuffled", |b| {
        b.iter(|| {
            black_box(merge_intervals_u32(black_box(&shuffled)));
        });
    });
    merge_group.bench_function("shuffled_radix", |b| {
        b.iter(|| {
            black_box(merge_intervals_u32_radix(black_box(&shuffled)));
        });
    });
    merge_group.bench_function("source_sorted_concat", |b| {
        b.iter(|| {
            black_box(merge_intervals_u32(black_box(&source_sorted_concat)));
        });
    });
    merge_group.bench_function("source_sorted_concat_radix", |b| {
        b.iter(|| {
            black_box(merge_intervals_u32_radix(black_box(&source_sorted_concat)));
        });
    });
    merge_group.finish();

    let mut effective_group = c.benchmark_group("real_world_compute_effective_blocklists");
    effective_group.throughput(Throughput::Elements(
        (dataset.candidates.len() + dataset.safelist.len()) as u64,
    ));
    effective_group.bench_function("ipv4_ipv6_enabled", |b| {
        b.iter(|| {
            black_box(compute_effective_blocklists(
                black_box(&dataset.candidates),
                black_box(&dataset.safelist),
                black_box(true),
            ));
        });
    });
    effective_group.bench_function("ipv4_only", |b| {
        b.iter(|| {
            black_box(compute_effective_blocklists(
                black_box(&dataset.candidates),
                black_box(&dataset.safelist),
                black_box(false),
            ));
        });
    });
    effective_group.finish();

    let scales = [1_usize, 2_usize, 5_usize, 10_usize];

    let mut merge_scaled_group = c.benchmark_group("real_world_merge_intervals_ipv4_scaled");
    for scale in scales {
        let intervals = repeat_vec(&dataset.ipv4_intervals, scale);
        merge_scaled_group.throughput(Throughput::Elements(intervals.len() as u64));
        merge_scaled_group.bench_with_input(
            BenchmarkId::new("as_loaded", scale),
            &intervals,
            |b, input| {
                b.iter(|| {
                    black_box(merge_intervals_u32(black_box(input)));
                });
            },
        );
        merge_scaled_group.bench_with_input(
            BenchmarkId::new("as_loaded_radix", scale),
            &intervals,
            |b, input| {
                b.iter(|| {
                    black_box(merge_intervals_u32_radix(black_box(input)));
                });
            },
        );

        let mut shuffled = intervals.clone();
        deterministic_shuffle_u32(&mut shuffled);
        merge_scaled_group.bench_with_input(
            BenchmarkId::new("shuffled", scale),
            &shuffled,
            |b, input| {
                b.iter(|| {
                    black_box(merge_intervals_u32(black_box(input)));
                });
            },
        );
        merge_scaled_group.bench_with_input(
            BenchmarkId::new("shuffled_radix", scale),
            &shuffled,
            |b, input| {
                b.iter(|| {
                    black_box(merge_intervals_u32_radix(black_box(input)));
                });
            },
        );
    }
    merge_scaled_group.finish();

    let mut effective_scaled_group =
        c.benchmark_group("real_world_compute_effective_blocklists_scaled");
    for scale in scales {
        let candidates = repeat_vec(&dataset.candidates, scale);
        let safelist = repeat_vec(&dataset.safelist, scale);
        effective_scaled_group.throughput(Throughput::Elements(
            (candidates.len() + safelist.len()) as u64,
        ));
        effective_scaled_group.bench_with_input(
            BenchmarkId::new("ipv4_only", scale),
            &(candidates, safelist),
            |b, input| {
                b.iter(|| {
                    black_box(compute_effective_blocklists(
                        black_box(&input.0),
                        black_box(&input.1),
                        black_box(false),
                    ));
                });
            },
        );
    }
    effective_scaled_group.finish();
}

criterion_group!(
    core_perf,
    benchmark_merge_intervals_ipv4,
    benchmark_real_world,
    benchmark_effective_blocklists,
    benchmark_subtract_safelist,
    benchmark_lookup
);
criterion_main!(core_perf);
