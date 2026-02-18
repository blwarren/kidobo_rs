#!/usr/bin/env bash
set -euo pipefail

if [[ ! -x /usr/bin/time ]]; then
  echo "error: /usr/bin/time is required for max RSS reporting" >&2
  exit 1
fi

blocks="${KIDOBO_PERF_BLOCKS:-50000}"
targets="${KIDOBO_PERF_TARGETS:-10000}"

if [[ "${blocks}" -le 0 || "${targets}" -le 1 ]]; then
  echo "error: KIDOBO_PERF_BLOCKS must be > 0 and KIDOBO_PERF_TARGETS must be > 1" >&2
  exit 1
fi

tmp_root="$(mktemp -d)"
trap 'rm -rf "${tmp_root}"' EXIT

export KIDOBO_ROOT="${tmp_root}/root"
binary="target/release/kidobo"
blocklist_path="${KIDOBO_ROOT}/data/blocklist.txt"
targets_path="${tmp_root}/targets.txt"
lookup_output_path="${tmp_root}/lookup.out"
time_output_path="${tmp_root}/time.out"

cargo build --release --locked --bin kidobo >/dev/null
"${binary}" init >/dev/null

awk -v count="${blocks}" 'BEGIN {
  for (i = 0; i < count; i++) {
    a = int(i / 256) % 256;
    b = i % 256;
    printf "203.%d.%d.0/24\n", a, b;
  }
}' > "${blocklist_path}"

half_targets=$((targets / 2))
awk -v count="${half_targets}" 'BEGIN {
  for (i = 0; i < count; i++) {
    a = int(i / 256) % 256;
    b = i % 256;
    printf "203.%d.%d.7\n", a, b;
  }
  for (i = 0; i < count; i++) {
    a = int(i / 256) % 256;
    b = i % 256;
    printf "198.51.%d.%d\n", a, b;
  }
}' > "${targets_path}"

/usr/bin/time -f 'elapsed_s=%e
max_rss_kib=%M' \
  "${binary}" lookup --file "${targets_path}" > "${lookup_output_path}" 2> "${time_output_path}"

printf 'blocklist_entries=%s\n' "${blocks}"
printf 'target_entries=%s\n' "$((half_targets * 2))"
printf 'lookup_matches=%s\n' "$(wc -l < "${lookup_output_path}" | tr -d ' ')"
cat "${time_output_path}"
