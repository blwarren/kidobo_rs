#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

export KIDOBO_PERF_CPU_CORE="${KIDOBO_PERF_CPU_CORE:-0}"
export KIDOBO_PERF_MEM_LIMIT_KIB="${KIDOBO_PERF_MEM_LIMIT_KIB:-1048576}"

exec "${script_dir}/measure-lookup-rss.sh"
