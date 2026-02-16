#!/usr/bin/env bash
set -euo pipefail

log() {
    printf '[coverage-critical] %s\n' "$1"
}

extract_line_coverage() {
    local file="$1"
    local report_file="$2"

    awk -v target="$file" '
        $1 == target {
            gsub("%", "", $10);
            print $10;
            exit;
        }
    ' "$report_file"
}

check_min_line_coverage() {
    local file="$1"
    local min_percent="$2"
    local report_file="$3"

    local actual_percent
    actual_percent="$(extract_line_coverage "$file" "$report_file")"

    if [[ -z "$actual_percent" ]]; then
        log "missing coverage row for ${file}"
        return 1
    fi

    if ! awk -v actual="$actual_percent" -v min="$min_percent" 'BEGIN { exit (actual + 0 >= min + 0 ? 0 : 1) }'; then
        log "coverage below minimum for ${file}: ${actual_percent}% < ${min_percent}%"
        return 1
    fi

    log "coverage OK for ${file}: ${actual_percent}% (min ${min_percent}%)"
}

report_file="$(mktemp)"
trap 'rm -f "$report_file"' EXIT

log "running global line coverage gate"
cargo llvm-cov --all-features --fail-under-lines 85 --summary-only --quiet | tee "$report_file"

log "checking critical-file minimums"
check_min_line_coverage "main.rs" 100 "$report_file"
check_min_line_coverage "lib.rs" 100 "$report_file"
check_min_line_coverage "logging.rs" 80 "$report_file"
check_min_line_coverage "cli/interrupt.rs" 60 "$report_file"
check_min_line_coverage "cli/mod.rs" 70 "$report_file"
check_min_line_coverage "cli/commands.rs" 70 "$report_file"
check_min_line_coverage "adapters/command_runner.rs" 80 "$report_file"

log "critical coverage checks passed"
