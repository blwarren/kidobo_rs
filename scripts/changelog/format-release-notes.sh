#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
release_notes_dir="${repo_root}/release-notes"

format_one() {
  local file="$1"
  local tmp_file
  tmp_file="$(mktemp)"

  # Deterministic markdown normalization:
  # - trim trailing whitespace
  # - drop leading blank lines
  # - collapse repeated blank lines to a single blank line
  awk '
    {
      sub(/[[:space:]]+$/, "", $0)
      lines[NR] = $0
    }
    END {
      saw_content = 0
      prev_blank = 0
      for (i = 1; i <= NR; i++) {
        line = lines[i]
        blank = (line == "")

        if (!saw_content && blank) {
          continue
        }

        if (blank && prev_blank) {
          continue
        }

        print line
        saw_content = 1
        prev_blank = blank
      }
    }
  ' "${file}" > "${tmp_file}"

  mv "${tmp_file}" "${file}"
}

shopt -s nullglob
files=("${release_notes_dir}/unreleased.md" "${release_notes_dir}"/v*.md)
for file in "${files[@]}"; do
  format_one "${file}"
done
