#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
release_notes_dir="${repo_root}/release-notes"
output_file="${repo_root}/CHANGELOG.md"
dates_file="${release_notes_dir}/dates.tsv"
unreleased_file="${release_notes_dir}/unreleased.md"

declare -A release_dates
if [[ -f "${dates_file}" ]]; then
  while IFS= read -r line; do
    [[ -z "${line}" || "${line}" =~ ^# ]] && continue
    read -r version date <<<"${line}"
    if [[ -n "${version}" && -n "${date}" ]]; then
      release_dates["${version}"]="${date}"
    fi
  done < "${dates_file}"
fi

tmp_file="$(mktemp)"
trap 'rm -f "${tmp_file}"' EXIT

{
  echo "# Changelog"
  echo
  echo "## [Unreleased]"
  echo
  if [[ -f "${unreleased_file}" ]]; then
    cat "${unreleased_file}"
    echo
  fi

  mapfile -t release_files < <(find "${release_notes_dir}" -maxdepth 1 -type f -name 'v*.md' | sort -rV)
  for file in "${release_files[@]}"; do
    file_name="$(basename "${file}" .md)"
    version="${file_name#v}"
    release_date="${release_dates[${file_name}]:-}"
    if [[ -n "${release_date}" ]]; then
      echo "## [${version}] - ${release_date}"
    else
      echo "## [${version}]"
    fi
    echo
    sed '1{/^# Release /d;}' "${file}" | sed '1{/^$/d;}'
    echo
  done
} > "${tmp_file}"

mv "${tmp_file}" "${output_file}"
