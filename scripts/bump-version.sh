#!/usr/bin/env bash
set -euo pipefail

TXN_ACTIVE=0
TXN_BACKUP_DIR=""
TXN_FILES=()
TXN_EXISTED=()

usage() {
    cat <<'EOF'
Usage:
  scripts/bump-version.sh [--dry-run] <major|minor|patch|X.Y.Z>

Examples:
  scripts/bump-version.sh patch
  scripts/bump-version.sh --dry-run patch
  scripts/bump-version.sh minor
  scripts/bump-version.sh 0.2.0
EOF
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

ensure_file_exists() {
    if [[ ! -f "$1" ]]; then
        echo "missing required file: $1" >&2
        exit 1
    fi
}

read_package_field() {
    local field="$1"
    awk -v field="$field" '
        BEGIN { in_package = 0 }
        /^\[package\]$/ { in_package = 1; next }
        /^\[/ && $0 != "[package]" { in_package = 0 }
        in_package && $0 ~ ("^" field " = \"") {
            line = $0
            sub("^" field " = \"", "", line)
            sub("\"$", "", line)
            print line
            exit 0
        }
    ' Cargo.toml
}

parse_numeric_semver() {
    local value="$1"
    if [[ "$value" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; then
        echo "${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]}"
        return 0
    fi
    return 1
}

compute_target_version() {
    local current="$1"
    local request="$2"

    case "$request" in
        patch|minor|major)
            local parsed
            if ! parsed="$(parse_numeric_semver "$current")"; then
                echo "cannot perform $request bump from non-numeric version: $current" >&2
                exit 1
            fi
            local major minor patch
            read -r major minor patch <<<"$parsed"

            case "$request" in
                patch)
                    patch=$((patch + 1))
                    ;;
                minor)
                    minor=$((minor + 1))
                    patch=0
                    ;;
                major)
                    major=$((major + 1))
                    minor=0
                    patch=0
                    ;;
            esac

            echo "${major}.${minor}.${patch}"
            ;;
        *)
            if [[ "$request" =~ ^[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
                echo "$request"
            else
                echo "invalid version: $request" >&2
                exit 1
            fi
            ;;
    esac
}

update_cargo_toml_version() {
    local new_version="$1"
    local temp
    temp="$(mktemp)"

    awk -v new_version="$new_version" '
        BEGIN { in_package = 0; updated = 0 }
        /^\[package\]$/ { in_package = 1 }
        /^\[/ && $0 != "[package]" { in_package = 0 }
        in_package && /^version = "/ && !updated {
            $0 = "version = \"" new_version "\""
            updated = 1
        }
        { print }
        END {
            if (!updated) {
                print "failed to update version in Cargo.toml" > "/dev/stderr"
                exit 2
            }
        }
    ' Cargo.toml >"$temp"

    mv "$temp" Cargo.toml
}

update_cargo_lock_root_version() {
    local package_name="$1"
    local new_version="$2"
    local temp
    temp="$(mktemp)"

    awk -v package_name="$package_name" -v new_version="$new_version" '
        BEGIN { in_package = 0; target_package = 0; updated = 0 }

        /^\[\[package\]\]$/ {
            in_package = 1
            target_package = 0
        }

        in_package && /^name = "/ {
            name = $0
            sub(/^name = "/, "", name)
            sub(/"$/, "", name)
            if (name == package_name) {
                target_package = 1
            }
        }

        in_package && target_package && /^version = "/ && !updated {
            $0 = "version = \"" new_version "\""
            updated = 1
            target_package = 0
            in_package = 0
        }

        { print }

        END {
            if (!updated) {
                print "failed to update root package version in Cargo.lock" > "/dev/stderr"
                exit 3
            }
        }
    ' Cargo.lock >"$temp"

    mv "$temp" Cargo.lock
}

update_readme_release_example() {
    local new_tag_version="v$1"
    local temp
    temp="$(mktemp)"

    awk -v new_tag_version="$new_tag_version" '
        BEGIN { updated = 0 }
        /install\.sh/ && /--version[[:space:]]+v[0-9A-Za-z][0-9A-Za-z.-]*/ && !updated {
            sub(/--version[[:space:]]+v[0-9A-Za-z][0-9A-Za-z.-]*/, "--version " new_tag_version)
            updated = 1
        }
        { print }
        END {
            if (!updated) {
                print "failed to update release example version in README.md" > "/dev/stderr"
                exit 4
            }
        }
    ' README.md >"$temp"

    mv "$temp" README.md
}

extract_changelog_section_body() {
    local section="$1"
    local changelog_file="$2"

    awk -v section="$section" '
        BEGIN {
            in_section = 0
            found = 0
        }

        {
            if (match($0, /^## \[([^]]+)\]/, match_data)) {
                if (in_section) {
                    exit 0
                }

                if (match_data[1] == section) {
                    in_section = 1
                    found = 1
                    next
                }
            }

            if (in_section) {
                print
            }
        }

        END {
            if (!found) {
                exit 10
            }
        }
    ' "$changelog_file"
}

changelog_body_has_content() {
    local content="$1"
    awk '
        /^[[:space:]]*$/ { next }
        { found = 1; exit 0 }
        END { exit found ? 0 : 1 }
    ' <<<"$content"
}

changelog_has_section() {
    local section="$1"
    local changelog_file="$2"

    awk -v section="$section" '
        match($0, /^## \[([^]]+)\]/, match_data) {
            if (match_data[1] == section) {
                found = 1
                exit 0
            }
        }
        END { exit found ? 0 : 1 }
    ' "$changelog_file"
}

resolve_release_notes_body() {
    local target_version="$1"
    local changelog_file="$2"
    local body=""

    if body="$(extract_changelog_section_body "$target_version" "$changelog_file")"; then
        :
    elif body="$(extract_changelog_section_body "Unreleased" "$changelog_file")"; then
        :
    else
        echo "failed to find changelog section [${target_version}] or [Unreleased] in ${changelog_file}" >&2
        exit 1
    fi

    if ! changelog_body_has_content "$body"; then
        echo "changelog section for release notes is empty in ${changelog_file}" >&2
        exit 1
    fi

    printf '%s' "$body"
}

promote_unreleased_to_version_section() {
    local target_version="$1"
    local release_date="$2"
    local changelog_file="$3"
    local temp
    temp="$(mktemp)"

    awk -v target_version="$target_version" -v release_date="$release_date" '
        BEGIN {
            in_unreleased = 0
            updated = 0
        }

        !updated && $0 == "## [Unreleased]" {
            print "## [Unreleased]"
            print ""
            print "## [" target_version "] - " release_date
            print ""
            in_unreleased = 1
            updated = 1
            next
        }

        in_unreleased && /^## \[/ {
            in_unreleased = 0
            print ""
            print
            next
        }

        { print }

        END {
            if (!updated) {
                print "failed to promote [Unreleased] section in CHANGELOG.md" > "/dev/stderr"
                exit 12
            }
        }
    ' "$changelog_file" >"$temp"

    mv "$temp" "$changelog_file"
}

write_release_notes_file() {
    local target_version="$1"
    local body="$2"
    local output_dir="$3"
    local output_file="$output_dir/v${target_version}.md"

    mkdir -p "$output_dir"
    {
        echo "# Release v${target_version}"
        echo
        printf '%s\n' "$body"
    } >"$output_file"
}

transaction_begin() {
    local file_path

    TXN_BACKUP_DIR="$(mktemp -d)"
    TXN_ACTIVE=1
    TXN_FILES=()
    TXN_EXISTED=()

    for file_path in "$@"; do
        TXN_FILES+=("$file_path")
        if [[ -f "$file_path" ]]; then
            TXN_EXISTED+=("1")
            mkdir -p "$TXN_BACKUP_DIR/$(dirname "$file_path")"
            cp -- "$file_path" "$TXN_BACKUP_DIR/$file_path"
        else
            TXN_EXISTED+=("0")
        fi
    done

    trap 'transaction_on_exit $?' EXIT
}

transaction_cleanup() {
    if [[ -n "$TXN_BACKUP_DIR" && -d "$TXN_BACKUP_DIR" ]]; then
        rm -rf -- "$TXN_BACKUP_DIR"
    fi
    TXN_ACTIVE=0
    TXN_BACKUP_DIR=""
    TXN_FILES=()
    TXN_EXISTED=()
}

transaction_rollback() {
    local idx file_path existed_flag
    for idx in "${!TXN_FILES[@]}"; do
        file_path="${TXN_FILES[$idx]}"
        existed_flag="${TXN_EXISTED[$idx]}"
        if [[ "$existed_flag" == "1" ]]; then
            mkdir -p "$(dirname "$file_path")"
            cp -- "$TXN_BACKUP_DIR/$file_path" "$file_path"
        else
            rm -f -- "$file_path"
        fi
    done
    transaction_cleanup
}

transaction_on_exit() {
    local status="$1"

    if [[ "$TXN_ACTIVE" -ne 1 ]]; then
        return
    fi

    if [[ "$status" -eq 0 ]]; then
        transaction_cleanup
        return
    fi

    transaction_rollback
    echo "bump-version: rolled back file changes after failure" >&2
}

main() {
    local dry_run=0
    local requested=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run)
                dry_run=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            -*)
                echo "unknown option: $1" >&2
                usage >&2
                exit 1
                ;;
            *)
                if [[ -n "$requested" ]]; then
                    echo "unexpected extra argument: $1" >&2
                    usage >&2
                    exit 1
                fi
                requested="$1"
                ;;
        esac
        shift
    done

    if [[ -z "$requested" ]]; then
        usage >&2
        exit 1
    fi

    require_cmd git
    require_cmd awk
    require_cmd mktemp

    local repo_root
    repo_root="$(git rev-parse --show-toplevel)"
    cd "$repo_root"

    ensure_file_exists Cargo.toml
    ensure_file_exists Cargo.lock
    ensure_file_exists README.md
    ensure_file_exists CHANGELOG.md

    local current_version
    current_version="$(read_package_field version)"
    if [[ -z "${current_version}" ]]; then
        echo "failed to read current version from Cargo.toml" >&2
        exit 1
    fi

    local package_name
    package_name="$(read_package_field name)"
    if [[ -z "${package_name}" ]]; then
        echo "failed to read package name from Cargo.toml" >&2
        exit 1
    fi

    local target_version
    target_version="$(compute_target_version "$current_version" "$requested")"
    local changelog_needs_promotion=0
    if ! changelog_has_section "$target_version" CHANGELOG.md; then
        changelog_needs_promotion=1
    fi
    local release_notes_body
    release_notes_body="$(resolve_release_notes_body "$target_version" CHANGELOG.md)"
    local release_notes_file="release-notes/v${target_version}.md"

    if [[ "$dry_run" -eq 1 ]]; then
        echo "dry-run: version would be updated: ${current_version} -> ${target_version}"
        echo "dry-run: files that would be updated:"
        echo "  Cargo.toml"
        echo "  Cargo.lock"
        echo "  README.md"
        if [[ "$changelog_needs_promotion" -eq 1 ]]; then
            echo "  CHANGELOG.md"
        fi
        echo "  ${release_notes_file}"
        echo
        echo "dry-run: release notes source: CHANGELOG.md section [${target_version}] or [Unreleased]"
        echo "dry-run: this script does not create or push git tags"
        echo "dry-run: after commit, run:"
        echo "  scripts/post-coding-gates.sh"
        echo "  cargo +nightly udeps --all-targets --all-features"
        echo "  git tag -a v${target_version} -m \"v${target_version}\""
        echo "  git push origin v${target_version}"
        echo "dry-run: no files were modified"
        exit 0
    fi

    local txn_files=("Cargo.toml" "Cargo.lock" "README.md" "$release_notes_file")
    if [[ "$changelog_needs_promotion" -eq 1 ]]; then
        txn_files+=("CHANGELOG.md")
    fi
    transaction_begin "${txn_files[@]}"

    update_cargo_toml_version "$target_version"
    update_cargo_lock_root_version "$package_name" "$target_version"
    update_readme_release_example "$target_version"
    if [[ "$changelog_needs_promotion" -eq 1 ]]; then
        promote_unreleased_to_version_section "$target_version" "$(date +%Y-%m-%d)" CHANGELOG.md
    fi
    write_release_notes_file "$target_version" "$release_notes_body" "release-notes"

    echo "version updated: ${current_version} -> ${target_version}"
    echo "updated files:"
    echo "  Cargo.toml"
    echo "  Cargo.lock"
    echo "  README.md"
    if [[ "$changelog_needs_promotion" -eq 1 ]]; then
        echo "  CHANGELOG.md"
    fi
    echo "  ${release_notes_file}"
    echo
    echo "this script does not create or push git tags"
    echo "next steps:"
    echo "  1) run validation gates: scripts/post-coding-gates.sh"
    echo "  2) run periodic gate: cargo +nightly udeps --all-targets --all-features"
    echo "  3) commit changes"
    echo "  4) run tag commands:"
    echo "     git tag -a v${target_version} -m \"v${target_version}\""
    echo "     git push origin v${target_version}"
}

main "$@"
