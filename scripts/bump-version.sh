#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat <<'EOF'
Usage:
  scripts/bump-version.sh <major|minor|patch|X.Y.Z>

Examples:
  scripts/bump-version.sh patch
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
        /^version="v[^"]+"$/ && !updated {
            $0 = "version=\"" new_tag_version "\""
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

main() {
    if [[ $# -ne 1 ]]; then
        usage >&2
        exit 1
    fi

    require_cmd git
    require_cmd awk
    require_cmd mktemp

    local repo_root
    repo_root="$(git rev-parse --show-toplevel)"
    cd "$repo_root"

    if [[ ! -f Cargo.toml || ! -f Cargo.lock || ! -f README.md ]]; then
        echo "must run inside repository root with Cargo.toml, Cargo.lock, and README.md" >&2
        exit 1
    fi

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

    local requested="$1"
    local target_version
    target_version="$(compute_target_version "$current_version" "$requested")"

    update_cargo_toml_version "$target_version"
    update_cargo_lock_root_version "$package_name" "$target_version"
    update_readme_release_example "$target_version"

    echo "version updated: ${current_version} -> ${target_version}"
    echo "updated files:"
    echo "  Cargo.toml"
    echo "  Cargo.lock"
    echo "  README.md"
    echo
    echo "next steps:"
    echo "  1) run validation gates"
    echo "  2) commit changes"
    echo "  3) push matching tag: v${target_version}"
}

main "$@"
