#!/usr/bin/env bash
set -euo pipefail

REPO_SLUG="${KIDOBO_REPO_SLUG:-blwarren/kidobo_rs}"
INSTALL_DIR="${KIDOBO_INSTALL_DIR:-/usr/local/bin}"
BINARY_NAME="kidobo"
INIT_AFTER_INSTALL=0
VERSION=""

usage() {
    cat <<'EOF'
Usage:
  scripts/install.sh [--version vX.Y.Z] [--init]

Options:
  --version vX.Y.Z  Install a specific release tag. Defaults to latest.
  --init            Run `kidobo init` after installing the binary.
  -h, --help        Show this help.

Environment:
  KIDOBO_REPO_SLUG   Override GitHub repo slug (default: blwarren/kidobo_rs)
  KIDOBO_INSTALL_DIR Override install path (default: /usr/local/bin)
EOF
}

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}

resolve_latest_tag() {
    local latest_url
    latest_url="$(
        curl -fsSL -o /dev/null -w '%{url_effective}' \
            "https://github.com/${REPO_SLUG}/releases/latest"
    )"

    local tag="${latest_url##*/}"
    if [[ ! "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
        echo "failed to resolve latest release tag from: ${latest_url}" >&2
        exit 1
    fi

    echo "${tag}"
}

install_file() {
    local source_file="$1"
    local target_file="$2"

    if [[ -w "$(dirname "${target_file}")" ]]; then
        install -m 0755 "${source_file}" "${target_file}"
    elif command -v sudo >/dev/null 2>&1; then
        sudo install -m 0755 "${source_file}" "${target_file}"
    else
        echo "no write access to $(dirname "${target_file}") and sudo is unavailable" >&2
        exit 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)
            if [[ $# -lt 2 ]]; then
                echo "missing value for --version" >&2
                exit 1
            fi
            VERSION="$2"
            shift
            ;;
        --init)
            INIT_AFTER_INSTALL=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "unknown argument: $1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

require_cmd curl
require_cmd tar
require_cmd sha256sum
require_cmd install

if [[ -z "${VERSION}" ]]; then
    VERSION="$(resolve_latest_tag)"
fi

if [[ ! "${VERSION}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    echo "invalid version tag: ${VERSION}" >&2
    exit 1
fi

ARCHIVE="kidobo-${VERSION}-linux-x86_64.tar.gz"
BASE_URL="https://github.com/${REPO_SLUG}/releases/download/${VERSION}"
TARGET_PATH="${INSTALL_DIR}/${BINARY_NAME}"

workdir="$(mktemp -d)"
trap 'rm -rf "${workdir}"' EXIT

echo "installing ${BINARY_NAME} ${VERSION} from ${REPO_SLUG}"
curl -fsSL -o "${workdir}/${ARCHIVE}" "${BASE_URL}/${ARCHIVE}"
curl -fsSL -o "${workdir}/SHA256SUMS" "${BASE_URL}/SHA256SUMS"

(
    cd "${workdir}"
    expected_line="$(grep " ${ARCHIVE}\$" SHA256SUMS || true)"
    if [[ -z "${expected_line}" ]]; then
        echo "checksum entry not found for ${ARCHIVE}" >&2
        exit 1
    fi
    echo "${expected_line}" | sha256sum -c -
)

tar -xzf "${workdir}/${ARCHIVE}" -C "${workdir}"
install_file "${workdir}/kidobo-${VERSION}-linux-x86_64/${BINARY_NAME}" "${TARGET_PATH}"

echo "installed ${BINARY_NAME} to ${TARGET_PATH}"
"${TARGET_PATH}" --version

if [[ "${INIT_AFTER_INSTALL}" -eq 1 ]]; then
    echo "running ${BINARY_NAME} init"
    if [[ -w /etc || -w /var || -w /usr ]]; then
        "${TARGET_PATH}" init
    elif command -v sudo >/dev/null 2>&1; then
        sudo "${TARGET_PATH}" init
    else
        echo "skipping init: insufficient privileges and sudo unavailable" >&2
        exit 1
    fi
fi
