#!/usr/bin/env bash
#
# Fetch a pinned snapshot of PQClean's Falcon-512 clean implementation.
#
# We download a specific tarball rather than git-clone because:
#   1. Tarball downloads are deterministic (HTTP caching, hash-checkable)
#   2. PQClean's git history is large; we only need a few directories
#   3. Avoids requiring git inside the Docker build image
#
# The commit we pin is the latest stable as of mid-2025; bump
# CONSCIOUSLY in a separate PR with falcon.t-vector verification.

set -euo pipefail

# Pin to a specific PQClean commit.
#
# How to update:
#   1. Find the new commit hash on https://github.com/PQClean/PQClean/commits/master
#   2. Replace PQCLEAN_COMMIT and PQCLEAN_SHA256 below
#   3. Run: ./fetch-pqclean.sh
#   4. ./build.sh
#   5. Run the falcon.t-vector test; if it passes, commit the new .wasm
PQCLEAN_COMMIT="202a8f96315f9ed219387a50f7e40d04af037ea8"
PQCLEAN_TARBALL_URL="https://github.com/PQClean/PQClean/archive/${PQCLEAN_COMMIT}.tar.gz"

# SHA-256 of the tarball, captured the first time you run this. Pinned
# here so future runs can verify nobody tampered with the download.
# Empty string = compute and print on first run; you copy it here.
PQCLEAN_SHA256=""

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="${SCRIPT_DIR}/pqclean-src"

if [ -d "${DEST}" ]; then
  echo "PQClean already extracted at: ${DEST}"
  echo "Delete it manually to refetch."
  exit 0
fi

echo "Fetching PQClean @ ${PQCLEAN_COMMIT}..."
TMPDIR="$(mktemp -d)"
trap 'rm -rf "${TMPDIR}"' EXIT

TARBALL="${TMPDIR}/pqclean.tar.gz"
curl -fsSL "${PQCLEAN_TARBALL_URL}" -o "${TARBALL}"

ACTUAL_SHA="$(sha256sum "${TARBALL}" | cut -d' ' -f1)"
if [ -z "${PQCLEAN_SHA256}" ]; then
  echo "WARNING: PQCLEAN_SHA256 not set in fetch-pqclean.sh"
  echo "Computed: ${ACTUAL_SHA}"
  echo "Paste this value into PQCLEAN_SHA256 to pin it for future runs."
elif [ "${ACTUAL_SHA}" != "${PQCLEAN_SHA256}" ]; then
  echo "ERROR: PQClean tarball SHA-256 mismatch!"
  echo "  Expected: ${PQCLEAN_SHA256}"
  echo "  Actual:   ${ACTUAL_SHA}"
  echo "Aborting to avoid silently building from tampered source."
  exit 1
fi

echo "Extracting..."
tar -xzf "${TARBALL}" -C "${TMPDIR}"

# We only need two subtrees:
#  - common/        (SHA-3/SHAKE, generic utilities)
#  - crypto_sign/falcon-512/clean/  (the algorithm itself)
mkdir -p "${DEST}"
EXTRACTED="${TMPDIR}/PQClean-${PQCLEAN_COMMIT}"
cp -r "${EXTRACTED}/common"                              "${DEST}/common"
cp -r "${EXTRACTED}/crypto_sign/falcon-512/clean"        "${DEST}/falcon-512"

# Remove the randombytes implementation — we provide our own in shim.c.
rm -f "${DEST}/common/randombytes.c"

echo ""
echo "Done. PQClean source is in: ${DEST}"
echo "Run 'make' (or './build.sh' for the Docker route) next."
