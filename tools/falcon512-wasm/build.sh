#!/usr/bin/env bash
#
# Build the Falcon-512 WASM module inside a pinned Docker image.
# Usage: ./build.sh
#
# Requires Docker or Podman. For local emcc builds use `make` directly
# (see README.md).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "${SCRIPT_DIR}"

# Choose the container engine — Docker preferred, Podman as fallback.
if command -v docker >/dev/null 2>&1; then
  ENGINE=docker
elif command -v podman >/dev/null 2>&1; then
  ENGINE=podman
else
  echo "Neither docker nor podman is installed."
  echo "Install one of them, or use './fetch-pqclean.sh && make' with local emcc."
  exit 1
fi

IMAGE_TAG="falcon512-builder:latest"

# Fetch PQClean if missing (idempotent).
./fetch-pqclean.sh

# Build the image (cached after first run).
echo "==> Building Docker image..."
${ENGINE} build -t "${IMAGE_TAG}" .

# Run make inside the container. We invoke just `make` (not `make install`)
# because the install target writes to ../../packages/crypto/wasm/ —
# outside the mounted volume — so the host doesn't see the result. We do
# the copy on the host side below, where the path actually exists.
echo "==> Compiling WASM..."
${ENGINE} run --rm \
  --user "$(id -u):$(id -g)" \
  -v "${SCRIPT_DIR}:/work" \
  "${IMAGE_TAG}" \
  make

# Install on the host side so the destination path works regardless of
# Docker's mount layout.
DEST="${SCRIPT_DIR}/../../packages/crypto/wasm"
mkdir -p "${DEST}"
cp "${SCRIPT_DIR}/out/falcon512.wasm" "${DEST}/"
cp "${SCRIPT_DIR}/out/falcon512.mjs"  "${DEST}/"

echo
echo "==> Installed to ${DEST}/"
shasum -a 256 "${DEST}/falcon512.wasm" 2>/dev/null || sha256sum "${DEST}/falcon512.wasm"

echo
echo "==> Done. Verify with:"
echo "    cd ../.."
echo "    pnpm --filter @qbtc/crypto test falcon512"
