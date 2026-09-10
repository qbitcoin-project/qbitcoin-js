# Reproducible build environment for the Falcon-512 WASM module.
#
# Pinned to Emscripten 3.1.61 (released July 2024). Bumping this version
# is a deliberate decision — different Emscripten versions can produce
# byte-different wasm output even for identical C source. Reproducibility
# only holds within the same image.

FROM emscripten/emsdk:3.1.61

# Add curl & sha256sum for fetch-pqclean.sh.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        ca-certificates \
        coreutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# We mount the source tree at runtime; the image only carries the
# toolchain.
CMD ["make"]
