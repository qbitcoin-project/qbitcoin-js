/*
 * Falcon-512 WASM shim — three functions exported to the wallet:
 *
 *   wallet_falcon512_keygen_from_seed(seed[48], pk, sk)
 *   wallet_falcon512_sign_detached(msg, msg_len, sk, sig_out, sig_len_out)
 *   wallet_falcon512_verify(sig, sig_len, msg, msg_len, pk)
 *
 * Plus our own implementation of `randombytes` which PQClean depends on,
 * switching between deterministic-from-seed (during keygen-from-seed)
 * and JS-provided crypto.getRandomValues (during signing).
 *
 * The crypto itself is implemented inside PQClean — we don't touch it.
 * This file is just the boundary between WASM exports and PQClean's
 * internal API.
 *
 */

#include <emscripten.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "api.h"  /* from pqclean-src/falcon-512/, gives sizes + signatures */

/* ─── randombytes plumbing ─────────────────────────────────────────────
 *
 * PQClean Falcon's crypto_sign_keypair calls randombytes() to grab 48
 * bytes of seed; everything after that is deterministic given those
 * bytes. We exploit this by providing our own randombytes that EITHER:
 *
 *  - Hands out bytes from a caller-supplied seed buffer
 *    (deterministic keygen)
 *  - Calls back to JS crypto.getRandomValues
 *    (randomized signing — Falcon's sign also uses entropy)
 */

static const uint8_t *g_seed_buf = NULL;
static size_t         g_seed_off = 0;
static size_t         g_seed_len = 0;

/* JS-side function — Emscripten generates the binding. */
EM_JS(void, js_random_bytes, (uint8_t *out, size_t len), {
  const dst = new Uint8Array(HEAPU8.buffer, out, len);
  crypto.getRandomValues(dst);
});

/* PQClean expects this symbol at link time.
 *
 * Modern PQClean namespaces this function as `PQCLEAN_randombytes` to
 * avoid conflicts with libcrypto / libsodium. The signature returns
 * `int` — 0 on success, nonzero on failure. */
int PQCLEAN_randombytes(uint8_t *out, size_t outlen) {
  if (g_seed_buf != NULL) {
    /* Deterministic mode: serve from the caller's seed buffer.
     *
     * If PQClean asks for more bytes than the caller provided as seed,
     * we ZERO-fill and RETURN FAILURE rather than continue with an
     * underrun. Silent zero-padding here would produce a predictable
     * key — strictly worse than a loud error. PQClean's Falcon-512
     * keygen needs exactly 48 bytes; anything else is a caller bug. */
    if (g_seed_off + outlen <= g_seed_len) {
      memcpy(out, g_seed_buf + g_seed_off, outlen);
      g_seed_off += outlen;
      return 0;
    }
    memset(out, 0, outlen);
    return -1;
  }
  js_random_bytes(out, outlen);
  return 0;
}

/* ─── Exported API ────────────────────────────────────────────────────
 *
 * EMSCRIPTEN_KEEPALIVE ensures the symbols survive dead-code elimination
 * even though no internal caller references them — they're only invoked
 * from JS via Module.ccall / cwrap.
 */

EMSCRIPTEN_KEEPALIVE
int wallet_falcon512_keygen_from_seed(
    const uint8_t *seed,
    size_t         seed_len,
    uint8_t       *pk_out,
    uint8_t       *sk_out)
{
  if (seed_len < 48) {
    return -1;  /* Falcon-512 needs at least 48 bytes of entropy. */
  }

  g_seed_buf = seed;
  g_seed_off = 0;
  g_seed_len = seed_len;

  int rc = PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(pk_out, sk_out);

  /* Always reset the seed-mode flag, even on failure, so subsequent
   * signing operations don't accidentally inherit deterministic mode. */
  g_seed_buf = NULL;
  g_seed_off = 0;
  g_seed_len = 0;

  return rc;
}

EMSCRIPTEN_KEEPALIVE
int wallet_falcon512_sign_detached(
    const uint8_t *msg,
    size_t         msg_len,
    const uint8_t *sk,
    uint8_t       *sig_out,
    size_t        *sig_len_out)
{
  /* Caller pre-allocates a buffer of size CRYPTO_BYTES (max sig size,
   * 666 bytes for Falcon-512). PQClean writes the actual length into
   * sig_len_out — caller should slice sig_out to that. */
  *sig_len_out = PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES;
  return PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
      sig_out, sig_len_out, msg, msg_len, sk);
}

EMSCRIPTEN_KEEPALIVE
int wallet_falcon512_verify(
    const uint8_t *sig,
    size_t         sig_len,
    const uint8_t *msg,
    size_t         msg_len,
    const uint8_t *pk)
{
  /* PQClean returns 0 on valid signature, nonzero otherwise. */
  return PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
      sig, sig_len, msg, msg_len, pk);
}

/* ─── Size constants exposed to JS ────────────────────────────────────
 *
 * Avoids hardcoding magic numbers in the TypeScript wrapper — JS reads
 * these once at module-init time and uses them to allocate buffers.
 */

EMSCRIPTEN_KEEPALIVE
size_t wallet_falcon512_pubkey_bytes(void) {
  return PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES;  /* 897 */
}

EMSCRIPTEN_KEEPALIVE
size_t wallet_falcon512_privkey_bytes(void) {
  return PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES;  /* 1281 */
}

EMSCRIPTEN_KEEPALIVE
size_t wallet_falcon512_sig_max_bytes(void) {
  return PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES;           /* 666 */
}

EMSCRIPTEN_KEEPALIVE
size_t wallet_falcon512_seed_bytes(void) {
  return 48;  /* Falcon-512 inner_shake256 seed length */
}
