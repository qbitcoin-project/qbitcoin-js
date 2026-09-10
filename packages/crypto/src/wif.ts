// WIF (Wallet Import Format) — private-key serialization, node-compatible.
//
// Wire layout (the node's WIF codec):
//
//   wif = base58( version (1) || payload || checksum (4) )
//
//   version  = one byte per network, a CHAIN VALUE (`profile.wifVersion`;
//              typically the Bitcoin-compatible 0x80 mainnet / 0xEF testnet)
//   checksum = first 4 bytes of HASH256(version || payload)
//
// Unlike Bitcoin there is NO trailing compression-flag byte — the node always
// derives compressed pubkeys (its ECC layer exports 'public_compressed'), so the
// payload is exactly the raw key material:
//
//   32 bytes           secp256k1 scalar — ECDSA *or* Schnorr; the format
//                      cannot tell them apart (the node's pk_alg() lists
//                      both, and importprivkey defaults to ECDSA)
//   1281 + 897 bytes   Falcon-512 private key || public key — PQClean
//                      serialization (the node's Falcon-512 pk_serialize)
//
// The algorithm is NOT encoded in the string, so decodeWif reports every
// algorithm the payload is valid for — in the node's own preference order —
// and the caller (typically the import UI) picks one.

import type { Algorithm, Network } from './constants';
import { decodeBase58Check, encodeBase58Check } from './encoding/base58check';
import {
  FALCON512_PRIVATE_KEY_BYTES,
  FALCON512_PUBLIC_KEY_BYTES,
  falcon512Sign,
  falcon512Verify,
  type Falcon512Keypair,
} from './falcon512';
import { PRIVATE_KEY_BYTES, isValidPrivateKey } from './secp256k1';

/** Length of a Falcon-512 WIF payload: private key ‖ public key (2178). */
export const FALCON512_KEYPAIR_BYTES =
  FALCON512_PRIVATE_KEY_BYTES + FALCON512_PUBLIC_KEY_BYTES;

const VERSION_LEN = 1;

/** Malformed WIF: bad Base58, checksum, version byte, or payload. */
export class WifError extends Error {
  override readonly name: string = 'WifError';
}

/**
 * Structurally valid WIF for the WRONG network. Its own error type so the
 * UI can say "this is a testnet key" instead of a generic parse failure.
 */
export class WifNetworkError extends WifError {
  override readonly name = 'WifNetworkError';
  constructor(
    /** The network the caller asked for. */
    readonly expected: Network,
    /** The network the key actually belongs to. */
    readonly detected: Network,
  ) {
    super(`This is a ${detected} private key, not ${expected}.`);
  }
}

/** Result of {@link decodeWif}. */
export interface DecodedWif {
  /**
   * The raw key material (32 bytes classical, 2178 bytes Falcon-512).
   * SECRET — the caller owns it and should wipe it (`payload.fill(0)`)
   * as soon as it is no longer needed.
   */
  readonly payload: Uint8Array;
  /**
   * Every algorithm this payload is valid for, in the node's preference
   * order (ascending numeric algo id, like pk_alg()): a 32-byte key is
   * `['ecdsa', 'schnorr']`, a 2178-byte blob is `['falcon512']`.
   */
  readonly candidates: readonly Algorithm[];
}

/**
 * Decode and validate a WIF string for `network`.
 *
 * `versions` maps each network to its one-byte WIF version
 * (`profile.wifVersion`); both networks are needed so a structurally
 * valid key for the OTHER network is reported as {@link WifNetworkError}
 * rather than a generic parse failure.
 *
 * Throws {@link WifNetworkError} if the key belongs to the other network,
 * {@link WifError} for anything else malformed. Never guesses: a Bitcoin
 * compressed-key WIF (33-byte payload with a trailing 0x01 flag) is
 * rejected with an explanatory message rather than silently reinterpreted.
 */
export function decodeWif(
  wif: string,
  network: Network,
  versions: Readonly<Record<Network, number>>,
): DecodedWif {
  let version: Uint8Array;
  let payload: Uint8Array;
  try {
    ({ version, payload } = decodeBase58Check(wif.trim(), VERSION_LEN));
  } catch (e) {
    throw new WifError(`Not a valid WIF string: ${(e as Error).message}`);
  }

  const versionByte = version[0];
  if (versionByte !== versions[network]) {
    const other: Network = network === 'mainnet' ? 'testnet' : 'mainnet';
    if (versionByte === versions[other]) {
      throw new WifNetworkError(network, other);
    }
    throw new WifError(
      `Unknown WIF version byte 0x${(versionByte ?? 0).toString(16).padStart(2, '0')}.`,
    );
  }

  return { payload, candidates: candidatesFor(payload) };
}

/**
 * Encode raw key material as a WIF string for `network`, using the
 * chain's per-network version bytes (`profile.wifVersion`).
 *
 * Accepts the two node payload sizes (32-byte classical scalar, 2178-byte
 * Falcon-512 keypair). Length is the only check — a 32-byte payload is not
 * scalar-validated here, matching the node's wallet_import_format().
 */
export function encodeWif(
  payload: Uint8Array,
  network: Network,
  versions: Readonly<Record<Network, number>>,
): string {
  if (
    payload.length !== PRIVATE_KEY_BYTES &&
    payload.length !== FALCON512_KEYPAIR_BYTES
  ) {
    throw new RangeError(
      `WIF payload must be ${PRIVATE_KEY_BYTES} or ${FALCON512_KEYPAIR_BYTES} bytes, got ${payload.length}`,
    );
  }
  return encodeBase58Check(Uint8Array.of(versions[network]), payload);
}

// Fixed message for the Falcon pair self-check below. The content is
// arbitrary; it only has to be deterministic.
const PAIR_CHECK_MESSAGE = new TextEncoder().encode(
  'wif/falcon512-pair-check/v1',
);

/**
 * Split a 2178-byte Falcon-512 WIF payload into its keypair and PROVE the
 * halves belong together (sign a fixed message with the private key, verify
 * with the embedded public key). The Base58Check checksum only guards
 * against transport corruption — a hand-assembled blob could carry a
 * mismatched pair, which would derive an address the private key cannot
 * actually spend from.
 *
 * Returns independent copies; the caller should wipe both the input payload
 * and, eventually, the returned private key. Throws {@link WifError} on a
 * wrong length or a mismatched pair.
 */
export async function falconKeypairFromWifPayload(
  payload: Uint8Array,
): Promise<Falcon512Keypair> {
  if (payload.length !== FALCON512_KEYPAIR_BYTES) {
    throw new WifError(
      `Falcon-512 WIF payload must be ${FALCON512_KEYPAIR_BYTES} bytes, got ${payload.length}`,
    );
  }
  const privateKey = payload.slice(0, FALCON512_PRIVATE_KEY_BYTES);
  const publicKey = payload.slice(FALCON512_PRIVATE_KEY_BYTES);

  const sig = await falcon512Sign(PAIR_CHECK_MESSAGE, privateKey);
  const ok = await falcon512Verify(sig, PAIR_CHECK_MESSAGE, publicKey);
  if (!ok) {
    privateKey.fill(0);
    throw new WifError(
      'The Falcon-512 private key does not match its embedded public key.',
    );
  }
  return { privateKey, publicKey };
}

// The algorithms a payload length admits, mirroring the node's pk_alg():
// every module whose is_valid_pk() accepts the length, ascending algo id.
function candidatesFor(payload: Uint8Array): readonly Algorithm[] {
  if (payload.length === PRIVATE_KEY_BYTES) {
    if (!isValidPrivateKey(payload)) {
      throw new WifError(
        'The 32-byte payload is not a valid secp256k1 private key.',
      );
    }
    return ['ecdsa', 'schnorr'];
  }
  if (payload.length === FALCON512_KEYPAIR_BYTES) {
    return ['falcon512'];
  }
  if (
    payload.length === PRIVATE_KEY_BYTES + 1 &&
    payload[PRIVATE_KEY_BYTES] === 0x01
  ) {
    throw new WifError(
      'This looks like a Bitcoin compressed-key WIF (trailing 0x01 flag). ' +
        'This chain\'s WIF carries the raw 32-byte key with no flag.',
    );
  }
  throw new WifError(
    `Unsupported private-key payload: ${payload.length} bytes (expected ${PRIVATE_KEY_BYTES} or ${FALCON512_KEYPAIR_BYTES}).`,
  );
}
