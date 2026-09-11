// Bitcoin address encoding/decoding for the upgrade flow.
//
// Two jobs only:
//   - ENCODE the wallet's own legacy P2PKH staging address (base58check,
//     version 0x00/0x6f) — what the user funds from anywhere;
//   - DECODE an arbitrary user-supplied Bitcoin address into its
//     scriptPubKey for the "Return BTC" action (legacy P2PKH/P2SH plus
//     bech32/bech32m segwit v0/v1).
//
// Chain-generic Bitcoin, no chain-specific values.

import { decodeBase58Check, encodeBase58Check } from '../encoding/base58check.js';
import { hash160 } from '../hashes.js';

export type BtcNetwork = 'mainnet' | 'testnet';

const P2PKH_VERSION: Record<BtcNetwork, number> = { mainnet: 0x00, testnet: 0x6f };
const P2SH_VERSION: Record<BtcNetwork, number> = { mainnet: 0x05, testnet: 0xc4 };
const BECH32_HRP: Record<BtcNetwork, string> = { mainnet: 'bc', testnet: 'tb' };

/** Legacy P2PKH address ("1…" / testnet "m/n…") for a 20-byte pubkeyhash. */
export function btcP2pkhAddress(pubkeyhash: Uint8Array, network: BtcNetwork): string {
  if (pubkeyhash.length !== 20) {
    throw new RangeError(`pubkeyhash must be 20 bytes, got ${pubkeyhash.length}`);
  }
  return encodeBase58Check(Uint8Array.of(P2PKH_VERSION[network]), pubkeyhash);
}

/** Encode a P2SH address from a 20-byte script hash (hash160 of the redeem
 *  script) — the address form of the federated upgrade lock. */
export function btcP2shAddress(scripthash: Uint8Array, network: BtcNetwork): string {
  if (scripthash.length !== 20) {
    throw new RangeError(`script hash must be 20 bytes, got ${scripthash.length}`);
  }
  return encodeBase58Check(Uint8Array.of(P2SH_VERSION[network]), scripthash);
}

/** Legacy P2PKH address for a compressed public key. */
export function btcP2pkhAddressForPubkey(pubkey: Uint8Array, network: BtcNetwork): string {
  return btcP2pkhAddress(hash160(pubkey), network);
}

/**
 * The inverse of decodeBtcAddress, for DISPLAY: decode a scriptPubKey into
 * the address it pays when the script is one of the standard templates
 * (P2PKH, P2SH, segwit v0/v1). Undefined for anything nonstandard — the
 * caller shows the raw hex then. Used by the downgrade card, which knows
 * only the payout scriptPubKey the freeze output committed to.
 */
export function btcAddressFromScriptPubKey(
  script: Uint8Array,
  network: BtcNetwork,
): string | undefined {
  // P2PKH: OP_DUP OP_HASH160 <20> OP_EQUALVERIFY OP_CHECKSIG
  if (
    script.length === 25 &&
    script[0] === 0x76 && script[1] === 0xa9 && script[2] === 0x14 &&
    script[23] === 0x88 && script[24] === 0xac
  ) {
    return encodeBase58Check(Uint8Array.of(P2PKH_VERSION[network]), script.subarray(3, 23));
  }
  // P2SH: OP_HASH160 <20> OP_EQUAL
  if (script.length === 23 && script[0] === 0xa9 && script[1] === 0x14 && script[22] === 0x87) {
    return encodeBase58Check(Uint8Array.of(P2SH_VERSION[network]), script.subarray(2, 22));
  }
  // Segwit: OP_0 <20|32> (v0) or OP_1 <32> (v1 taproot)
  if (script.length >= 2 && script[1] === script.length - 2) {
    const program = script.subarray(2);
    if (script[0] === 0x00 && (program.length === 20 || program.length === 32)) {
      return bech32Encode(BECH32_HRP[network], [0, ...toWords(program)], 'bech32');
    }
    if (script[0] === 0x51 && program.length === 32) {
      return bech32Encode(BECH32_HRP[network], [1, ...toWords(program)], 'bech32m');
    }
  }
  return undefined;
}

export type BtcAddressKind = 'p2pkh' | 'p2sh' | 'v0_p2wpkh' | 'v0_p2wsh' | 'v1_p2tr';

export interface DecodedBtcAddress {
  readonly kind: BtcAddressKind;
  readonly scriptPubKey: Uint8Array;
}

/**
 * Decode a Bitcoin address into the scriptPubKey to pay it. Throws a
 * descriptive Error for anything unrecognized — the caller surfaces it as
 * a validation message.
 */
export function decodeBtcAddress(address: string, network: BtcNetwork): DecodedBtcAddress {
  // Route anything that LOOKS like bech32 for a known Bitcoin hrp through
  // the segwit decoder, so a wrong-network paste gets the helpful
  // "different network" error instead of a base58 complaint.
  if (/^(bc|tb)1/i.test(address)) {
    return decodeSegwit(address, network);
  }
  return decodeLegacy(address, network);
}

function decodeLegacy(address: string, network: BtcNetwork): DecodedBtcAddress {
  let version: number;
  let payload: Uint8Array;
  try {
    const decoded = decodeBase58Check(address, 1);
    version = decoded.version[0]!;
    payload = decoded.payload;
  } catch (e) {
    throw new Error(`Not a valid Bitcoin address: ${(e as Error).message}`);
  }
  if (payload.length !== 20) {
    throw new Error(`Unexpected legacy payload length: ${payload.length}`);
  }
  if (version === P2PKH_VERSION[network]) {
    const s = new Uint8Array(25);
    s.set([0x76, 0xa9, 0x14], 0);
    s.set(payload, 3);
    s.set([0x88, 0xac], 23);
    return { kind: 'p2pkh', scriptPubKey: s };
  }
  if (version === P2SH_VERSION[network]) {
    const s = new Uint8Array(23);
    s.set([0xa9, 0x14], 0);
    s.set(payload, 2);
    s[22] = 0x87;
    return { kind: 'p2sh', scriptPubKey: s };
  }
  throw new Error(`Unknown Bitcoin address version 0x${version.toString(16)} for ${network}`);
}

function decodeSegwit(address: string, network: BtcNetwork): DecodedBtcAddress {
  const { hrp, values, spec } = bech32Decode(address);
  if (hrp !== BECH32_HRP[network]) {
    throw new Error(`Address is for a different network (hrp "${hrp}")`);
  }
  if (values.length < 1) throw new Error('Empty witness section');
  const version = values[0]!;
  const program = fromWords(values.slice(1));
  if (version === 0) {
    if (spec !== 'bech32') throw new Error('Witness v0 must use bech32 (not bech32m)');
    if (program.length === 20) return { kind: 'v0_p2wpkh', scriptPubKey: witnessScript(0, program) };
    if (program.length === 32) return { kind: 'v0_p2wsh', scriptPubKey: witnessScript(0, program) };
    throw new Error(`Witness v0 program must be 20 or 32 bytes, got ${program.length}`);
  }
  if (version === 1) {
    if (spec !== 'bech32m') throw new Error('Witness v1 must use bech32m');
    if (program.length !== 32) throw new Error(`Taproot program must be 32 bytes, got ${program.length}`);
    return { kind: 'v1_p2tr', scriptPubKey: witnessScript(1, program) };
  }
  throw new Error(`Unsupported witness version ${version}`);
}

/** `OP_n <program>` — the scriptPubKey of a segwit output. */
function witnessScript(version: 0 | 1, program: Uint8Array): Uint8Array {
  const s = new Uint8Array(2 + program.length);
  s[0] = version === 0 ? 0x00 : 0x50 + version; // OP_0 / OP_1
  s[1] = program.length;
  s.set(program, 2);
  return s;
}

// ── bech32 / bech32m (BIP-173 / BIP-350) ───────────────────────────────

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const GENERATORS = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const BECH32M_CONST = 0x2bc830a3;

function polymod(values: readonly number[]): number {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= GENERATORS[i]!;
    }
  }
  return chk >>> 0;
}

function hrpExpand(hrp: string): number[] {
  const out: number[] = [];
  for (const c of hrp) out.push(c.charCodeAt(0) >>> 5);
  out.push(0);
  for (const c of hrp) out.push(c.charCodeAt(0) & 31);
  return out;
}

function bech32Decode(address: string): {
  hrp: string;
  values: number[];
  spec: 'bech32' | 'bech32m';
} {
  const hasLower = /[a-z]/.test(address);
  const hasUpper = /[A-Z]/.test(address);
  if (hasLower && hasUpper) throw new Error('Mixed-case bech32 string');
  const s = address.toLowerCase();
  const sep = s.lastIndexOf('1');
  if (sep < 1 || sep + 7 > s.length || s.length > 90) {
    throw new Error('Malformed bech32 string');
  }
  const hrp = s.slice(0, sep);
  const values: number[] = [];
  for (const c of s.slice(sep + 1)) {
    const v = CHARSET.indexOf(c);
    if (v === -1) throw new Error(`Invalid bech32 character "${c}"`);
    values.push(v);
  }
  const check = polymod([...hrpExpand(hrp), ...values]);
  let spec: 'bech32' | 'bech32m';
  if (check === 1) spec = 'bech32';
  else if (check === BECH32M_CONST) spec = 'bech32m';
  else throw new Error('Bad bech32 checksum');
  return { hrp, values: values.slice(0, -6), spec };
}

/** Encode (used by tests to round-trip; the wallet itself only decodes). */
export function bech32Encode(
  hrp: string,
  values: readonly number[],
  spec: 'bech32' | 'bech32m',
): string {
  const target = spec === 'bech32' ? 1 : BECH32M_CONST;
  const data = [...values, 0, 0, 0, 0, 0, 0];
  const mod = polymod([...hrpExpand(hrp), ...data]) ^ target;
  const checksum: number[] = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return `${hrp}1${[...values, ...checksum].map((v) => CHARSET[v]).join('')}`;
}

/** 5-bit groups → bytes (strict: no illegal padding). */
function fromWords(words: readonly number[]): Uint8Array {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const w of words) {
    acc = (acc << 5) | w;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      out.push((acc >>> bits) & 0xff);
    }
  }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xff) !== 0) {
    throw new Error('Invalid bech32 data padding');
  }
  return new Uint8Array(out);
}

/** Bytes → 5-bit groups (test helper for round-trips). */
export function toWords(bytes: Uint8Array): number[] {
  let acc = 0;
  let bits = 0;
  const out: number[] = [];
  for (const b of bytes) {
    acc = (acc << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >>> bits) & 31);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
}
