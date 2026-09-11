// The federated P2SH-P2WSH multisig — the BTC-side deposit/pool address of
// the upgrade path. Byte-exact port of the node's lock-script constructors:
//
//   witnessScript = OP_m <33:pk> … <33:pk> OP_n OP_CHECKMULTISIG
//                   (keys in BIP67 order = bytewise lexicographic)
//   redeemScript  = OP_0 <32: sha256(witnessScript)>      (P2WSH program)
//   scriptPubKey  = OP_HASH160 <20: hash160(redeemScript)> OP_EQUAL
//   address       = base58check(P2SH version ‖ hash160(redeemScript))
//
// Spending it under BIP141 forces the input's scriptSig to be exactly one
// push of the redeemScript — the node uses that constant as the SPV-provable
// pool-spend marker. The wallet needs only the DEPOSIT side: the script to
// detect/compose payments and the address to display.

import { hash160, sha256 } from '../hashes.js';
import { btcP2shAddress, type BtcNetwork } from './address.js';

const OP_HASH160 = 0xa9;
const OP_EQUAL = 0x87;
const OP_CHECKMULTISIG = 0xae;
/** OP_1..OP_16 are 0x51..0x60: OP_N = SMALLNUM_BASE + N. */
const SMALLNUM_BASE = 0x50;
const COMPRESSED_PUBKEY_BYTES = 33;

export interface BtcMultisigLock {
  /** The m-of-n CHECKMULTISIG script the witness must satisfy. */
  readonly witnessScript: Uint8Array;
  /** The P2WSH program (0x00 0x20 sha256(witnessScript)) — also the exact
   *  scriptSig push a pool spend must carry. */
  readonly redeemScript: Uint8Array;
  /** What a deposit pays: OP_HASH160 <hash160(redeemScript)> OP_EQUAL. */
  readonly scriptPubKey: Uint8Array;
  /** Base58Check P2SH address of that scriptPubKey. */
  readonly address: string;
}

/**
 * Build the m-of-n P2SH-P2WSH lock for a set of compressed pubkeys. Key
 * order does not matter — the witnessScript sorts them (BIP67), exactly as
 * the node does, so the same key set always yields the same address.
 */
export function btcP2shP2wshMultisig(
  m: number,
  pubkeys: readonly Uint8Array[],
  network: BtcNetwork,
): BtcMultisigLock {
  const n = pubkeys.length;
  if (!Number.isInteger(m) || m < 1 || m > n || n > 16) {
    throw new RangeError(`invalid multisig shape: ${m}-of-${n}`);
  }
  for (const pk of pubkeys) {
    if (pk.length !== COMPRESSED_PUBKEY_BYTES) {
      throw new RangeError(`multisig pubkeys must be ${COMPRESSED_PUBKEY_BYTES} bytes compressed, got ${pk.length}`);
    }
  }
  const sorted = [...pubkeys].sort(compareBytes);
  const witnessScript = new Uint8Array(1 + n * (1 + COMPRESSED_PUBKEY_BYTES) + 2);
  let at = 0;
  witnessScript[at++] = SMALLNUM_BASE + m;
  for (const pk of sorted) {
    witnessScript[at++] = COMPRESSED_PUBKEY_BYTES;
    witnessScript.set(pk, at);
    at += COMPRESSED_PUBKEY_BYTES;
  }
  witnessScript[at++] = SMALLNUM_BASE + n;
  witnessScript[at++] = OP_CHECKMULTISIG;

  const redeemScript = new Uint8Array(2 + 32);
  redeemScript[0] = 0x00; // OP_0: witness version
  redeemScript[1] = 0x20; // push of the 32-byte program
  redeemScript.set(sha256(witnessScript), 2);

  const scriptHash = hash160(redeemScript);
  const scriptPubKey = new Uint8Array(2 + 20 + 1);
  scriptPubKey[0] = OP_HASH160;
  scriptPubKey[1] = 20;
  scriptPubKey.set(scriptHash, 2);
  scriptPubKey[22] = OP_EQUAL;

  return {
    witnessScript,
    redeemScript,
    scriptPubKey,
    address: btcP2shAddress(scriptHash, network),
  };
}

/** Bytewise lexicographic order — BIP67, and how the node sorts the keys. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) {
    if (a[i]! !== b[i]!) return a[i]! - b[i]!;
  }
  return a.length - b.length;
}
