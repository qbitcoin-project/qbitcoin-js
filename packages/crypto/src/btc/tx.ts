// Bitcoin transaction construction for the upgrade flow (BTC → native).
//
// Deliberately minimal: the wallet only ever SPENDS ITS OWN legacy P2PKH
// staging outputs into the chain's upgrade transaction (lock output +
// OP_RETURN commitment, optional change). That means:
//
//   - legacy (pre-segwit) serialization only — no witness anywhere;
//   - SIGHASH_ALL only;
//   - single signing key per transaction (one staging key per episode).
//
// Kept chain-generic: nothing here knows the lock address or payload
// format — those are chain parameters supplied by the caller (see
// `UpgradeChainConfig` in the ChainProfile). This module is plain Bitcoin.

import { encodeVarint } from '../encoding/varint';
import { fromHex, toHex } from '../encoding/hex';
import { hash160, hash256 } from '../hashes';
import { getPublicKey, sign } from '../secp256k1';

/** An unspent output reference. `txid` is display order (big-endian hex). */
export interface BtcOutPoint {
  readonly txid: string;
  readonly vout: number;
}

export interface BtcTxInput {
  readonly prevout: BtcOutPoint;
  /** Unlocking script. Empty until signed. */
  readonly scriptSig: Uint8Array;
  readonly sequence: number;
}

export interface BtcTxOutput {
  /** Value in satoshi. */
  readonly value: bigint;
  readonly scriptPubKey: Uint8Array;
}

export interface BtcTransaction {
  readonly version: number;
  readonly inputs: readonly BtcTxInput[];
  readonly outputs: readonly BtcTxOutput[];
  readonly locktime: number;
}

/** Opt-in RBF: any sequence below 0xfffffffe signals replaceability. */
export const BTC_RBF_SEQUENCE = 0xfffffffd;

/** The only sighash mode this module emits. */
export const BTC_SIGHASH_ALL = 0x01;

const OP_DUP = 0x76;
const OP_HASH160 = 0xa9;
const OP_EQUALVERIFY = 0x88;
const OP_CHECKSIG = 0xac;
const OP_RETURN = 0x6a;

const HASH160_LEN = 20;
/** Bitcoin standardness cap for a single OP_RETURN datum push. */
const OP_RETURN_MAX = 75;

/** `OP_DUP OP_HASH160 <pubkeyhash> OP_EQUALVERIFY OP_CHECKSIG` */
export function scriptBtcP2pkh(pubkeyhash: Uint8Array): Uint8Array {
  if (pubkeyhash.length !== HASH160_LEN) {
    throw new RangeError(
      `P2PKH pubkeyhash must be ${HASH160_LEN} bytes, got ${pubkeyhash.length}`,
    );
  }
  const out = new Uint8Array(5 + HASH160_LEN);
  out[0] = OP_DUP;
  out[1] = OP_HASH160;
  out[2] = HASH160_LEN;
  out.set(pubkeyhash, 3);
  out[3 + HASH160_LEN] = OP_EQUALVERIFY;
  out[4 + HASH160_LEN] = OP_CHECKSIG;
  return out;
}

/** `OP_RETURN <push payload>` — a zero-value data commitment output. */
export function scriptBtcOpReturn(payload: Uint8Array): Uint8Array {
  if (payload.length < 1 || payload.length > OP_RETURN_MAX) {
    throw new RangeError(
      `OP_RETURN payload must be 1..${OP_RETURN_MAX} bytes, got ${payload.length}`,
    );
  }
  const out = new Uint8Array(2 + payload.length);
  out[0] = OP_RETURN;
  out[1] = payload.length;
  out.set(payload, 2);
  return out;
}

/** P2PKH scriptPubKey for a compressed pubkey's hash160. */
export function scriptBtcP2pkhForPubkey(pubkey: Uint8Array): Uint8Array {
  return scriptBtcP2pkh(hash160(pubkey));
}

// ── Serialization (legacy, no witness) ─────────────────────────────────

class ByteWriter {
  private chunks: Uint8Array[] = [];

  push(b: Uint8Array): void {
    this.chunks.push(b);
  }

  u32le(n: number): void {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n >>> 0, true);
    this.push(b);
  }

  u64le(n: bigint): void {
    if (n < 0n || n > 0xffffffffffffffffn) {
      throw new RangeError(`value out of uint64 range: ${n}`);
    }
    const b = new Uint8Array(8);
    new DataView(b.buffer).setBigUint64(0, n, true);
    this.push(b);
  }

  varint(n: number): void {
    this.push(encodeVarint(n));
  }

  bytes(): Uint8Array {
    const total = this.chunks.reduce((s, c) => s + c.length, 0);
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of this.chunks) {
      out.set(c, off);
      off += c.length;
    }
    return out;
  }
}

/** Display-order txid hex → the 32 little-endian bytes used on the wire. */
function txidToWire(txid: string): Uint8Array {
  const raw = fromHex(txid);
  if (raw.length !== 32) {
    throw new RangeError(`txid must be 32 bytes of hex, got ${raw.length}`);
  }
  return raw.reverse();
}

function writeTx(
  w: ByteWriter,
  tx: BtcTransaction,
  scriptSigFor: (index: number) => Uint8Array,
): void {
  w.u32le(tx.version);
  w.varint(tx.inputs.length);
  tx.inputs.forEach((input, i) => {
    w.push(txidToWire(input.prevout.txid));
    w.u32le(input.prevout.vout);
    const script = scriptSigFor(i);
    w.varint(script.length);
    w.push(script);
    w.u32le(input.sequence);
  });
  w.varint(tx.outputs.length);
  for (const out of tx.outputs) {
    w.u64le(out.value);
    w.varint(out.scriptPubKey.length);
    w.push(out.scriptPubKey);
  }
  w.u32le(tx.locktime);
}

/** Legacy serialization of the transaction as-is. */
export function serializeBtcTx(tx: BtcTransaction): Uint8Array {
  const w = new ByteWriter();
  writeTx(w, tx, (i) => tx.inputs[i]!.scriptSig);
  return w.bytes();
}

/** Display-order txid (reversed double-SHA256 of the legacy serialization). */
export function btcTxid(tx: BtcTransaction): string {
  return toHex(hash256(serializeBtcTx(tx)).reverse());
}

// ── Signing (SIGHASH_ALL, P2PKH) ───────────────────────────────────────

/**
 * Legacy SIGHASH_ALL digest for one input: the signed input's scriptSig is
 * replaced by the scriptPubKey of the output it spends, every other
 * scriptSig is empty, and the 4-byte hash type is appended before
 * double-SHA256.
 */
export function btcSighashAll(
  tx: BtcTransaction,
  inputIndex: number,
  spentScriptPubKey: Uint8Array,
): Uint8Array {
  if (inputIndex < 0 || inputIndex >= tx.inputs.length) {
    throw new RangeError(`input index ${inputIndex} out of range`);
  }
  const w = new ByteWriter();
  writeTx(w, tx, (i) => (i === inputIndex ? spentScriptPubKey : new Uint8Array(0)));
  w.u32le(BTC_SIGHASH_ALL);
  return hash256(w.bytes());
}

/** `push(sig ‖ hashtype) push(pubkey)` — the P2PKH unlocking script. */
function p2pkhScriptSig(derSig: Uint8Array, pubkey: Uint8Array): Uint8Array {
  const sigPush = derSig.length + 1; // + hash type byte
  const out = new Uint8Array(1 + sigPush + 1 + pubkey.length);
  let off = 0;
  out[off++] = sigPush;
  out.set(derSig, off);
  off += derSig.length;
  out[off++] = BTC_SIGHASH_ALL;
  out[off++] = pubkey.length;
  out.set(pubkey, off);
  return out;
}

export interface UnsignedBtcSpend {
  /** All prevouts being spent — every one must lock to `privateKey`'s P2PKH. */
  readonly prevouts: readonly BtcOutPoint[];
  readonly outputs: readonly BtcTxOutput[];
  readonly version?: number;
  readonly sequence?: number;
  readonly locktime?: number;
}

/**
 * Build and sign a P2PKH spend where EVERY input is locked to the same
 * key — the staging-episode model (one fresh key per conversion). Returns
 * the fully signed transaction; `serializeBtcTx` it for broadcast.
 *
 * The compressed pubkey is derived from `privateKey`; input[0] therefore
 * carries `push(sig) push(compressed pubkey)`, which is exactly the shape
 * the node's no-OP_RETURN fallback credits — the built-in safety net.
 */
export function signBtcP2pkhSpend(
  spend: UnsignedBtcSpend,
  privateKey: Uint8Array,
): BtcTransaction {
  if (spend.prevouts.length === 0) throw new RangeError('no inputs to spend');
  if (spend.outputs.length === 0) throw new RangeError('no outputs');
  const pubkey = getPublicKey(privateKey); // compressed (33 bytes)
  const spentScript = scriptBtcP2pkhForPubkey(pubkey);
  const sequence = spend.sequence ?? BTC_RBF_SEQUENCE;

  const unsigned: BtcTransaction = {
    version: spend.version ?? 2,
    inputs: spend.prevouts.map((prevout) => ({
      prevout,
      scriptSig: new Uint8Array(0),
      sequence,
    })),
    outputs: spend.outputs,
    locktime: spend.locktime ?? 0,
  };

  const inputs = unsigned.inputs.map((input, i) => {
    const digest = btcSighashAll(unsigned, i, spentScript);
    const der = sign(digest, privateKey);
    return { ...input, scriptSig: p2pkhScriptSig(der, pubkey) };
  });

  return { ...unsigned, inputs };
}

// ── Fee sizing ─────────────────────────────────────────────────────────

/**
 * Conservative byte-size estimate for a legacy P2PKH spend, for fee math
 * BEFORE signing (a DER signature is 70–72 bytes; we assume the worst).
 * Never underestimates; may overestimate by ~2 bytes per input.
 */
export function estimateBtcP2pkhTxSize(shape: {
  readonly inputCount: number;
  readonly p2pkhOutputCount: number;
  readonly opReturnPayloadLen?: number;
}): number {
  const overhead = 4 + 1 + 1 + 4; // version + in-count + out-count + locktime
  const perInput = 32 + 4 + 1 + 108 + 4; // prevout + script len + max scriptSig + sequence
  const perP2pkhOut = 8 + 1 + 25;
  const opReturn =
    shape.opReturnPayloadLen !== undefined
      ? 8 + 1 + 2 + shape.opReturnPayloadLen
      : 0;
  return (
    overhead +
    shape.inputCount * perInput +
    shape.p2pkhOutputCount * perP2pkhOut +
    opReturn
  );
}
