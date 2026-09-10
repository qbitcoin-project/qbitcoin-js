// transaction model + serialization.
//
//
// Scope:
//   - TX_TYPE_STANDARD and TX_TYPE_TOKENS transfers — no coinbase, no stake,
//     no token creation / MINT
//   - SIGHASH_ALL only — no NONE / SINGLE / ANYONECANPAY
//   - The single classical script type seen on mainnet: P2PK
//
// All multi-byte numeric fields are little-endian.

import { SIGHASH } from './constants';
import { decodeVarint, encodeVarint } from './encoding/varint';
import { decodeVarstr, encodeVarstr } from './encoding/varstr';
import { hash256 } from './hashes';

/** TX_TYPE numeric values from the node. */
export const TX_TYPE_STANDARD = 1;
export const TX_TYPE_TOKENS = 4;

/** Token output `data` tag for a spendable transfer (the node's token
 *  output types). A TRANSFER `data` is exactly `0x01 + uint64LE amount`. */
export const TOKEN_TXO_TYPE_TRANSFER = 0x01;

/** A token id (= its creation-tx hash) is 32 bytes, used as-is (no reversal)
 * for the `varstr(token_hash)` prefix. */
export const TOKEN_HASH_BYTES = 32;

/**
 * Reference to a previously-mined transaction output, plus (after
 * signing) the witness data that unlocks it.
 *
 *  - `txid`:    32-byte SHA-256d hash of the funding transaction.
 *  - `vout`:    Index of the output within that transaction.
 *  - `siglist`: After signing, holds one or more byte strings (sig,
 *               possibly + pubkey for P2PKH). For P2PK each siglist
 *               entry is `[sighash_type:1][algo:1][raw_sig:variable]`.
 *  - `redeemScript`: The P2PK script `pushdata(pubkey) || OP_CHECKSIG`.
 */
export interface TxInput {
  readonly txid: Uint8Array;
  readonly vout: number;
  readonly siglist?: ReadonlyArray<Uint8Array>;
  readonly redeemScript?: Uint8Array;
}

/**
 * A spending destination.
 *
 *  - `value`:      Atomic units (1 coin = 10^8). `bigint` to safely
 *                  represent uint64 sums above Number.MAX_SAFE_INTEGER.
 *  - `scripthash`: 20 bytes for classical destinations, 32 bytes for PQ.
 *  - `data`:       Optional opaque payload (token transfers etc.). For
 *                  standard sends this is empty.
 */
export interface TxOutput {
  readonly value: bigint;
  readonly scripthash: Uint8Array;
  readonly data?: Uint8Array;
}

/** An transaction skeleton (standard or token transfer). */
export interface Transaction {
  readonly txType: typeof TX_TYPE_STANDARD | typeof TX_TYPE_TOKENS;
  readonly inputs: ReadonlyArray<TxInput>;
  readonly outputs: ReadonlyArray<TxOutput>;
  /**
   * For TX_TYPE_TOKENS transfers: the 32-byte token id, used as-is (the REST
   * `token_id` bytes — no reversal, unlike txid). Encoded as a `varstr`
   * prefix in `serialize` only; the sighash never covers it
   * Omitted for standard txs.
   */
  readonly tokenHash?: Uint8Array;
}

const TXID_BYTES = 32;
const VALUE_BYTES = 8;

// ─── Serialization for sighash (no signatures present) ────────────────

/**
 * Build the byte string that is double-SHA256-hashed to produce the
 * digest each input signs. For `SIGHASH_ALL` (the only mode we support)
 * the output is the same for every input of a given transaction.
 *
 * Layout (sign_data, SIGHASH_ALL branch):
 *
 *   tx_type (1)
 *   varint(num_inputs)
 *   for each input: txid(32) + varint(vout)
 *   varint(num_outputs)
 *   for each output: value(8 LE) + varstr(scripthash) + varstr(data)
 *
 * Note: input siglist and redeem_script are NOT included — this is the
 * intentional simplification that makes signing fast (no need to mutate
 * the tx between input signings) and matches the node.
 */
export function serializeForSighash(
  tx: Transaction,
  sighashType: number = SIGHASH.ALL,
  commitsTokenId?: boolean,
): Uint8Array {
  if (sighashType !== SIGHASH.ALL) {
    // NONE / SINGLE / ANYONECANPAY aren't implemented. Document the
    // restriction explicitly rather than silently producing wrong bytes.
    throw new RangeError(
      `serializeForSighash: only SIGHASH_ALL is supported, got ${sighashType}`,
    );
  }

  const parts: Uint8Array[] = [];
  parts.push(new Uint8Array([tx.txType]));
  parts.push(encodeVarint(tx.inputs.length));
  for (const input of tx.inputs) {
    parts.push(serializeInputForSign(input));
  }
  parts.push(encodeVarint(tx.outputs.length));
  for (const output of tx.outputs) {
    parts.push(serializeOutput(output));
  }
  // Past the chain's token-sighash fork (`profile.tokenSighashFork`, a
  // chain value), a token transfer signs its token id too — appended RAW (32
  // bytes, no varstr prefix, unlike the wire form), after the outputs.
  // Without it a signature would be valid for the same movement of ANY
  // token; BEFORE the fork the node rejects sign data that includes it.
  // This layer knows neither network nor time, so a token transfer demands
  // the verdict explicitly — sighashCommitsTokenId(network) at signing time.
  if (tx.txType === TX_TYPE_TOKENS) {
    if (commitsTokenId === undefined) {
      throw new RangeError(
        'serializeForSighash: a token transfer needs an explicit commitsTokenId (pass sighashCommitsTokenId(network))',
      );
    }
    if (commitsTokenId) {
      parts.push(tokenHashPrefix(tx.tokenHash));
    }
  }
  return concat(parts);
}

/**
 * Compute the 32-byte sighash digest fed to the signing algorithm.
 *
 * `hash256(sign_data) = SHA-256(SHA-256(sign_data))`.
 */
export function sighash(
  tx: Transaction,
  sighashType: number = SIGHASH.ALL,
  commitsTokenId?: boolean,
): Uint8Array {
  return hash256(serializeForSighash(tx, sighashType, commitsTokenId));
}

// ─── Full serialization (with signatures) ────────────────────────────

/**
 * Build the on-the-wire serialized transaction, including signatures
 * and redeem scripts. This is what gets broadcast via `sendrawtransaction`
 * and what `txid()` hashes.
 *
 * Layout (wire serialization, standard tx):
 *
 *   tx_type (1)
 *   varint(num_inputs)
 *   for each input: txid(32) + varint(vout)
 *                 + varint(siglist_n) + varstr(sig1) + … + varstr(sigN)
 *                 + varstr(redeem_script)
 *   varint(num_outputs)
 *   for each output: value(8 LE) + varstr(scripthash) + varstr(data)
 *
 * Throws if any input is missing its `siglist` or `redeemScript` — call
 * `signTransaction` (in signing.ts) first to fill them in.
 */
export function serialize(tx: Transaction): Uint8Array {
  const parts: Uint8Array[] = [];
  parts.push(new Uint8Array([tx.txType]));
  // Token transfers carry a varstr(token_hash) prefix right after the type
  // byte on the wire; the sighash appends the RAW hash after the outputs
  // instead — and only past the chain's token-sighash fork (see
  // serializeForSighash and TOKEN_SIGHASH_FORK).
  if (tx.txType === TX_TYPE_TOKENS) {
    parts.push(encodeVarstr(tokenHashPrefix(tx.tokenHash)));
  }
  parts.push(encodeVarint(tx.inputs.length));
  for (let i = 0; i < tx.inputs.length; i++) {
    parts.push(serializeInputFull(tx.inputs[i]!, i));
  }
  parts.push(encodeVarint(tx.outputs.length));
  for (const output of tx.outputs) {
    parts.push(serializeOutput(output));
  }
  return concat(parts);
}

/**
 * The transaction id: `hash256(serialize(tx))`. Matches Bitcoin's
 * pre-segwit txid (and The chain uses no segwit-style separation).
 */
export function txid(tx: Transaction): Uint8Array {
  return hash256(serialize(tx));
}

/**
 * Parse a wire-serialized transaction back into the model — the exact
 * inverse of `serialize`. The wallet uses it to read outputs (a covenant
 * output's `data` in particular) from the node's raw-hex endpoint when the
 * JSON view does not carry them.
 *
 * Only the layouts `serialize` can produce are accepted: TX_TYPE_STANDARD
 * and TX_TYPE_TOKENS. Other types carry type-specific payloads this module
 * does not know, and misreading them would yield garbage offsets — refuse
 * loudly instead. Trailing bytes and truncation are errors too.
 */
export function deserialize(raw: Uint8Array): Transaction {
  let at = 0;
  const uint = (what: string): number => {
    const { value, bytesRead } = decodeVarint(raw, at);
    if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new RangeError(`deserialize: ${what} ${value} exceeds safe integer range`);
    }
    at += bytesRead;
    return Number(value);
  };
  const str = (): Uint8Array => {
    const { bytes, bytesRead } = decodeVarstr(raw, at);
    at += bytesRead;
    return bytes;
  };
  const take = (n: number, what: string): Uint8Array => {
    if (at + n > raw.length) {
      throw new RangeError(`deserialize: truncated ${what} at offset ${at}`);
    }
    const out = raw.subarray(at, at + n);
    at += n;
    return out;
  };

  const txType = take(1, 'tx type')[0]!;
  if (txType !== TX_TYPE_STANDARD && txType !== TX_TYPE_TOKENS) {
    throw new RangeError(`deserialize: unsupported tx type ${txType}`);
  }
  const tokenHash = txType === TX_TYPE_TOKENS ? tokenHashPrefix(str()) : undefined;

  const inputs: TxInput[] = [];
  const inputCount = uint('input count');
  for (let i = 0; i < inputCount; i++) {
    const txidBytes = take(32, `input ${i} txid`);
    const vout = uint(`input ${i} vout`);
    const siglist: Uint8Array[] = [];
    const sigCount = uint(`input ${i} siglist length`);
    for (let s = 0; s < sigCount; s++) siglist.push(str());
    const redeemScript = str();
    inputs.push({ txid: txidBytes, vout, siglist, redeemScript });
  }

  const outputs: TxOutput[] = [];
  const outputCount = uint('output count');
  for (let i = 0; i < outputCount; i++) {
    const valueBytes = take(8, `output ${i} value`);
    const value = new DataView(valueBytes.buffer, valueBytes.byteOffset, 8).getBigUint64(0, true);
    const scripthash = str();
    if (scripthash.length !== 20 && scripthash.length !== 32) {
      throw new RangeError(`deserialize: output ${i} scripthash must be 20 or 32 bytes, got ${scripthash.length}`);
    }
    const data = str();
    outputs.push({ value, scripthash, ...(data.length > 0 ? { data } : {}) });
  }

  if (at !== raw.length) {
    throw new RangeError(`deserialize: ${raw.length - at} trailing bytes after the outputs`);
  }
  return { txType, ...(tokenHash !== undefined ? { tokenHash } : {}), inputs, outputs };
}

// ─── Token helpers ───────────────────────────────────────────────────

/**
 * Encode a token TRANSFER output `data`: `0x01 + uint64LE amount` (exactly 9
 * bytes). The output's native `value` is 0; the token movement is this data.
 */
export function encodeTokenTransfer(amount: bigint): Uint8Array {
  if (amount < 0n) {
    throw new RangeError(`Token amount must be non-negative, got ${amount}`);
  }
  if (amount > 0xffffffffffffffffn) {
    throw new RangeError(`Token amount exceeds uint64 max: ${amount}`);
  }
  const out = new Uint8Array(9);
  out[0] = TOKEN_TXO_TYPE_TRANSFER;
  new DataView(out.buffer).setBigUint64(1, amount, true);
  return out;
}

// ─── Internal helpers ────────────────────────────────────────────────

/** Validate the token_hash prefix bytes: 32 (transfer) or empty (create). */
function tokenHashPrefix(tokenHash: Uint8Array | undefined): Uint8Array {
  const h = tokenHash ?? new Uint8Array(0);
  if (h.length !== 0 && h.length !== TOKEN_HASH_BYTES) {
    throw new RangeError(
      `token_hash must be ${TOKEN_HASH_BYTES} bytes (transfer) or empty (create), got ${h.length}`,
    );
  }
  return h;
}

function serializeInputForSign(input: TxInput): Uint8Array {
  assertTxid(input.txid);
  return concat([input.txid, encodeVarint(input.vout)]);
}

function serializeInputFull(input: TxInput, index: number): Uint8Array {
  assertTxid(input.txid);
  if (!input.siglist) {
    throw new Error(`Input ${index}: missing siglist (sign the transaction first)`);
  }
  if (!input.redeemScript) {
    throw new Error(`Input ${index}: missing redeemScript`);
  }
  const parts: Uint8Array[] = [
    input.txid,
    encodeVarint(input.vout),
    encodeVarint(input.siglist.length),
  ];
  for (const sig of input.siglist) {
    parts.push(encodeVarstr(sig));
  }
  parts.push(encodeVarstr(input.redeemScript));
  return concat(parts);
}

function serializeOutput(output: TxOutput): Uint8Array {
  if (output.value < 0n) {
    throw new RangeError(`Output value must be non-negative, got ${output.value}`);
  }
  if (output.value > 0xffffffffffffffffn) {
    throw new RangeError(`Output value exceeds uint64 max: ${output.value}`);
  }
  if (
    output.scripthash.length !== 20 &&
    output.scripthash.length !== 32
  ) {
    throw new RangeError(
      `Output scripthash must be 20 or 32 bytes, got ${output.scripthash.length}`,
    );
  }

  const valueBuf = new Uint8Array(VALUE_BYTES);
  new DataView(valueBuf.buffer).setBigUint64(0, output.value, true);
  return concat([
    valueBuf,
    encodeVarstr(output.scripthash),
    encodeVarstr(output.data ?? new Uint8Array(0)),
  ]);
}

function assertTxid(txid: Uint8Array): void {
  if (txid.length !== TXID_BYTES) {
    throw new RangeError(`txid must be ${TXID_BYTES} bytes, got ${txid.length}`);
  }
}

function concat(parts: ReadonlyArray<Uint8Array>): Uint8Array {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
