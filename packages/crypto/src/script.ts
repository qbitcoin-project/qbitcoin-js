// Bitcoin-script primitives needed to build redeem scripts for the
// wallet.
//
// The wallet only constructs **P2PK** scripts — that's what the node
// generates by default (confirmed from a live mempool dump:
// `21 <33-byte pubkey> ac`). P2PKH and multisig support is out of scope
// until the network actually starts using them.

// ─── Opcodes we use ──────────────────────────────────────────────────

export const OP_DUP = 0x76;
export const OP_EQUALVERIFY = 0x88;
export const OP_HASH160 = 0xa9;
export const OP_HASH256 = 0xaa;
export const OP_CHECKSIG = 0xac;
export const OP_PUSHDATA1 = 0x4c;
export const OP_PUSHDATA2 = 0x4d;
export const OP_PUSHDATA4 = 0x4e;

// ─── Pushdata encoding ────────────────────────────────────────────────

const MAX_INLINE_PUSH = 75; // bytes pushable with a single-byte length prefix

/**
 * Encode `data` as a Bitcoin script push, choosing the smallest opcode
 * that fits. Used internally by `scriptP2PK`; exported because address
 * derivation tests check intermediate values.
 *
 * Output is `prefix || data` where `prefix` is one of:
 *   - single byte `length` (1..75)
 *   - `OP_PUSHDATA1 (0x4c)` + 1-byte length
 *   - `OP_PUSHDATA2 (0x4d)` + 2-byte LE length
 *   - `OP_PUSHDATA4 (0x4e)` + 4-byte LE length
 *
 * Throws `RangeError` for payloads exceeding 2^32 - 1 bytes (which
 * blockchain protocols never allow anyway).
 */
export function opPushdata(data: Uint8Array): Uint8Array {
  const len = data.length;

  if (len <= MAX_INLINE_PUSH) {
    const out = new Uint8Array(1 + len);
    out[0] = len;
    out.set(data, 1);
    return out;
  }
  if (len <= 0xff) {
    const out = new Uint8Array(2 + len);
    out[0] = OP_PUSHDATA1;
    out[1] = len;
    out.set(data, 2);
    return out;
  }
  if (len <= 0xffff) {
    const out = new Uint8Array(3 + len);
    out[0] = OP_PUSHDATA2;
    new DataView(out.buffer).setUint16(1, len, true);
    out.set(data, 3);
    return out;
  }
  if (len <= 0xffffffff) {
    const out = new Uint8Array(5 + len);
    out[0] = OP_PUSHDATA4;
    new DataView(out.buffer).setUint32(1, len, true);
    out.set(data, 5);
    return out;
  }
  throw new RangeError(`Pushdata too large: ${len} bytes`);
}

// ─── Standard script constructors ─────────────────────────────────────

/**
 * Build a P2PK redeem script:  `pushdata(pubkey) || OP_CHECKSIG`.
 *
 * For ECDSA secp256k1 the pubkey is 33 bytes (compressed), giving a
 * 35-byte script:  `21 <33 bytes> ac`.
 *
 * For Falcon-512 the pubkey is 897 bytes, giving a 901-byte script:
 *  `4d 8103 <897 bytes> ac`  (OP_PUSHDATA2 + length).
 */
export function scriptP2PK(pubkey: Uint8Array): Uint8Array {
  const push = opPushdata(pubkey);
  const out = new Uint8Array(push.length + 1);
  out.set(push, 0);
  out[push.length] = OP_CHECKSIG;
  return out;
}

// ─── Script type detection ────────────────────────────────────────────

export type ScriptType = 'P2PK' | 'P2PKH' | 'unknown';

/**
 * Classify a redeem script by its leading byte. Matches the node's
 * redeem-script type detection — a simple heuristic
 * sufficient for current network usage.
 *
 *   P2PKH:  OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
 *   P2PK:   <pubkey> OP_CHECKSIG
 */
export function scriptType(script: Uint8Array): ScriptType {
  if (script.length === 0) return 'unknown';
  return script[0] === OP_DUP ? 'P2PKH' : 'P2PK';
}
