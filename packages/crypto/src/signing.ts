// Transaction signing — glues together sighash + the signature algorithms.
//
// Scope:
//   - SIGHASH_ALL only
//   - ECDSA-secp256k1, Falcon-512 (WASM), and Schnorr (BIP-340)
//
// Schnorr SIGNING is feature-gated (see features.ts): fully implemented,
// but off until cross-checked against a live node. Verification is not
// gated — incoming network data may already carry Schnorr signatures.

import { ALGO_ID, type Algorithm, SIGHASH } from './constants';
import * as falcon from './falcon512';
import { SchnorrDisabledError, isSchnorrEnabled } from './features';
import * as schnorr from './schnorr';
import { scriptP2PK } from './script';
import * as ecdsa from './secp256k1';
import { sighash, type Transaction, type TxInput } from './transaction';

/**
 * Encode a signature into a siglist entry as the node expects:
 *
 *   [sighash_type:1] [algo_id:1] [raw_sig: variable]
 *
 * `01 01 30 45 …` for SIGHASH_ALL + ECDSA, which matches every entry we
 * saw in `/api/mempool/recent`.
 */
export function encodeSiglistEntry(
  sighashType: number,
  algo: Algorithm,
  rawSig: Uint8Array,
): Uint8Array {
  if (sighashType < 0 || sighashType > 0xff) {
    throw new RangeError(`sighash_type out of byte range: ${sighashType}`);
  }
  const out = new Uint8Array(2 + rawSig.length);
  out[0] = sighashType;
  out[1] = ALGO_ID[algo];
  out.set(rawSig, 2);
  return out;
}

/**
 * Decompose a siglist entry into its parts. Inverse of `encodeSiglistEntry`.
 * Useful for verification and for inspecting received transactions.
 */
export function decodeSiglistEntry(entry: Uint8Array): {
  sighashType: number;
  algoId: number;
  rawSig: Uint8Array;
} {
  if (entry.length < 2) {
    throw new RangeError(`siglist entry too short: ${entry.length} bytes`);
  }
  return {
    sighashType: entry[0]!,
    algoId: entry[1]!,
    rawSig: entry.slice(2),
  };
}

/** Per-input data needed to sign. The caller provides one of these for
 *  each input owned by the wallet. */
export interface SigningInput {
  /** Index into `tx.inputs`. */
  readonly inputIndex: number;
  /** Raw private key for the algorithm. For ECDSA: 32 bytes. */
  readonly privateKey: Uint8Array;
  /** Public key matching `privateKey`. For ECDSA: 33-byte compressed. */
  readonly publicKey: Uint8Array;
  /** Algorithm identifier (must match the address type). */
  readonly algo: Algorithm;
}

/**
 * Produce a fully-signed copy of `tx`. Pure function: input `tx` is not
 * mutated.
 *
 * For each `SigningInput`, this function:
 *   1. Computes the sighash (same for every input under SIGHASH_ALL).
 *   2. Signs with the algorithm's signing function.
 *   3. Wraps the raw signature in the `[sighash][algo][sig]` envelope.
 *   4. Attaches the siglist and a P2PK redeem script to that input.
 *
 * Inputs without a matching `SigningInput` are left untouched.
 *
 * Async because Falcon-512 lives in a WASM module and we need to await
 * its loading on first use. ECDSA signing is itself synchronous; only
 * the Falcon path actually yields.
 */
export async function signTransaction(
  tx: Transaction,
  signers: ReadonlyArray<SigningInput>,
  sighashType: number = SIGHASH.ALL,
  // Required for token transfers: whether the sign data commits the token
  // id (sighashCommitsTokenId(network) at signing time). See transaction.ts.
  commitsTokenId?: boolean,
): Promise<Transaction> {
  if (sighashType !== SIGHASH.ALL) {
    throw new RangeError(
      `signTransaction: only SIGHASH_ALL is supported, got ${sighashType}`,
    );
  }

  const byIndex = new Map<number, SigningInput>();
  for (const signer of signers) {
    if (signer.inputIndex < 0 || signer.inputIndex >= tx.inputs.length) {
      throw new RangeError(
        `Signer references missing input index ${signer.inputIndex} (tx has ${tx.inputs.length})`,
      );
    }
    if (byIndex.has(signer.inputIndex)) {
      throw new Error(`Duplicate signer for input ${signer.inputIndex}`);
    }
    byIndex.set(signer.inputIndex, signer);
  }

  const digest = sighash(tx, sighashType, commitsTokenId);

  const inputs: TxInput[] = await Promise.all(
    tx.inputs.map(async (input, i): Promise<TxInput> => {
      const signer = byIndex.get(i);
      if (!signer) return input;

      const rawSig = await signWithAlgorithm(
        digest,
        signer.privateKey,
        signer.algo,
      );
      const siglist = [encodeSiglistEntry(sighashType, signer.algo, rawSig)];
      const redeemScript = scriptP2PK(signer.publicKey);

      return { ...input, siglist, redeemScript };
    }),
  );

  return { ...tx, inputs };
}

/**
 * Sign `digest` with the given algorithm. Dispatcher used by
 * `signTransaction`; exposed for callers that already have a digest
 * (e.g., for a provider's signMessage call).
 *
 * For protocol consistency, callers MUST pass a 32-byte digest — the
 * algorithm doesn't hash again on top. The chain's convention is
 * `hash256(sign_data)` for transaction signing.
 */
export async function signWithAlgorithm(
  digest: Uint8Array,
  privateKey: Uint8Array,
  algo: Algorithm,
): Promise<Uint8Array> {
  switch (algo) {
    case 'ecdsa':
      return ecdsa.sign(digest, privateKey);
    case 'schnorr':
      if (!isSchnorrEnabled()) throw new SchnorrDisabledError();
      return schnorr.schnorrSign(digest, privateKey);
    case 'falcon512':
      return falcon.falcon512Sign(digest, privateKey);
  }
}

/**
 * Verify a `[sighash][algo][sig]` envelope against a digest and public
 * key. Returns `false` on any kind of malformedness — never throws,
 * since this gets called on potentially adversarial network data.
 */
export async function verifySiglistEntry(
  entry: Uint8Array,
  digest: Uint8Array,
  publicKey: Uint8Array,
): Promise<boolean> {
  let parts: { sighashType: number; algoId: number; rawSig: Uint8Array };
  try {
    parts = decodeSiglistEntry(entry);
  } catch {
    return false;
  }
  switch (parts.algoId) {
    case ALGO_ID.ecdsa:
      return ecdsa.verify(parts.rawSig, digest, publicKey);
    case ALGO_ID.falcon512:
      return falcon.falcon512Verify(parts.rawSig, digest, publicKey);
    case ALGO_ID.schnorr:
      // Deliberately NOT feature-gated: verification of network data must
      // work regardless of whether we offer Schnorr signing ourselves.
      return schnorr.schnorrVerify(parts.rawSig, digest, publicKey);
    default:
      return false;
  }
}
