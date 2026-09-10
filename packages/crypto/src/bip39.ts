// BIP-39 mnemonic generation, validation, and seed derivation.
//
// We use the English wordlist exclusively for now. International
// wordlists are nice but multiply the attack surface for typo-driven
// fund loss and make support harder. They can be added later if there's
// real demand.
//
// All bytes-handling code goes through @scure/bip39 — audited, no deps,
// constant-time where it matters.

import {
  generateMnemonic as scureGenerate,
  mnemonicToSeedSync,
  validateMnemonic as scureValidate,
} from '@scure/bip39';
import { wordlist as english } from '@scure/bip39/wordlists/english';

/** Number of words in the mnemonic. Maps to BIP-39 entropy sizes:
 *  12 = 128 bits, 15 = 160, 18 = 192, 21 = 224, 24 = 256.
 *  We default to 12 (industry standard for non-custodial wallets). */
export type MnemonicLength = 12 | 15 | 18 | 21 | 24;

const STRENGTH_BY_WORDS: Record<MnemonicLength, number> = {
  12: 128,
  15: 160,
  18: 192,
  21: 224,
  24: 256,
};

/**
 * Generate a fresh BIP-39 mnemonic.
 *
 * The underlying CSPRNG is `crypto.getRandomValues` (Web Crypto API),
 * available in both browser extension contexts and Node 22+.
 */
export function generateMnemonic(words: MnemonicLength = 12): string {
  return scureGenerate(english, STRENGTH_BY_WORDS[words]);
}

/**
 * Validate that a mnemonic is well-formed:
 *  - Has 12 / 15 / 18 / 21 / 24 words
 *  - Each word is in the English BIP-39 wordlist
 *  - The trailing checksum matches the leading entropy
 *
 * Returns `true` if valid, `false` otherwise. Does NOT throw on invalid
 * input — callers can show "Invalid recovery phrase" without try/catch.
 */
export function validateMnemonic(mnemonic: string): boolean {
  return scureValidate(mnemonic.trim(), english);
}

/**
 * Convert a mnemonic into the 64-byte BIP-39 seed (PBKDF2-HMAC-SHA512
 * with 2048 iterations).
 *
 * The seed is the input to BIP-32 master-key derivation. The optional
 * `passphrase` (BIP-39 "25th word") is salted into PBKDF2 — if the user
 * uses one, they need it on every device.
 *
 * Throws if the mnemonic is malformed; the caller should pre-validate
 * with `validateMnemonic` for friendly error messages.
 */
export function mnemonicToSeed(
  mnemonic: string,
  passphrase = '',
): Uint8Array {
  return mnemonicToSeedSync(mnemonic.trim(), passphrase);
}
