import { describe, expect, it } from 'vitest';
import {
  ALGO_ID,
  ALGO_POSTQUANTUM_BIT,
  DENOMINATOR,
  SIGHASH,
  forkCommitsTokenId,
  isPostQuantum,
} from './constants.js';

// Only protocol-level constants live here — per-chain values (address
// magic, WIF versions, schemes, labels) are ChainProfile fields and are
// exercised in profile.test.ts against the test fixture.

describe('ALGO_ID', () => {
  it('matches the node CRYPT_ALGO_* constants', () => {
    expect(ALGO_ID.ecdsa).toBe(1);
    expect(ALGO_ID.schnorr).toBe(2);
    expect(ALGO_ID.falcon512).toBe(129);
  });

  it('Falcon has the post-quantum bit set', () => {
    expect(ALGO_ID.falcon512 & ALGO_POSTQUANTUM_BIT).toBe(ALGO_POSTQUANTUM_BIT);
  });
});

describe('isPostQuantum', () => {
  it('ECDSA is classical', () => {
    expect(isPostQuantum('ecdsa')).toBe(false);
  });
  it('Schnorr is classical', () => {
    expect(isPostQuantum('schnorr')).toBe(false);
  });
  it('Falcon-512 is post-quantum', () => {
    expect(isPostQuantum('falcon512')).toBe(true);
  });
});

describe('DENOMINATOR', () => {
  it('is 10^8', () => {
    expect(DENOMINATOR).toBe(100_000_000);
  });
});

describe('SIGHASH', () => {
  it('values match the node', () => {
    expect(SIGHASH.ALL).toBe(1);
    expect(SIGHASH.NONE).toBe(2);
    expect(SIGHASH.SINGLE).toBe(3);
    expect(SIGHASH.ANYONECANPAY).toBe(0x80);
  });
});

describe('token sighash fork predicate', () => {
  it('the predicate: null never commits, 0 always, T from T inclusive', () => {
    expect(forkCommitsTokenId(null, 0)).toBe(false);
    expect(forkCommitsTokenId(null, 4_000_000_000)).toBe(false);
    expect(forkCommitsTokenId(0, 0)).toBe(true);
    expect(forkCommitsTokenId(0, 1)).toBe(true);
    const fork = 1_789_430_400;
    expect(forkCommitsTokenId(fork, fork - 1)).toBe(false);
    expect(forkCommitsTokenId(fork, fork)).toBe(true);
    expect(forkCommitsTokenId(fork, fork + 1)).toBe(true);
  });

});
