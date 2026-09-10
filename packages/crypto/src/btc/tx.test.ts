// Cross-implementation golden vectors for the Bitcoin spend builder.
//
// The expected hex/txids below were produced by an INDEPENDENT reference
// implementation (python: textbook secp256k1 point math + RFC 6979 +
// hand-rolled RIPEMD-160/serialization), which itself reproduces this
// package's frozen signed-message ECDSA vector bit-for-bit. Deterministic
// signing (RFC 6979, low-S) makes full-transaction hex comparable across
// implementations.
import { describe, expect, it } from 'vitest';
import { fromHex, toHex } from '../encoding/hex';
import { hash160 } from '../hashes';
import { getPublicKey } from '../secp256k1';
import {
  BTC_RBF_SEQUENCE,
  btcSighashAll,
  btcTxid,
  estimateBtcP2pkhTxSize,
  scriptBtcOpReturn,
  scriptBtcP2pkh,
  scriptBtcP2pkhForPubkey,
  serializeBtcTx,
  signBtcP2pkhSpend,
} from './tx';

// Fixed test key: private bytes 0x01..0x20 (same fixture family as
// signedMessage.test.ts).
const PRIV = (() => {
  const k = new Uint8Array(32);
  for (let i = 0; i < 32; i++) k[i] = i + 1;
  return k;
})();
const PUBKEY = getPublicKey(PRIV);

// sha256('qbt/btc-upgrade test prevout 1' / '… 2') — synthetic prevouts.
const PREV1 = 'cb10d9e67b7f4000bbb2e7fe48d2cc3714a0f51d8497fb74e3cdf6a0da841f59';
const PREV2 = '54347932f1b0d4841e311ff67a6d84ba433db4ae1e45e415d4e19146f8cc82f1';
// sha256('qbt destination scripthash') — a 32-byte PQ-style commitment.
const DEST32 = fromHex('2910f9641b513f3f62f546c8bb454cae81825325d9997b4812241b54957d47e0');
// An arbitrary realistic 20-byte lock hash.
const LOCK = fromHex('56ca8180ab9c6f4b9bb8a3d84cddd85670319407');

describe('script builders', () => {
  it('builds the canonical P2PKH scriptPubKey', () => {
    expect(toHex(scriptBtcP2pkh(LOCK))).toBe(
      '76a91456ca8180ab9c6f4b9bb8a3d84cddd8567031940788ac',
    );
  });

  it('builds OP_RETURN with a single datum push', () => {
    const s = scriptBtcOpReturn(DEST32);
    expect(s[0]).toBe(0x6a);
    expect(s[1]).toBe(32);
    expect(s.length).toBe(34);
  });

  it('rejects out-of-range OP_RETURN payloads', () => {
    expect(() => scriptBtcOpReturn(new Uint8Array(0))).toThrow(/1\.\.75/);
    expect(() => scriptBtcOpReturn(new Uint8Array(76))).toThrow(/1\.\.75/);
  });

  it('fixture pubkey hashes to the reference pubkeyhash', () => {
    expect(toHex(hash160(PUBKEY))).toBe('587c9bfc87a837a056f716c2f9de891adbc46c90');
  });
});

describe('signBtcP2pkhSpend — golden vectors', () => {
  it('vector 1: one input → lock + OP_RETURN (full conversion, no change)', () => {
    const tx = signBtcP2pkhSpend(
      {
        prevouts: [{ txid: PREV1, vout: 1 }],
        outputs: [
          { value: 4_999_295n, scriptPubKey: scriptBtcP2pkh(LOCK) },
          { value: 0n, scriptPubKey: scriptBtcOpReturn(DEST32) },
        ],
      },
      PRIV,
    );
    expect(toHex(serializeBtcTx(tx))).toBe(
      '0200000001591f84daa0f6cde374fb97841df5a01437ccd248fee7b2bb00407f7be6d910cb' +
        '010000006a47304402205b2dfa3fe8d436ae2f2ffb18da6b701478e61fa65f3ee6850dcf' +
        '7ec4e9a200be022078558429c9946b8fa3ce5a1a15d802c6adcc223ac5897c7e23ae9303' +
        '6a8d19bb01210284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351cc' +
        'ffa4b0fdffffff027f484c00000000001976a91456ca8180ab9c6f4b9bb8a3d84cddd856' +
        '7031940788ac0000000000000000226a202910f9641b513f3f62f546c8bb454cae818253' +
        '25d9997b4812241b54957d47e000000000',
    );
    expect(btcTxid(tx)).toBe(
      '03b79a921d8b36b19c5473bb589ee6fea79fc01b178b1de77c75ffcc3753a759',
    );
  });

  it('vector 2: two inputs → lock + OP_RETURN + change (partial conversion)', () => {
    const tx = signBtcP2pkhSpend(
      {
        prevouts: [
          { txid: PREV1, vout: 0 },
          { txid: PREV2, vout: 3 },
        ],
        outputs: [
          { value: 3_000_000n, scriptPubKey: scriptBtcP2pkh(LOCK) },
          { value: 0n, scriptPubKey: scriptBtcOpReturn(DEST32) },
          { value: 1_998_530n, scriptPubKey: scriptBtcP2pkhForPubkey(PUBKEY) },
        ],
      },
      PRIV,
    );
    expect(toHex(serializeBtcTx(tx))).toBe(
      '0200000002591f84daa0f6cde374fb97841df5a01437ccd248fee7b2bb00407f7be6d910cb' +
        '000000006b48304502210083ca2d446af513a9457901667a53d43813bf346e0d3ae66228' +
        'dc6f7e9c42752c02203916c595c243f34aeac75b7237ded5d3e219f2c75fdae3996fc393' +
        'e482ee39a901210284bf7562262bbd6940085748f3be6afa52ae317155181ece31b66351' +
        'ccffa4b0fdfffffff182ccf84691e1d415e4451eaeb43d43ba846d7af61f311e84d4b0f1' +
        '32793454030000006b483045022100cc013690c84332c558717bd446adc9aa5907b6f0b1' +
        '0baf4c401a700e09b3a841022038c8db1bac0d341abd1fac4fd3e75d996e2b5cc61cf8a1' +
        'a78837751d5b6642e201210284bf7562262bbd6940085748f3be6afa52ae317155181ece' +
        '31b66351ccffa4b0fdffffff03c0c62d00000000001976a91456ca8180ab9c6f4b9bb8a3' +
        'd84cddd8567031940788ac0000000000000000226a202910f9641b513f3f62f546c8bb45' +
        '4cae81825325d9997b4812241b54957d47e0c27e1e00000000001976a914587c9bfc87a8' +
        '37a056f716c2f9de891adbc46c9088ac00000000',
    );
    expect(btcTxid(tx)).toBe(
      'b26ed109e3161f4de7493353257b52dc770ad2565b4a8ba9f9cae520f1fcf6bc',
    );
  });
});

describe('structure and invariants', () => {
  const spend = {
    prevouts: [{ txid: PREV1, vout: 1 }],
    outputs: [
      { value: 4_999_295n, scriptPubKey: scriptBtcP2pkh(LOCK) },
      { value: 0n, scriptPubKey: scriptBtcOpReturn(DEST32) },
    ],
  };

  it('inputs opt into RBF by default', () => {
    const tx = signBtcP2pkhSpend(spend, PRIV);
    for (const input of tx.inputs) expect(input.sequence).toBe(BTC_RBF_SEQUENCE);
  });

  it('input[0] scriptSig is push(sig) push(compressed pubkey) — the fallback shape', () => {
    const tx = signBtcP2pkhSpend(spend, PRIV);
    const script = tx.inputs[0]!.scriptSig;
    const sigLen = script[0]!;
    expect(script[sigLen]).toBe(0x01); // trailing SIGHASH_ALL byte
    expect(script[1 + sigLen]).toBe(33); // compressed pubkey push
    expect(toHex(script.slice(2 + sigLen))).toBe(toHex(PUBKEY));
  });

  it('sighash is stable and differs per input', () => {
    const unsigned = {
      version: 2,
      inputs: [
        { prevout: { txid: PREV1, vout: 0 }, scriptSig: new Uint8Array(0), sequence: BTC_RBF_SEQUENCE },
        { prevout: { txid: PREV2, vout: 3 }, scriptSig: new Uint8Array(0), sequence: BTC_RBF_SEQUENCE },
      ],
      outputs: spend.outputs,
      locktime: 0,
    };
    const spent = scriptBtcP2pkhForPubkey(PUBKEY);
    const d0 = btcSighashAll(unsigned, 0, spent);
    expect(toHex(btcSighashAll(unsigned, 0, spent))).toBe(toHex(d0));
    expect(toHex(btcSighashAll(unsigned, 1, spent))).not.toBe(toHex(d0));
  });

  it('size estimate never underestimates and stays within 2 bytes per input', () => {
    for (const [prevouts, outs] of [
      [spend.prevouts, spend.outputs],
      [
        [
          { txid: PREV1, vout: 0 },
          { txid: PREV2, vout: 3 },
        ],
        [
          { value: 3_000_000n, scriptPubKey: scriptBtcP2pkh(LOCK) },
          { value: 0n, scriptPubKey: scriptBtcOpReturn(DEST32) },
          { value: 1_998_530n, scriptPubKey: scriptBtcP2pkhForPubkey(PUBKEY) },
        ],
      ],
    ] as const) {
      const tx = signBtcP2pkhSpend({ prevouts, outputs: outs }, PRIV);
      const actual = serializeBtcTx(tx).length;
      const estimate = estimateBtcP2pkhTxSize({
        inputCount: prevouts.length,
        p2pkhOutputCount: outs.length - 1,
        opReturnPayloadLen: 32,
      });
      expect(estimate).toBeGreaterThanOrEqual(actual);
      expect(estimate - actual).toBeLessThanOrEqual(2 * prevouts.length);
    }
  });

  it('refuses empty inputs or outputs', () => {
    expect(() => signBtcP2pkhSpend({ prevouts: [], outputs: spend.outputs }, PRIV)).toThrow(/no inputs/);
    expect(() => signBtcP2pkhSpend({ prevouts: spend.prevouts, outputs: [] }, PRIV)).toThrow(/no outputs/);
  });
});
