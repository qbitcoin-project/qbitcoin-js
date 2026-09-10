import { describe, expect, it } from 'vitest';
import { SIGHASH } from './constants';
import {
  buildFreezeOutput,
  downgradeScript,
  federationFreezeScript,
  federationScripthash,
  freezeOutputData,
  freezeScript,
  reclaimCsvValue,
  reclaimIdFor,
  reclaimScripthash,
  signReclaimInput,
} from './downgrade';
import { fromHex, toHex } from './encoding/hex';
import { hash160, hash256 } from './hashes';
import { getPublicKey } from './secp256k1';
import { serialize, sighash, TX_TYPE_STANDARD, txid, type Transaction } from './transaction';
import { verifySiglistEntry } from './signing';

// A synthetic 33-byte "compressed pubkey" — the script builder treats it as
// opaque bytes, so a recognizable pattern keeps the expected hex readable.
const LOCK_PUBKEY = fromHex('02' + 'ab'.repeat(32));

// 48h and 7d — the node's consensus windows (chain values at runtime).
const FREEZE_SEC = 48 * 3600;
const OUTPUT_SEC = 7 * 24 * 3600;

describe('reclaimCsvValue', () => {
  it('encodes a time-based relative locktime in 10s units', () => {
    // 48h = 172800s → 17280 units, with the time flag (1<<27).
    expect(reclaimCsvValue(FREEZE_SEC)).toBe(17280 | (1 << 27));
    expect(reclaimCsvValue(OUTPUT_SEC)).toBe(60480 | (1 << 27));
  });

  it('rejects nonsense windows', () => {
    expect(() => reclaimCsvValue(0)).toThrow(/positive/);
    expect(() => reclaimCsvValue(-10)).toThrow(/positive/);
  });
});

// The expected bytes below are assembled BY HAND from the node's script
// template (independent of the builder), so the tests catch any drift in
// either. The ELSE branch is shared by every covenant script and era:
//
//   OP_IF <if> OP_ELSE <push4 csvLE> OP_CSV OP_DROP
//   OP_OUTPUTDATA <push1 0> <push1 32> OP_SUBSTR
//   OP_OVER OP_HASH256 OP_EQUALVERIFY OP_CHECKSIG OP_ENDIF
const elseBranch = (csvLeHex: string): string =>
  '67' + '04' + csvLeHex + 'b2' + '75' + '80' + '0100' + '0120' + '7f' + '78' + 'aa' + '88' + 'ac' + '68';

describe('freezeScript / downgradeScript', () => {
  it('assembles the freeze script byte-exactly', () => {
    // csv(48h) = 17280 | 1<<27 = 0x08004380 → LE 80430008
    const expected =
      '63' + // OP_IF
      '57' + '7e' + '88' + // OP_7 OP_TX_TYPE OP_EQUALVERIFY (type must be 7)
      '21' + toHex(LOCK_PUBKEY) + 'ac' + // push(33) lock pubkey, OP_CHECKSIG
      elseBranch('80430008');
    expect(toHex(freezeScript(LOCK_PUBKEY, FREEZE_SEC))).toBe(expected);
  });

  it('assembles the downgrade script byte-exactly', () => {
    // csv(7d) = 60480 | 1<<27 = 0x0800EC40 → LE 40ec0008
    const expected =
      '63' +
      '56' + '7e' + '88' + '51' + // OP_6 OP_TX_TYPE OP_EQUALVERIFY OP_1 (permissionless burn)
      elseBranch('40ec0008');
    expect(toHex(downgradeScript(OUTPUT_SEC))).toBe(expected);
  });

  it('scripthash is hash160 of the script', () => {
    const script = freezeScript(LOCK_PUBKEY, FREEZE_SEC);
    expect(toHex(reclaimScripthash(script))).toBe(toHex(hash160(script)));
    expect(reclaimScripthash(script)).toHaveLength(20);
  });
});

describe('federationFreezeScript', () => {
  // Three synthetic Falcon-512-sized keys (897 bytes); the first bytes force
  // a sort order different from every input order used below.
  const K_LOW = new Uint8Array(897).fill(0x1a);
  const K_MID = new Uint8Array(897).fill(0x77);
  const K_HIGH = new Uint8Array(897).fill(0xc1);
  const PUSH_897 = '4d8103'; // OP_PUSHDATA2, length 897 LE — the node's op_pushdata encoding

  it('assembles the 2-of-3 multisig IF branch byte-exactly, keys sorted', () => {
    const script = federationFreezeScript([K_MID, K_HIGH, K_LOW], FREEZE_SEC);
    const expected =
      '63' + // OP_IF
      '57' + '7e' + '88' + // OP_7 OP_TX_TYPE OP_EQUALVERIFY (type must be 7)
      '52' + // OP_2
      PUSH_897 + toHex(K_LOW) +
      PUSH_897 + toHex(K_MID) +
      PUSH_897 + toHex(K_HIGH) +
      '53' + 'ae' + // OP_3 OP_CHECKMULTISIG
      elseBranch('80430008'); // csv(48h), same ELSE as the single-key era
    expect(toHex(script)).toBe(expected);
  });

  it('is key-order independent (the same set → the same script)', () => {
    const a = federationFreezeScript([K_LOW, K_MID, K_HIGH], FREEZE_SEC);
    const b = federationFreezeScript([K_HIGH, K_LOW, K_MID], FREEZE_SEC);
    expect(toHex(a)).toBe(toHex(b));
  });

  it('keeps the ELSE (user reclaim) branch byte-identical to the single-key era', () => {
    const legacy = freezeScript(LOCK_PUBKEY, FREEZE_SEC);
    const federation = federationFreezeScript([K_LOW, K_MID, K_HIGH], FREEZE_SEC);
    // OP_IF(1) + IF branch: legacy 3 + push(33)=34 + 1 = 38; federation
    // 3 + 1 + (3+897)*3 + 2 = 2706. Everything after must match.
    expect(toHex(federation.subarray(1 + 2706))).toBe(toHex(legacy.subarray(1 + 38)));
  });

  it('demands exactly three keys', () => {
    expect(() => federationFreezeScript([K_LOW, K_MID], FREEZE_SEC)).toThrow(/2-of-3/);
    expect(() => federationFreezeScript([K_LOW, K_MID, K_HIGH, K_LOW], FREEZE_SEC)).toThrow(/2-of-3/);
  });

  it('federationScripthash is hash256 of the script (32 bytes, PQ address form)', () => {
    const script = federationFreezeScript([K_LOW, K_MID, K_HIGH], FREEZE_SEC);
    expect(toHex(federationScripthash(script))).toBe(toHex(hash256(script)));
    expect(federationScripthash(script)).toHaveLength(32);
    // The downgrade-output script did not change between eras — only its
    // scripthash function did.
    expect(toHex(federationScripthash(downgradeScript(OUTPUT_SEC)))).toBe(toHex(hash256(downgradeScript(OUTPUT_SEC))));
  });
});

describe('freeze output', () => {
  const reclaimKey = getPublicKey(fromHex('11'.repeat(32)));
  const btcSpk = fromHex('76a914' + '22'.repeat(20) + '88ac');

  it('data = hash256(reclaim pubkey) ‖ btc scriptPubKey', () => {
    const data = freezeOutputData(reclaimKey, btcSpk);
    expect(toHex(data.subarray(0, 32))).toBe(toHex(hash256(reclaimKey)));
    expect(toHex(data.subarray(32))).toBe(toHex(btcSpk));
    expect(toHex(reclaimIdFor(reclaimKey))).toBe(toHex(hash256(reclaimKey)));
  });

  it('builds the full output', () => {
    const scripthash = reclaimScripthash(freezeScript(LOCK_PUBKEY, FREEZE_SEC));
    const out = buildFreezeOutput(386_322n, scripthash, reclaimKey, btcSpk);
    expect(out.value).toBe(386_322n);
    expect(out.scripthash).toBe(scripthash);
    expect(out.data).toHaveLength(32 + btcSpk.length);
  });

  it('rejects an empty scriptPubKey', () => {
    expect(() => freezeOutputData(reclaimKey, new Uint8Array(0))).toThrow(/empty/);
  });
});

describe('signReclaimInput', () => {
  const privateKey = fromHex('33'.repeat(32));
  const publicKey = getPublicKey(privateKey);

  const reclaimTx = (): Transaction => ({
    txType: TX_TYPE_STANDARD,
    inputs: [{ txid: fromHex('44'.repeat(32)), vout: 1 }],
    outputs: [{ value: 386_000n, scripthash: fromHex('55'.repeat(20)) }],
  });

  it('produces siglist [signature, pubkey, empty] and attaches the script', async () => {
    const script = freezeScript(LOCK_PUBKEY, FREEZE_SEC);
    const signed = await signReclaimInput(reclaimTx(), { inputIndex: 0, privateKey, publicKey, algo: 'ecdsa' }, script);
    const input = signed.inputs[0]!;
    expect(input.siglist).toHaveLength(3);
    // OP_IF pops the LAST siglist element: empty = FALSE = the reclaim branch.
    expect(input.siglist![2]).toHaveLength(0);
    expect(toHex(input.siglist![1]!)).toBe(toHex(publicKey));
    expect(input.redeemScript).toBe(script);
    // The first element is a valid [sighash][algo][sig] envelope over the
    // standard SIGHASH_ALL digest — the same digest ordinary inputs sign.
    const digest = sighash(signed, SIGHASH.ALL);
    await expect(verifySiglistEntry(input.siglist![0]!, digest, publicKey)).resolves.toBe(true);
  });

  it('the signed transaction serializes and has a txid', async () => {
    const script = freezeScript(LOCK_PUBKEY, FREEZE_SEC);
    const signed = await signReclaimInput(reclaimTx(), { inputIndex: 0, privateKey, publicKey, algo: 'ecdsa' }, script);
    const wire = serialize(signed);
    expect(wire.length).toBeGreaterThan(100);
    expect(txid(signed)).toHaveLength(32);
  });

  it('refuses a non-standard transaction and a missing input', async () => {
    const script = freezeScript(LOCK_PUBKEY, FREEZE_SEC);
    await expect(
      signReclaimInput(reclaimTx(), { inputIndex: 5, privateKey, publicKey, algo: 'ecdsa' }, script),
    ).rejects.toThrow(/missing input/);
  });
});
