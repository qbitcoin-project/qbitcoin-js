import { describe, expect, it } from 'vitest';
import { ALGO_ID, SIGHASH } from './constants';
import { fromHex, toHex } from './encoding/hex';
import {
  FALCON512_SEED_BYTES,
  falcon512KeygenFromSeed,
} from './falcon512';
import { getPublicKey } from './secp256k1';
import {
  decodeSiglistEntry,
  encodeSiglistEntry,
  signTransaction,
  signWithAlgorithm,
  verifySiglistEntry,
} from './signing';
import { scriptP2PK } from './script';
import {
  TX_TYPE_STANDARD,
  serialize,
  sighash,
  type Transaction,
} from './transaction';

// Reuse the mainnet vector for tx shape; we ignore its real siglist and
// re-sign with our own key — the focus here is the signing pipeline,
// not exact byte-match of someone else's signature (ECDSA isn't
// deterministic anyway).
const PRIV = fromHex(
  '0c28fca386c7a227600b2fe50b7cae11ec86d3bf1fbe471be89827e19d72aa1d',
);
const PUB = getPublicKey(PRIV);

const TX_TEMPLATE: Transaction = {
  txType: TX_TYPE_STANDARD,
  inputs: [
    {
      txid: fromHex(
        '7cbf37f26bdaea7615c506c4507a9613c4776936d6860ecd8ec046e19699db32',
      ),
      vout: 2,
    },
  ],
  outputs: [
    {
      value: 39800995n,
      scripthash: fromHex('de4bde2de43a35b7538e9992b94f2c29bec01e8b'),
    },
  ],
};

describe('encodeSiglistEntry', () => {
  it('prefixes with sighash_type and algo bytes', () => {
    const raw = fromHex('30450221');
    const entry = encodeSiglistEntry(SIGHASH.ALL, 'ecdsa', raw);
    expect(entry[0]).toBe(SIGHASH.ALL);
    expect(entry[1]).toBe(ALGO_ID.ecdsa);
    expect(toHex(entry.slice(2))).toBe('30450221');
  });

  it('produces 01 01 prefix for SIGHASH_ALL + ECDSA (matches mempool dump)', () => {
    const raw = fromHex('aa');
    const entry = encodeSiglistEntry(SIGHASH.ALL, 'ecdsa', raw);
    expect(toHex(entry.slice(0, 2))).toBe('0101');
  });

  it('produces 01 81 prefix for SIGHASH_ALL + Falcon-512', () => {
    const raw = fromHex('aa');
    const entry = encodeSiglistEntry(SIGHASH.ALL, 'falcon512', raw);
    expect(toHex(entry.slice(0, 2))).toBe('0181');
  });

  it('rejects out-of-byte-range sighash type', () => {
    expect(() => encodeSiglistEntry(256, 'ecdsa', new Uint8Array())).toThrow(RangeError);
    expect(() => encodeSiglistEntry(-1, 'ecdsa', new Uint8Array())).toThrow(RangeError);
  });
});

describe('decodeSiglistEntry', () => {
  it('is the inverse of encodeSiglistEntry', () => {
    const raw = fromHex('deadbeefcafe');
    const entry = encodeSiglistEntry(SIGHASH.ALL, 'ecdsa', raw);
    const decoded = decodeSiglistEntry(entry);
    expect(decoded.sighashType).toBe(SIGHASH.ALL);
    expect(decoded.algoId).toBe(ALGO_ID.ecdsa);
    expect(toHex(decoded.rawSig)).toBe('deadbeefcafe');
  });

  it('decodes a real mempool siglist entry', () => {
    const entry = fromHex(
      '01013045022100fb9864295b0d9897de67038fde90023bf0e05d523e5837138fd541ec791e52a2022025dd966192586003603ba451d07cf39d8a05d638b967ae916c313102300ff3dd',
    );
    const decoded = decodeSiglistEntry(entry);
    expect(decoded.sighashType).toBe(SIGHASH.ALL);
    expect(decoded.algoId).toBe(ALGO_ID.ecdsa);
    expect(decoded.rawSig[0]).toBe(0x30);
  });

  it('rejects too-short entries', () => {
    expect(() => decodeSiglistEntry(new Uint8Array(0))).toThrow(RangeError);
    expect(() => decodeSiglistEntry(new Uint8Array(1))).toThrow(RangeError);
  });
});

describe('signWithAlgorithm', () => {
  it('signs with ECDSA and produces a DER signature', async () => {
    const digest = sighash(TX_TEMPLATE);
    const sig = await signWithAlgorithm(digest, PRIV, 'ecdsa');
    expect(sig[0]).toBe(0x30); // DER SEQUENCE
  });

  it('refuses Schnorr while the feature flag is off (the default)', async () => {
    const digest = sighash(TX_TEMPLATE);
    await expect(signWithAlgorithm(digest, PRIV, 'schnorr')).rejects.toThrow(
      /not enabled/,
    );
  });

  it('signs with Falcon-512 (WASM-backed)', async () => {
    // Falcon-512 needs a Falcon-format private key, not the secp256k1 one.
    const { privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0xfa),
    );
    const digest = sighash(TX_TEMPLATE);
    const sig = await signWithAlgorithm(digest, privateKey, 'falcon512');
    // Falcon raw signature starts with header byte 0x39 (Falcon-512 logn=9).
    expect(sig[0]).toBe(0x39);
    expect(sig.length).toBeGreaterThan(40);
  });
});

describe('signTransaction — end-to-end (ECDSA)', () => {
  it('produces a valid signed transaction', async () => {
    const signed = await signTransaction(TX_TEMPLATE, [
      { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
    ]);

    expect(signed.inputs[0]!.siglist).toBeDefined();
    expect(signed.inputs[0]!.redeemScript).toBeDefined();

    const entry = signed.inputs[0]!.siglist![0]!;
    expect(entry[0]).toBe(SIGHASH.ALL);
    expect(entry[1]).toBe(ALGO_ID.ecdsa);

    const rs = signed.inputs[0]!.redeemScript!;
    expect(rs[0]).toBe(0x21);
    expect(rs[rs.length - 1]).toBe(0xac);
    expect(toHex(rs.slice(1, 34))).toBe(toHex(PUB));
  });

  it('is a pure function (does not mutate the input)', async () => {
    const before = JSON.stringify(TX_TEMPLATE, replacer);
    await signTransaction(TX_TEMPLATE, [
      { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
    ]);
    expect(JSON.stringify(TX_TEMPLATE, replacer)).toBe(before);
  });

  it('serializes to a valid transaction (can be passed to txid)', async () => {
    const signed = await signTransaction(TX_TEMPLATE, [
      { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
    ]);
    expect(() => serialize(signed)).not.toThrow();
    expect(serialize(signed)[0]).toBe(TX_TYPE_STANDARD);
  });

  it('signed signature verifies against the same digest and pubkey', async () => {
    const signed = await signTransaction(TX_TEMPLATE, [
      { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
    ]);
    const digest = sighash(TX_TEMPLATE);
    const entry = signed.inputs[0]!.siglist![0]!;
    expect(await verifySiglistEntry(entry, digest, PUB)).toBe(true);
  });

  it('verifySiglistEntry rejects entry against wrong digest', async () => {
    const signed = await signTransaction(TX_TEMPLATE, [
      { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
    ]);
    const entry = signed.inputs[0]!.siglist![0]!;
    const wrongDigest = new Uint8Array(32).fill(0xff);
    expect(await verifySiglistEntry(entry, wrongDigest, PUB)).toBe(false);
  });

  it('verifySiglistEntry rejects entry with unknown algo byte', async () => {
    const fakeEntry = new Uint8Array([0x01, 0xff, 0xaa]);
    const digest = new Uint8Array(32);
    expect(await verifySiglistEntry(fakeEntry, digest, PUB)).toBe(false);
  });

  it('verifySiglistEntry returns false on truncated entry without throwing', async () => {
    const digest = new Uint8Array(32);
    expect(await verifySiglistEntry(new Uint8Array(1), digest, PUB)).toBe(false);
  });

  it('rejects signer with out-of-range inputIndex', async () => {
    await expect(
      signTransaction(TX_TEMPLATE, [
        { inputIndex: 5, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
      ]),
    ).rejects.toThrow(RangeError);
  });

  it('rejects duplicate signers for the same input', async () => {
    await expect(
      signTransaction(TX_TEMPLATE, [
        { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
        { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
      ]),
    ).rejects.toThrow(/Duplicate signer/);
  });

  it('rejects non-SIGHASH_ALL types', async () => {
    await expect(
      signTransaction(
        TX_TEMPLATE,
        [{ inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' }],
        SIGHASH.NONE,
      ),
    ).rejects.toThrow(RangeError);
  });

  it('leaves un-signed inputs untouched', async () => {
    const multiInput: Transaction = {
      ...TX_TEMPLATE,
      inputs: [TX_TEMPLATE.inputs[0]!, { ...TX_TEMPLATE.inputs[0]!, vout: 7 }],
    };
    const signed = await signTransaction(multiInput, [
      { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
    ]);
    expect(signed.inputs[0]!.siglist).toBeDefined();
    expect(signed.inputs[1]!.siglist).toBeUndefined();
  });
});

describe('signTransaction — end-to-end (Falcon-512)', () => {
  it('produces a valid Falcon-signed transaction and verifies it', async () => {
    const { publicKey, privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0xf1),
    );
    const signed = await signTransaction(TX_TEMPLATE, [
      { inputIndex: 0, privateKey, publicKey, algo: 'falcon512' },
    ]);

    // siglist entry starts with `01 81` (SIGHASH_ALL + FALCON).
    const entry = signed.inputs[0]!.siglist![0]!;
    expect(entry[0]).toBe(SIGHASH.ALL);
    expect(entry[1]).toBe(ALGO_ID.falcon512);

    // redeemScript is P2PK with a 897-byte Falcon pubkey, encoded with
    // OP_PUSHDATA2 (0x4d) + little-endian length (0x0381 = 897).
    const rs = signed.inputs[0]!.redeemScript!;
    expect(rs[0]).toBe(0x4d);
    expect(rs[1]).toBe(0x81);
    expect(rs[2]).toBe(0x03);
    expect(rs[rs.length - 1]).toBe(0xac); // OP_CHECKSIG

    // Verify roundtrip through the same digest.
    const digest = sighash(TX_TEMPLATE);
    expect(await verifySiglistEntry(entry, digest, publicKey)).toBe(true);
  });

  it('falcon-signed transaction can be serialized for broadcast', async () => {
    const { publicKey, privateKey } = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0xf2),
    );
    const signed = await signTransaction(TX_TEMPLATE, [
      { inputIndex: 0, privateKey, publicKey, algo: 'falcon512' },
    ]);
    const hex = toHex(serialize(signed));
    // Sanity: bytes are long (Falcon sig + 897-byte pubkey in script).
    expect(hex.length).toBeGreaterThan(2000);
  });

  it('signs mixed inputs: ECDSA and Falcon side by side in one tx', async () => {
    const twoInputTx: Transaction = {
      ...TX_TEMPLATE,
      inputs: [
        { txid: new Uint8Array(32).fill(0x11), vout: 0 },
        { txid: new Uint8Array(32).fill(0x22), vout: 1 },
      ],
    };
    const falconKp = await falcon512KeygenFromSeed(
      new Uint8Array(FALCON512_SEED_BYTES).fill(0xfb),
    );
    const signed = await signTransaction(twoInputTx, [
      { inputIndex: 0, privateKey: PRIV, publicKey: PUB, algo: 'ecdsa' },
      {
        inputIndex: 1,
        privateKey: falconKp.privateKey,
        publicKey: falconKp.publicKey,
        algo: 'falcon512',
      },
    ]);

    const digest = sighash(twoInputTx);
    const e0 = signed.inputs[0]!.siglist![0]!;
    const e1 = signed.inputs[1]!.siglist![0]!;
    expect(e0[1]).toBe(ALGO_ID.ecdsa);
    expect(e1[1]).toBe(ALGO_ID.falcon512);
    expect(await verifySiglistEntry(e0, digest, PUB)).toBe(true);
    expect(await verifySiglistEntry(e1, digest, falconKp.publicKey)).toBe(true);
    // Per-input redeem matches each input's own key type.
    expect(signed.inputs[0]!.redeemScript!.length).toBe(35);
    expect(toHex(signed.inputs[1]!.redeemScript!)).toBe(
      toHex(scriptP2PK(falconKp.publicKey)),
    );
    expect(() => serialize(signed)).not.toThrow();
  });
});

// Helper to serialize Uint8Array fields in our Transaction type for the
// "no mutation" test (Uint8Array has no default JSON form).
function replacer(_key: string, value: unknown): unknown {
  if (value instanceof Uint8Array) return Array.from(value);
  if (typeof value === 'bigint') return value.toString();
  return value;
}
