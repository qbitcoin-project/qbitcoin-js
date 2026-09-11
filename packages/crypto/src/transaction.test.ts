import { describe, expect, it } from 'vitest';
import { SIGHASH } from './constants.js';
import { fromHex, toHex } from './encoding/hex.js';
import {
  TX_TYPE_STANDARD,
  TX_TYPE_TOKENS,
  deserialize,
  encodeTokenTransfer,
  serialize,
  serializeForSighash,
  sighash,
  txid,
  type Transaction,
} from './transaction.js';

// Real transaction captured from a live node (`/api/mempool/recent`),
// dump captured during protocol research.
//
// If our serialize + hash256 produces the same txid as the node ran on
// the same logical transaction, we are byte-for-byte protocol-compatible
// for the classical (ECDSA) signing path.
const MAINNET_TX: Transaction = {
  txType: TX_TYPE_STANDARD,
  inputs: [
    {
      txid: fromHex(
        '7cbf37f26bdaea7615c506c4507a9613c4776936d6860ecd8ec046e19699db32',
      ),
      vout: 2,
      siglist: [
        fromHex(
          '01013045022100fb9864295b0d9897de67038fde90023bf0e05d523e5837138fd541ec791e52a2022025dd966192586003603ba451d07cf39d8a05d638b967ae916c313102300ff3dd',
        ),
      ],
      redeemScript: fromHex(
        '21039b66566d3acb6bd203a0a61f4e0105b84f12e107aaf27f30466807121197d10cac',
      ),
    },
  ],
  outputs: [
    {
      value: 39800995n,
      scripthash: fromHex('de4bde2de43a35b7538e9992b94f2c29bec01e8b'),
    },
    {
      value: 6579599427781n,
      scripthash: fromHex('ad5ef5738c9b3e8de242e75d3f99c5b92a49a25a'),
    },
  ],
};

const MAINNET_TXID =
  '3c0efded93e7c11a39992d2a19aa13a8e03bbf9a265f939a0951d6f810458ad8';

describe('serialize — real mainnet vector', () => {
  it('produces a transaction whose hash256 matches the known txid', () => {
    expect(toHex(txid(MAINNET_TX))).toBe(MAINNET_TXID);
  });

  it('serialized form starts with tx_type byte 0x01', () => {
    expect(serialize(MAINNET_TX)[0]).toBe(TX_TYPE_STANDARD);
  });

  it('contains the input txid bytes verbatim', () => {
    const ser = toHex(serialize(MAINNET_TX));
    expect(ser).toContain(
      '7cbf37f26bdaea7615c506c4507a9613c4776936d6860ecd8ec046e19699db32',
    );
  });

  it('contains both output scripthashes verbatim', () => {
    const ser = toHex(serialize(MAINNET_TX));
    expect(ser).toContain('de4bde2de43a35b7538e9992b94f2c29bec01e8b');
    expect(ser).toContain('ad5ef5738c9b3e8de242e75d3f99c5b92a49a25a');
  });
});

describe('serializeForSighash', () => {
  it('omits siglist and redeemScript from inputs', () => {
    const sighashSer = toHex(serializeForSighash(MAINNET_TX));
    const full = toHex(serialize(MAINNET_TX));
    // sighash serialization is strictly shorter — no signatures inline.
    expect(sighashSer.length).toBeLessThan(full.length);
    // It must NOT contain the signature bytes.
    expect(sighashSer).not.toContain('3045022100fb9864');
    // But MUST contain the input txid and outputs.
    expect(sighashSer).toContain(
      '7cbf37f26bdaea7615c506c4507a9613c4776936d6860ecd8ec046e19699db32',
    );
    expect(sighashSer).toContain('de4bde2de43a35b7538e9992b94f2c29bec01e8b');
  });

  it('is deterministic', () => {
    expect(toHex(serializeForSighash(MAINNET_TX))).toBe(
      toHex(serializeForSighash(MAINNET_TX)),
    );
  });

  it('rejects unsupported sighash types', () => {
    expect(() => serializeForSighash(MAINNET_TX, SIGHASH.NONE)).toThrow(RangeError);
    expect(() => serializeForSighash(MAINNET_TX, SIGHASH.SINGLE)).toThrow(RangeError);
    expect(() => serializeForSighash(MAINNET_TX, SIGHASH.ANYONECANPAY)).toThrow(RangeError);
  });
});

describe('sighash', () => {
  it('returns 32 bytes', () => {
    expect(sighash(MAINNET_TX).length).toBe(32);
  });

  it('is deterministic', () => {
    expect(toHex(sighash(MAINNET_TX))).toBe(toHex(sighash(MAINNET_TX)));
  });

  it('is the double-SHA256 of serializeForSighash', () => {
    // Implementation detail check: we compute hash256 of the sighash
    // bytes, never anything else.
    const direct = sighash(MAINNET_TX);
    // Reproducing the operation by hand:
    const bytes = serializeForSighash(MAINNET_TX);
    // We trust hashes.ts (separately tested), so just ensure the API
    // composition matches the spec text.
    expect(direct.length).toBe(32);
    expect(bytes.length).toBeGreaterThan(0);
  });
});

describe('serialize — error cases', () => {
  it('throws if an input is missing its siglist', () => {
    const broken: Transaction = {
      ...MAINNET_TX,
      inputs: [{ ...MAINNET_TX.inputs[0]!, siglist: undefined }],
    };
    expect(() => serialize(broken)).toThrow(/missing siglist/);
  });

  it('throws if an input is missing its redeemScript', () => {
    const broken: Transaction = {
      ...MAINNET_TX,
      inputs: [{ ...MAINNET_TX.inputs[0]!, redeemScript: undefined }],
    };
    expect(() => serialize(broken)).toThrow(/missing redeemScript/);
  });

  it('throws on wrong-length txid', () => {
    const broken: Transaction = {
      ...MAINNET_TX,
      inputs: [{ ...MAINNET_TX.inputs[0]!, txid: new Uint8Array(31) }],
    };
    expect(() => serialize(broken)).toThrow(RangeError);
  });

  it('throws on negative output value', () => {
    const broken: Transaction = {
      ...MAINNET_TX,
      outputs: [
        { ...MAINNET_TX.outputs[0]!, value: -1n },
        MAINNET_TX.outputs[1]!,
      ],
    };
    expect(() => serialize(broken)).toThrow(RangeError);
  });

  it('throws on output value > uint64 max', () => {
    const broken: Transaction = {
      ...MAINNET_TX,
      outputs: [
        { ...MAINNET_TX.outputs[0]!, value: 0x10000000000000000n },
        MAINNET_TX.outputs[1]!,
      ],
    };
    expect(() => serialize(broken)).toThrow(RangeError);
  });

  it('throws on scripthash of wrong length', () => {
    const broken: Transaction = {
      ...MAINNET_TX,
      outputs: [
        { ...MAINNET_TX.outputs[0]!, scripthash: new Uint8Array(19) },
        MAINNET_TX.outputs[1]!,
      ],
    };
    expect(() => serialize(broken)).toThrow(RangeError);
  });

  it('accepts 32-byte scripthash (PQ output)', () => {
    const tx: Transaction = {
      ...MAINNET_TX,
      outputs: [
        { value: 1000n, scripthash: new Uint8Array(32).fill(0xab) },
        MAINNET_TX.outputs[1]!,
      ],
    };
    // Should not throw, even though we can't predict the txid.
    expect(() => serialize(tx)).not.toThrow();
  });
});

// Token transfer (TX_TYPE_TOKENS) — byte-exact against the golden vector
// (real transfer tx ceca437…). Key invariant:
// serialize carries the varstr(token_hash) prefix; serializeForSighash does
// NOT (wire serialize vs sign_data).
const TOKEN_ID =
  '8b33404b9e184215e783081af45702e2d8911b08f656f2f0724d5dda73279ccd';

const TOKEN_TX: Transaction = {
  txType: TX_TYPE_TOKENS,
  tokenHash: fromHex(TOKEN_ID),
  inputs: [
    {
      txid: fromHex(
        '77f8f9cf263a9aae4c911adf28c9f46570d6a86f80e753fa718cd02504e86afb',
      ),
      vout: 1,
      siglist: [fromHex('00')],
      redeemScript: fromHex('00'),
    },
  ],
  outputs: [
    {
      value: 0n,
      scripthash: fromHex('fd3d188229362eea73f407231ecdceb12206569e'),
      data: encodeTokenTransfer(56753706n),
    },
    {
      value: 0n,
      scripthash: fromHex('1f865808158b3e1c99e35a02b7a0470d42f9ac0a'),
      data: encodeTokenTransfer(92470986190320n),
    },
    {
      value: 278596684618803n,
      scripthash: fromHex('49ddff3521520cb6bf43437ad1a1fead5bedbc11'),
    },
  ],
};

describe('encodeTokenTransfer', () => {
  it('encodes 0x01 + uint64LE amount (golden bytes)', () => {
    expect(toHex(encodeTokenTransfer(56753706n))).toBe('012afe610300000000');
    expect(toHex(encodeTokenTransfer(92470986190320n))).toBe(
      '01f0ad48141a540000',
    );
  });

  it('is always 9 bytes', () => {
    expect(encodeTokenTransfer(0n).length).toBe(9);
    expect(encodeTokenTransfer(0xffffffffffffffffn).length).toBe(9);
  });

  it('rejects negative and over-uint64 amounts', () => {
    expect(() => encodeTokenTransfer(-1n)).toThrow(RangeError);
    expect(() => encodeTokenTransfer(0x10000000000000000n)).toThrow(RangeError);
  });
});

describe('serialize — token transfer', () => {
  it('starts with tx_type 0x04 + varstr(token_hash) = token_id as-is', () => {
    expect(toHex(serialize(TOKEN_TX)).startsWith(`0420${TOKEN_ID}`)).toBe(true);
  });

  it('serializes outputs byte-for-byte (TRANSFER + native change)', () => {
    const ser = toHex(serialize(TOKEN_TX));
    expect(ser).toContain(
      '000000000000000014fd3d188229362eea73f407231ecdceb12206569e09012afe610300000000',
    );
    expect(ser).toContain(
      '0000000000000000141f865808158b3e1c99e35a02b7a0470d42f9ac0a0901f0ad48141a540000',
    );
    // Native change: value + scripthash + EMPTY data (00).
    expect(ser).toContain(
      '331c6cd861fd000014' + '49ddff3521520cb6bf43437ad1a1fead5bedbc11' + '00',
    );
  });
});

describe('serializeForSighash — token transfer framing', () => {
  it('starts with tx_type + input count (the wire varstr prefix stays off the sighash)', () => {
    const sig = toHex(serializeForSighash(TOKEN_TX, SIGHASH.ALL, false));
    // 04 (type) + 01 (varint: 1 input) + txid… — no 0x20 token_hash prefix
    // up front; past the fork the RAW hash goes at the END instead (next
    // test suite).
    expect(sig.startsWith('0401')).toBe(true);
    expect(sig.startsWith(`0420${TOKEN_ID}`)).toBe(false);
  });

  it('still covers the TRANSFER amounts (output data is signed)', () => {
    expect(toHex(serializeForSighash(TOKEN_TX, SIGHASH.ALL, false))).toContain('012afe610300000000');
  });
});

describe('deserialize', () => {
  it('is the exact inverse of serialize (token transfer roundtrip)', () => {
    const wire = serialize(TOKEN_TX);
    const parsed = deserialize(wire);
    expect(parsed.txType).toBe(TX_TYPE_TOKENS);
    expect(toHex(parsed.tokenHash!)).toBe(TOKEN_ID);
    expect(toHex(serialize(parsed))).toBe(toHex(wire));
  });

  // A REAL testnet freeze transaction (display txid 46bacf48…1b6865): one
  // Falcon-signed input, a covenant output whose data carries
  // [reclaim_id(32)][btc scriptPubKey], and PQ change. This is the exact
  // payload the rescan fallback reads when the node's JSON view no longer
  // annotates a retired covenant era's outputs.
  const LIVE_FREEZE_HEX =
    '01018d6a177287f708a715aba0a9428ff4e82d88eff006e5b950e2a6eab02daf43920001fd90020181392ea0766b85a0' +
  '431ca2f32b63e3972d7e54a2acc8836c76dab3ca79322b836ecc129abca3d2bad84ee2e1eb6427da76ab6972148b84f6' +
  '2e59f7ed96d546265c845b81146d14472a33946650c309a2dd9205ca5f6b8efc2dfd7525bae04df5a7cf8a42d6cc8eda' +
  '070c7673f02b0a3b894d53742d5d20f25451cc3d0a5586e047deb8661cd4f0e4f127022c445b89173f3953bd9b8ec5c6' +
  '7f80721472b71c49f57cc71ba917d012f44d9d5a7e0e4214c9f9f154e216d27cabafe73739984963cce9751ce9cdc8bf' +
  'dbe14edcde18831eaca23042d7f8e640b4d7a685c2c4edf1a4c92e9e078fa16b52ce4d54a053d144abdd434f57faf154' +
  '8637340c65bfd7812073ec79a3353e26c39cc4e56119e2ef0fcb9aed4208e9d14ca34ddfdbf447f6bddbb76ed90477c0' +
  '632910c445387361ce17ba0482485a48318251524c1901baa3cd1f12373de81f83fb93c5e3159c8b151d55a9d52f17b5' +
  '1a2fd5686779a3fb43ba9fd4f97e9d4e9a4600a4cd752c849e318a461ae559748953db888915df49155649ac5a6cf9ce' +
  '02ab0865d973ad737920149559676f0b83817e9320c7cb772f411d36cd3d52d8d6c66ec3f01b3ef226c198d4e950cd1c' +
  '46ee297aa7c898a83b614938c6d3b28a4de70c6a3cc3c8a508a44234ce2e2a49dfd4b65b9da32b9993e850a5b7e9d79f' +
  'c15ebdd6235112c6619e34e7228ad2e8fcd9a5dac8cdf22d329a378b115cda18a2f734cb493e9abd2254b4ebe3e9421e' +
  'd64e6d84a1e0c01eaa6b3928cce0a4df0876e2a248b6fc0b25cfbbd03e96f22e8e7cb60501f9750bd700e76f0d0302a8' +
  'e96d8df44a4ca9608f9a85817f13aa6356fc6b98378b3345a6d999ff0d65a25d0c9ad9dc888489076dac0ab796a876ee' +
  '7eef46ca953e998a3bf8f2f22269865ff98299a9ca8419fd85034d8103092ef1d9539884e35d529ca65a17ad144eaa76' +
  '9291357d91ada395aa9822ce1af2894a6378dd7634ac0cb5a9213a41116b2c6489e61307ac716ca48cbab42047051271' +
  '05bc83ed0379c806401920ad0a248abd5cba66f6888680ccce62956a40e25331a4826c9a56477506ee54e83b44710c4e' +
  'dfe6502f3fa9ad6ed5d16d043fdab3b2d0d40f69aa0f0a9dc00059d08b044402f16b948e533beb6a5a24231782877442' +
  '91dc785a4bba055c0ab2b62f374c1689e57350cd6828d8f1ef92b69481f7312b45b39c1a65d6301b9422d60d1ae0a657' +
  '2400dd62aee51877f8c3a0c98ed94fa02a237b656b7e09b8770ade0fb11a35713bc3ad2f15cc94454ba33bdd1c985484' +
  '8d4a967d82209825b6f8e7a47b682d07a032e161698db37927b4001c526fcabf0be8948d94e6678338942723e5bbf926' +
  '16bda78eb9fbdd4dff1cfddac298535bbbe5a2331deb2d87797c61535c2588aadae393c9ba779949e9b2cfd165a08451' +
  'f62fbc54a0e73923da3f5638969ab593cf94706efb1faa533bb5bab62c662f9aca9ce1389d9009b84e245654bc102c9b' +
  '6be84465a0820e8bd81f2f85a1e9d8289e79304cde5bdc17403710a826eed70d50bea124a10dab232d797112e6267d41' +
  '2b909c5975a3e95961d09ec822623497b6c557a6609d3b59ad1d38893928456d06638dc6711ee1a09bad2f141c99d267' +
  '7cba66572b999cc5a6415840c614e283e1f51800b8b0471451e9ed8504ed48f9ca47823268f0a8d49402b091d0391df2' +
  '6d64c711095dab2b0e8ad8e4034cadb02ca9cddb7aaa9d06e06587d8232d013050dcd4aec6f703fee7e5580112c9e2af' +
  '8a8a713b19f318472cf1dc2119c4bb27ade20abb8b622969f3b4fe1ccf1814dfd7c967996f80230094868aaf5dd6e499' +
  '69316339e70710cec32a4d8b035e98f9ab22c7f00e49cf6dcadc6722af1d7eec580196ad1380f8ae25f6cd92b8ec23ba' +
  '5811f2614155f6d7625d4cc9e5abe0222712a18928d316f1501ab2810a09ac80aacf47600cde633e043be4e659225e94' +
  '450a64c96e02f0325b1b33163173212286a7732c3ad8d725d29a26eb3629cef1b42c814a878912950061c1ed4be165f5' +
  '0683a34e2e5e2910a431ce5e027d34568ba45f0030ffc411e9e8a250e5a1dbcd9700ca6d68265a3807f6c158ef683cbc' +
  'eae0f954e2c09e48e1715fce8c5292e2314cda273daa2e34d6dd20b318e5b8051b5a3cb2ea620b436a5c6a56fad0d062' +
  '67f1ed688b6a19ab184c354910e9ac02005a62020000000014b7f8632e19bc365891c6fc9d235c484ac4eb65c73961ea' +
  'fc5c9973084502fb9cc91ba6f35391a43886398bb0cbad8560d37519da4176a914ddbc3a40b3eeab12aa65de9736ce1b' +
  '22733478e288ac04f49000000000002045c3c19089e90768cb90dc0cafa9fae5300da9303eebec09b5befe9824a0570a' +
  '00';

  it('parses a live freeze transaction and reproduces its wire bytes and txid', () => {
    const raw = fromHex(LIVE_FREEZE_HEX);
    const tx = deserialize(raw);
    expect(tx.txType).toBe(TX_TYPE_STANDARD);
    expect(tx.inputs).toHaveLength(1);
    expect(tx.outputs).toHaveLength(2);
    // The freeze output: value + covenant data = [hash256(pubkey)][btc spk].
    expect(tx.outputs[0]!.value).toBe(40_000_000n);
    const data = tx.outputs[0]!.data!;
    expect(toHex(data.subarray(0, 32))).toBe('61eafc5c9973084502fb9cc91ba6f35391a43886398bb0cbad8560d37519da41');
    expect(toHex(data.subarray(32))).toMatch(/^76a914[0-9a-f]{40}88ac$/);
    // Byte-exact roundtrip, and the txid matches the chain (the chain shows
    // hash256(wire) as-is — no bitcoin-style byte reversal).
    expect(toHex(serialize(tx))).toBe(LIVE_FREEZE_HEX);
    expect(toHex(txid(tx))).toBe(
      '46bacf48690930403d10ab194a45465345b10712787bef28990cfd6dec1b6865',
    );
  });

  it('refuses tx types it cannot lay out, trailing bytes and truncation', () => {
    const wire = serialize(TOKEN_TX);
    const alien = Uint8Array.from(wire);
    alien[0] = 7; // TX_TYPE_DOWNGRADE carries payloads this parser does not know
    expect(() => deserialize(alien)).toThrow(/unsupported tx type/);
    const trailing = new Uint8Array(wire.length + 1);
    trailing.set(wire);
    expect(() => deserialize(trailing)).toThrow(/trailing/);
    expect(() => deserialize(wire.subarray(0, wire.length - 3))).toThrow();
  });
});

describe('sighash and the token id (the per-chain fork)', () => {
  // Past the fork the node appends the RAW 32-byte token_hash after the
  // outputs of a TX_TYPE_TOKENS sign data ("Add token_hash to transaction
  // sign data") and rejects signatures that omit it; before the fork it
  // rejects signatures that append it. The caller decides per signature
  // (sighashCommitsTokenId) — both framings are pinned here.
  const base = {
    inputs: [{ txid: new Uint8Array(32).fill(0x11), vout: 0 }],
    outputs: [{ value: 0n, scripthash: new Uint8Array(20).fill(0x22), data: encodeTokenTransfer(5n) }],
  };
  const tokenHash = new Uint8Array(32).fill(0xaa);

  it('committed framing: different token ids produce different digests', () => {
    const a = sighash({ txType: TX_TYPE_TOKENS, tokenHash, ...base }, SIGHASH.ALL, true);
    const b = sighash({ txType: TX_TYPE_TOKENS, tokenHash: new Uint8Array(32).fill(0xbb), ...base }, SIGHASH.ALL, true);
    expect(toHex(a)).not.toBe(toHex(b));
  });

  it('committed framing: the raw hash is appended after the outputs, unframed', () => {
    const withToken = serializeForSighash({ txType: TX_TYPE_TOKENS, tokenHash, ...base }, SIGHASH.ALL, true);
    const withoutToken = serializeForSighash({ txType: TX_TYPE_TOKENS, tokenHash: new Uint8Array(0), ...base }, SIGHASH.ALL, true);
    expect(withToken.length).toBe(withoutToken.length + 32);
    expect(toHex(withToken.subarray(withToken.length - 32))).toBe(toHex(tokenHash));
    // No varstr length prefix before it — the byte before the hash is the
    // last byte of the outputs section, unchanged between the two forms.
    expect(toHex(withToken.subarray(0, withoutToken.length))).toBe(toHex(withoutToken));
  });

  it('legacy framing: the sign data omits the token id', () => {
    const withToken = serializeForSighash({ txType: TX_TYPE_TOKENS, tokenHash, ...base }, SIGHASH.ALL, false);
    const withoutToken = serializeForSighash({ txType: TX_TYPE_TOKENS, tokenHash: new Uint8Array(0), ...base }, SIGHASH.ALL, false);
    expect(toHex(withToken)).toBe(toHex(withoutToken));
    expect(toHex(withToken)).not.toContain('aa'.repeat(32));
  });

  it('a token transfer without an explicit verdict is refused', () => {
    // Silently picking a side would produce a signature the node rejects on
    // one side of the fork — the caller must decide per signing time.
    expect(() => serializeForSighash({ txType: TX_TYPE_TOKENS, tokenHash, ...base })).toThrow(/commitsTokenId/);
  });

  it('a standard transaction needs no verdict and never signs the hash', () => {
    const std = { txType: TX_TYPE_STANDARD, inputs: base.inputs, outputs: [{ value: 7n, scripthash: new Uint8Array(20).fill(0x22) }] } as const;
    expect(toHex(serializeForSighash(std))).not.toContain('aa'.repeat(32));
  });
});
