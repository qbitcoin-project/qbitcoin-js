import { describe, expect, it } from 'vitest';
import { OP_CHECKSIG, opPushdata, scriptP2PK, scriptType } from './script';
import { fromHex, toHex } from './encoding/hex';

describe('opPushdata — boundaries', () => {
  it('encodes empty as single 0x00 byte', () => {
    expect(toHex(opPushdata(new Uint8Array(0)))).toBe('00');
  });

  it('encodes 1 byte', () => {
    expect(toHex(opPushdata(new Uint8Array([0xaa])))).toBe('01aa');
  });

  it('encodes 33 bytes (compressed pubkey) with single-byte prefix 0x21', () => {
    const pubkey = fromHex(
      '039b66566d3acb6bd203a0a61f4e0105b84f12e107aaf27f30466807121197d10c',
    );
    const out = opPushdata(pubkey);
    expect(out[0]).toBe(0x21);
    expect(out.length).toBe(34);
    expect(toHex(out.slice(1))).toBe(toHex(pubkey));
  });

  it('encodes 75 bytes with single-byte prefix 0x4b', () => {
    const data = new Uint8Array(75).fill(0xaa);
    expect(opPushdata(data)[0]).toBe(0x4b);
  });

  it('encodes 76 bytes with OP_PUSHDATA1', () => {
    const data = new Uint8Array(76).fill(0xaa);
    const out = opPushdata(data);
    expect(out[0]).toBe(0x4c); // OP_PUSHDATA1
    expect(out[1]).toBe(76);
    expect(out.length).toBe(78);
  });

  it('encodes 255 bytes with OP_PUSHDATA1', () => {
    const data = new Uint8Array(255).fill(0xaa);
    const out = opPushdata(data);
    expect(out[0]).toBe(0x4c);
    expect(out[1]).toBe(0xff);
  });

  it('encodes 256 bytes with OP_PUSHDATA2', () => {
    const data = new Uint8Array(256).fill(0xaa);
    const out = opPushdata(data);
    expect(out[0]).toBe(0x4d); // OP_PUSHDATA2
    expect(out[1]).toBe(0x00); // 256 = 0x0100 LE
    expect(out[2]).toBe(0x01);
  });

  it('encodes 897-byte Falcon pubkey with OP_PUSHDATA2', () => {
    const data = new Uint8Array(897).fill(0xaa);
    const out = opPushdata(data);
    expect(out[0]).toBe(0x4d);
    // 897 = 0x0381 → LE: 81 03
    expect(out[1]).toBe(0x81);
    expect(out[2]).toBe(0x03);
    expect(out.length).toBe(900);
  });

  it('encodes 65536 bytes with OP_PUSHDATA4', () => {
    const data = new Uint8Array(65536).fill(0xaa);
    const out = opPushdata(data);
    expect(out[0]).toBe(0x4e); // OP_PUSHDATA4
    expect(out.length).toBe(5 + 65536);
  });
});

describe('scriptP2PK', () => {
  // Real test vector from live mempool dump.
  // redeem_script: 21 039b66566d3acb6bd203a0a61f4e0105b84f12e107aaf27f30466807121197d10c ac
  it('matches the live network redeem_script byte-for-byte', () => {
    const pubkey = fromHex(
      '039b66566d3acb6bd203a0a61f4e0105b84f12e107aaf27f30466807121197d10c',
    );
    const expected =
      '21039b66566d3acb6bd203a0a61f4e0105b84f12e107aaf27f30466807121197d10cac';
    expect(toHex(scriptP2PK(pubkey))).toBe(expected);
  });

  it('matches second mainnet vector', () => {
    const pubkey = fromHex(
      '02b17362c10f06ff75a7039798de7301991fc371aeccf1aba3c8849a2f3f06322c',
    );
    expect(toHex(scriptP2PK(pubkey))).toBe(
      '2102b17362c10f06ff75a7039798de7301991fc371aeccf1aba3c8849a2f3f06322cac',
    );
  });

  it('appends OP_CHECKSIG (0xac) as the final byte', () => {
    const pubkey = new Uint8Array(33).fill(0x02);
    const out = scriptP2PK(pubkey);
    expect(out[out.length - 1]).toBe(OP_CHECKSIG);
  });

  it('produces 35-byte total for 33-byte compressed pubkey', () => {
    const pubkey = new Uint8Array(33);
    expect(scriptP2PK(pubkey).length).toBe(35);
  });

  it('builds the 901-byte Falcon-512 P2PK script (OP_PUSHDATA2 + 897 B)', () => {
    const pubkey = new Uint8Array(897);
    pubkey[0] = 0x09; // Falcon-512 version byte
    for (let i = 1; i < pubkey.length; i++) pubkey[i] = i % 256;
    const out = scriptP2PK(pubkey);
    expect(out.length).toBe(901);
    // OP_PUSHDATA2 + 897 as little-endian u16 (0x0381 → 81 03).
    expect(toHex(out.slice(0, 3))).toBe('4d8103');
    expect(toHex(out.slice(3, 900))).toBe(toHex(pubkey));
    expect(out[900]).toBe(OP_CHECKSIG);
  });
});

describe('scriptType', () => {
  it('classifies a P2PK script', () => {
    const pubkey = new Uint8Array(33).fill(0x02);
    expect(scriptType(scriptP2PK(pubkey))).toBe('P2PK');
  });

  it('classifies a P2PKH script (leading OP_DUP)', () => {
    // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    const script = fromHex(
      '76a914000000000000000000000000000000000000000088ac',
    );
    expect(scriptType(script)).toBe('P2PKH');
  });

  it('classifies empty script as unknown', () => {
    expect(scriptType(new Uint8Array(0))).toBe('unknown');
  });
});
