import { describe, expect, it } from 'vitest';
import { quoteLargeIntegers } from './jsonNumbers';

const parse = (text: string): unknown => JSON.parse(quoteLargeIntegers(text));

describe('quoteLargeIntegers', () => {
  it('quotes integers above the safe range so the digits survive', () => {
    // uint64 max — a real token_amount the node can emit as a JSON number.
    expect(parse('{"token_amount":18446744073709551615}')).toEqual({
      token_amount: '18446744073709551615',
    });
    expect(BigInt('18446744073709551615')).toBe(0xffffffffffffffffn);
  });

  it('quotes int64 min/max and negatives beyond the safe range', () => {
    expect(parse('[9223372036854775807,-9223372036854775808]')).toEqual([
      '9223372036854775807',
      '-9223372036854775808',
    ]);
  });

  it('leaves safe integers, floats and exponents as numbers', () => {
    expect(parse('{"a":9007199254740991,"b":-1,"c":0.5,"d":1e5,"e":123}')).toEqual({
      a: 9007199254740991,
      b: -1,
      c: 0.5,
      d: 1e5,
      e: 123,
    });
  });

  it('never touches digits inside string values', () => {
    const text = '{"txid":"99999999999999999999","note":"pay \\" 18446744073709551615"}';
    expect(parse(text)).toEqual({
      txid: '99999999999999999999',
      note: 'pay " 18446744073709551615',
    });
    expect(quoteLargeIntegers(text)).toBe(text);
  });

  it('handles big integers in arrays and nested objects', () => {
    expect(parse('{"txs":[["ab",99999999999999999999,5]]}')).toEqual({
      txs: [['ab', '99999999999999999999', 5]],
    });
  });

  it('returns the input unchanged when nothing needs quoting', () => {
    const text = '{"height":850105,"fee":1000}';
    expect(quoteLargeIntegers(text)).toBe(text);
  });
});
