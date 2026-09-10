// JSON with exact 64-bit integers.
//
// The node renders every numeric field as a JSON number — including uint64
// token amounts, whose top range does not survive JavaScript's JSON.parse
// (doubles round above 2^53, silently). JSON itself carries the digits
// exactly; only the default parsing loses them. So before parsing, integer
// literals that would not round-trip through a double are wrapped in quotes,
// turning them into strings — which every amount parser here accepts and
// feeds to BigInt() for the exact value.
//
// Floats and exponent forms are left alone (they are already lossy by
// nature and never carry amounts), as is anything inside string values.

const DIGITS = new Set('0123456789');
const NUMBER_CHARS = new Set('0123456789+-.eE');

/** True when the literal is an integer too large to survive Number parsing. */
function needsQuoting(literal: string): boolean {
  return !/[.eE]/.test(literal) && !Number.isSafeInteger(Number(literal));
}

/**
 * Quote integer literals that exceed the safe-integer range, so JSON.parse
 * keeps their digits as strings. Input must be syntactically valid JSON —
 * on garbage this is garbage-in/garbage-out and JSON.parse still throws.
 */
export function quoteLargeIntegers(text: string): string {
  let out = '';
  let copied = 0; // everything before this offset is already in `out`
  let i = 0;
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '"') {
      // Skip string values wholesale (with escapes) — digits inside them
      // are data, not number literals.
      i += 1;
      while (i < text.length) {
        const inner = text[i]!;
        if (inner === '\\') {
          i += 2;
          continue;
        }
        i += 1;
        if (inner === '"') break;
      }
      continue;
    }
    if (ch === '-' || DIGITS.has(ch)) {
      const start = i;
      while (i < text.length && NUMBER_CHARS.has(text[i]!)) i += 1;
      const literal = text.slice(start, i);
      if (needsQuoting(literal)) {
        out += text.slice(copied, start) + '"' + literal + '"';
        copied = i;
      }
      continue;
    }
    i += 1;
  }
  return copied === 0 ? text : out + text.slice(copied);
}
