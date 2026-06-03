// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

// A strict JSON parser ported to match Go's contract.ParseJSONStrict:
//
//   - duplicate object keys at any depth are rejected,
//   - trailing non-whitespace tokens after the top-level value are rejected,
//   - number literals are preserved verbatim (as RawNumber) so the I-JSON
//     safe-integer guard can inspect the source text before any lossy
//     float64 conversion, exactly as Go's json.Number does.
//
// JSON.parse cannot do any of these (it keeps the last duplicate key, silently
// ignores trailing whitespace only, and converts numbers to float64), so we
// hand-roll the parse. The grammar implemented is RFC 8259 JSON.

// FatalParseError marks an envelope-fatal parse condition: malformed JSON,
// duplicate key, or trailing tokens. The CLI maps it to exit 1.
export class FatalParseError extends Error {
  readonly code = 1;
}

// RawNumber wraps a JSON number literal verbatim. The verifier never converts it
// to a JS number (which would round outside the I-JSON safe range); the
// safe-number guard validates the literal text and typed-string fields carry the
// large values.
export class RawNumber {
  constructor(readonly literal: string) {}
}

const WHITESPACE = new Set([" ", "\t", "\n", "\r"]);

class Parser {
  private i = 0;
  constructor(private readonly s: string) {}

  parse(): unknown {
    this.skipWhitespace();
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.i !== this.s.length) {
      throw new FatalParseError(`trailing tokens after JSON value at offset ${this.i}`);
    }
    return value;
  }

  private skipWhitespace(): void {
    while (this.i < this.s.length && WHITESPACE.has(this.s[this.i] as string)) {
      this.i++;
    }
  }

  private parseValue(): unknown {
    this.skipWhitespace();
    if (this.i >= this.s.length) throw new FatalParseError("unexpected end of JSON input");
    const c = this.s[this.i];
    switch (c) {
      case "{":
        return this.parseObject();
      case "[":
        return this.parseArray();
      case '"':
        return this.parseString();
      case "t":
        return this.parseLiteral("true", true);
      case "f":
        return this.parseLiteral("false", false);
      case "n":
        return this.parseLiteral("null", null);
      default:
        if (c === "-" || (c !== undefined && c >= "0" && c <= "9")) {
          return this.parseNumber();
        }
        throw new FatalParseError(`unexpected character ${JSON.stringify(c)} at offset ${this.i}`);
    }
  }

  private parseLiteral<T>(word: string, value: T): T {
    if (this.s.slice(this.i, this.i + word.length) !== word) {
      throw new FatalParseError(`invalid literal at offset ${this.i}`);
    }
    this.i += word.length;
    return value;
  }

  private parseObject(): Record<string, unknown> {
    this.i++; // consume {
    const obj: Record<string, unknown> = {};
    const seen = new Set<string>();
    this.skipWhitespace();
    if (this.s[this.i] === "}") {
      this.i++;
      return obj;
    }
    for (;;) {
      this.skipWhitespace();
      if (this.s[this.i] !== '"') {
        throw new FatalParseError(`expected string key at offset ${this.i}`);
      }
      const key = this.parseString();
      if (seen.has(key)) {
        throw new FatalParseError(`duplicate object key: ${key}`);
      }
      seen.add(key);
      this.skipWhitespace();
      if (this.s[this.i] !== ":") {
        throw new FatalParseError(`expected ':' at offset ${this.i}`);
      }
      this.i++; // consume :
      obj[key] = this.parseValue();
      this.skipWhitespace();
      const next = this.s[this.i];
      if (next === ",") {
        this.i++;
        continue;
      }
      if (next === "}") {
        this.i++;
        return obj;
      }
      throw new FatalParseError(`expected ',' or '}' at offset ${this.i}`);
    }
  }

  private parseArray(): unknown[] {
    this.i++; // consume [
    const arr: unknown[] = [];
    this.skipWhitespace();
    if (this.s[this.i] === "]") {
      this.i++;
      return arr;
    }
    for (;;) {
      arr.push(this.parseValue());
      this.skipWhitespace();
      const next = this.s[this.i];
      if (next === ",") {
        this.i++;
        continue;
      }
      if (next === "]") {
        this.i++;
        return arr;
      }
      throw new FatalParseError(`expected ',' or ']' at offset ${this.i}`);
    }
  }

  private parseString(): string {
    this.i++; // consume opening quote
    let out = "";
    for (;;) {
      if (this.i >= this.s.length) throw new FatalParseError("unterminated string");
      const ch = this.s[this.i] as string;
      if (ch === '"') {
        this.i++;
        return out;
      }
      if (ch === "\\") {
        out += this.parseEscape();
        continue;
      }
      // Control characters U+0000..U+001F must be escaped in JSON.
      if (ch < " ") {
        throw new FatalParseError(`unescaped control character at offset ${this.i}`);
      }
      out += ch;
      this.i++;
    }
  }

  private parseEscape(): string {
    this.i++; // consume backslash
    const esc = this.s[this.i];
    switch (esc) {
      case '"':
        this.i++;
        return '"';
      case "\\":
        this.i++;
        return "\\";
      case "/":
        this.i++;
        return "/";
      case "b":
        this.i++;
        return "\b";
      case "f":
        this.i++;
        return "\f";
      case "n":
        this.i++;
        return "\n";
      case "r":
        this.i++;
        return "\r";
      case "t":
        this.i++;
        return "\t";
      case "u":
        return this.parseUnicodeEscape();
      default:
        throw new FatalParseError(`invalid escape \\${esc ?? ""} at offset ${this.i}`);
    }
  }

  private parseUnicodeEscape(): string {
    this.i++; // consume u
    const hi = this.readHex4();
    if (hi >= 0xd800 && hi <= 0xdbff) {
      // High surrogate. Match Go encoding/json (and Python json): pair ONLY with
      // an immediately following low-surrogate escape; otherwise the high alone
      // decodes to U+FFFD and the next escape is reprocessed. This must be
      // NON-GREEDY -- a following \u that is not a low surrogate is left in place,
      // not consumed -- so a high,high,low run (\uD800 \uDBFF \uDC00) yields
      // U+FFFD + the astral pair, not three U+FFFD. Emitting U+FFFD at decode (not
      // a lone surrogate) also makes the in-memory value match Go for raw string
      // comparisons (e.g. mediator_id trust pinning), not just canonical output.
      if (this.s[this.i] === "\\" && this.s[this.i + 1] === "u") {
        const saved = this.i;
        this.i += 2;
        const lo = this.readHex4();
        if (lo >= 0xdc00 && lo <= 0xdfff) {
          return String.fromCodePoint((hi - 0xd800) * 0x400 + (lo - 0xdc00) + 0x10000);
        }
        this.i = saved; // rewind; reprocess the second escape independently
      }
      return "\uFFFD";
    }
    if (hi >= 0xdc00 && hi <= 0xdfff) {
      return "\uFFFD"; // lone low surrogate
    }
    return String.fromCharCode(hi);
  }

  private readHex4(): number {
    const hex = this.s.slice(this.i, this.i + 4);
    if (hex.length !== 4 || !/^[0-9a-fA-F]{4}$/u.test(hex)) {
      throw new FatalParseError(`invalid \\u escape at offset ${this.i}`);
    }
    this.i += 4;
    return Number.parseInt(hex, 16);
  }

  private parseNumber(): RawNumber {
    const start = this.i;
    if (this.s[this.i] === "-") this.i++;
    if (this.s[this.i] === "0") {
      this.i++;
    } else if (this.isDigit(this.s[this.i])) {
      while (this.isDigit(this.s[this.i])) this.i++;
    } else {
      throw new FatalParseError(`invalid number at offset ${start}`);
    }
    if (this.s[this.i] === ".") {
      this.i++;
      if (!this.isDigit(this.s[this.i])) {
        throw new FatalParseError(`invalid number fraction at offset ${this.i}`);
      }
      while (this.isDigit(this.s[this.i])) this.i++;
    }
    if (this.s[this.i] === "e" || this.s[this.i] === "E") {
      this.i++;
      if (this.s[this.i] === "+" || this.s[this.i] === "-") this.i++;
      if (!this.isDigit(this.s[this.i])) {
        throw new FatalParseError(`invalid number exponent at offset ${this.i}`);
      }
      while (this.isDigit(this.s[this.i])) this.i++;
    }
    return new RawNumber(this.s.slice(start, this.i));
  }

  private isDigit(c: string | undefined): boolean {
    return c !== undefined && c >= "0" && c <= "9";
  }
}

// parseJSONStrict parses with duplicate-key, trailing-token, and number-literal
// fidelity. The returned tree carries RawNumber for every JSON number.
export function parseJSONStrict(text: string): unknown {
  return new Parser(text).parse();
}
