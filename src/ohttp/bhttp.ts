/**
 * Binary HTTP (RFC 9292) — the known-length subset this demo actually sends.
 *
 * Hand-rolled because the byte layout is part of what the lab shows: the
 * request the relay carries is a real BHTTP message under real HPKE, not a
 * placeholder string. This is NOT a conformance-grade codec — indeterminate-
 * length framing, informational (1xx) responses, and trailer fields are out
 * of scope and rejected explicitly (see the in-page "what this isn't" note).
 */
import { concatBytes, utf8 } from '@hub/hpke/bytes';

export class BhttpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BhttpError';
  }
}

export interface BhttpRequest {
  method: string;
  scheme: string;
  authority: string;
  path: string;
  headers: [string, string][];
  content: Uint8Array;
}

export interface BhttpResponse {
  status: number;
  headers: [string, string][];
  content: Uint8Array;
}

const FRAMING_REQUEST_KNOWN = 0;
const FRAMING_RESPONSE_KNOWN = 1;

/** QUIC variable-length integer (RFC 9000 §16), minimal encoding. */
export function encodeVarint(n: number): Uint8Array {
  if (!Number.isInteger(n) || n < 0) throw new BhttpError(`varint: not a non-negative integer: ${n}`);
  if (n < 2 ** 6) return new Uint8Array([n]);
  if (n < 2 ** 14) return new Uint8Array([0x40 | (n >> 8), n & 0xff]);
  if (n < 2 ** 30) {
    return new Uint8Array([0x80 | (n >>> 24), (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff]);
  }
  // 62-bit form exists in QUIC; nothing this demo encodes gets near it.
  throw new BhttpError(`varint: value too large for this demo's codec: ${n}`);
}

/** A cursor over the input; decodeVarint returns the value and advances. */
class Reader {
  private pos = 0;
  constructor(private readonly buf: Uint8Array) {}

  /** True once every byte has been consumed. */
  get done(): boolean {
    return this.pos >= this.buf.length;
  }

  get offset(): number {
    return this.pos;
  }

  varint(what: string): number {
    if (this.done) throw new BhttpError(`truncated inside a length field (${what})`);
    const first = this.buf[this.pos];
    const lenBytes = 1 << (first >> 6);
    if (this.pos + lenBytes > this.buf.length) {
      throw new BhttpError(`truncated inside a length field (${what})`);
    }
    let value = first & 0x3f;
    for (let i = 1; i < lenBytes; i++) value = value * 256 + this.buf[this.pos + i];
    if (value > Number.MAX_SAFE_INTEGER) throw new BhttpError(`varint too large (${what})`);
    this.pos += lenBytes;
    return value;
  }

  bytes(length: number, what: string): Uint8Array {
    if (this.pos + length > this.buf.length) {
      throw new BhttpError(`declared ${what} length ${length} overruns the message`);
    }
    const out = this.buf.slice(this.pos, this.pos + length);
    this.pos += length;
    return out;
  }

  /** RFC 9292 §3.8: any remaining bytes after truncation must be zero padding. */
  expectOnlyPadding(): void {
    for (let i = this.pos; i < this.buf.length; i++) {
      if (this.buf[i] !== 0) {
        throw new BhttpError(`non-zero byte 0x${this.buf[i].toString(16)} after final section (offset ${i})`);
      }
    }
    this.pos = this.buf.length;
  }
}

function lengthPrefixed(bytes: Uint8Array): Uint8Array {
  return concatBytes(encodeVarint(bytes.length), bytes);
}

const decoder = new TextDecoder('utf-8', { fatal: true });

function decodeAscii(bytes: Uint8Array, what: string): string {
  let s: string;
  try {
    s = decoder.decode(bytes);
  } catch {
    throw new BhttpError(`${what} is not valid UTF-8`);
  }
  // Field names/values and control data are token/URI material; reject control chars.
  if (/[\x00-\x1f\x7f]/.test(s)) throw new BhttpError(`${what} contains control characters`);
  return s;
}

/** Known-length field section: total length, then (name-len, name, value-len, value)*. */
function encodeFieldSection(headers: [string, string][]): Uint8Array {
  const parts: Uint8Array[] = [];
  for (const [name, value] of headers) {
    if (name.length === 0) throw new BhttpError('field name must not be empty');
    if (name !== name.toLowerCase()) throw new BhttpError(`field name must be lowercase: ${name}`);
    parts.push(lengthPrefixed(utf8(name)), lengthPrefixed(utf8(value)));
  }
  const body = concatBytes(...parts);
  return concatBytes(encodeVarint(body.length), body);
}

function decodeFieldSection(r: Reader): [string, string][] {
  const total = r.varint('field section length');
  const body = r.bytes(total, 'field section');
  const inner = new Reader(body);
  const out: [string, string][] = [];
  while (!inner.done) {
    const name = decodeAscii(inner.bytes(inner.varint('field name length'), 'field name'), 'field name');
    const value = decodeAscii(inner.bytes(inner.varint('field value length'), 'field value'), 'field value');
    if (name.length === 0) throw new BhttpError('field name must not be empty');
    out.push([name, value]);
  }
  return out;
}

/**
 * Encode a known-length request. Trailing empty sections are omitted
 * (RFC 9292 §3.8 truncation) — this is what makes the RFC 9458 example's
 * 25-byte GET reproduce byte-for-byte.
 */
export function encodeRequest(req: BhttpRequest): Uint8Array {
  for (const [part, what] of [
    [req.method, 'method'],
    [req.scheme, 'scheme'],
    [req.authority, 'authority'],
    [req.path, 'path'],
  ] as const) {
    if (part.length === 0 && what !== 'authority') throw new BhttpError(`${what} must not be empty`);
    if (/[\x00-\x1f\x7f]/.test(part)) throw new BhttpError(`${what} contains control characters`);
  }
  const parts: Uint8Array[] = [
    encodeVarint(FRAMING_REQUEST_KNOWN),
    lengthPrefixed(utf8(req.method)),
    lengthPrefixed(utf8(req.scheme)),
    lengthPrefixed(utf8(req.authority)),
    lengthPrefixed(utf8(req.path)),
  ];
  if (req.headers.length > 0 || req.content.length > 0) parts.push(encodeFieldSection(req.headers));
  if (req.content.length > 0) parts.push(lengthPrefixed(req.content));
  // Trailer section: this demo never sends trailers, so it is always truncated away.
  return concatBytes(...parts);
}

export function decodeRequest(bytes: Uint8Array): BhttpRequest {
  const r = new Reader(bytes);
  const framing = r.varint('framing indicator');
  if (framing !== FRAMING_REQUEST_KNOWN) {
    throw new BhttpError(
      `unsupported framing indicator ${framing} — this codec handles known-length requests only`,
    );
  }
  const method = decodeAscii(r.bytes(r.varint('method length'), 'method'), 'method');
  const scheme = decodeAscii(r.bytes(r.varint('scheme length'), 'scheme'), 'scheme');
  const authority = decodeAscii(r.bytes(r.varint('authority length'), 'authority'), 'authority');
  const path = decodeAscii(r.bytes(r.varint('path length'), 'path'), 'path');
  if (method.length === 0) throw new BhttpError('method must not be empty');
  const headers = r.done ? [] : decodeFieldSection(r);
  const content = r.done ? new Uint8Array(0) : r.bytes(r.varint('content length'), 'content');
  if (!r.done) {
    const trailers = decodeFieldSection(r);
    if (trailers.length > 0) throw new BhttpError('trailer fields are out of scope for this demo');
  }
  r.expectOnlyPadding();
  return { method, scheme, authority, path, headers, content };
}

/**
 * Append zero-byte padding up to `totalLength` (RFC 9292 §3.8) — the length
 * hiding OHTTP itself does not provide. Decoders skip trailing zeros, so a
 * padded message decodes to the identical request; only the ciphertext size
 * changes. This is the countermeasure the correlation exhibit demonstrates.
 */
export function padMessage(encoded: Uint8Array, totalLength: number): Uint8Array {
  if (totalLength < encoded.length) {
    throw new BhttpError(
      `cannot pad to ${totalLength} bytes: message is already ${encoded.length} bytes`,
    );
  }
  const out = new Uint8Array(totalLength);
  out.set(encoded, 0);
  return out;
}

/** Encode a known-length final response. Informational (1xx) responses are out of scope. */
export function encodeResponse(res: BhttpResponse): Uint8Array {
  if (!Number.isInteger(res.status) || res.status < 200 || res.status > 599) {
    throw new BhttpError(
      `status ${res.status} is not a final status code (informational responses are out of scope)`,
    );
  }
  const parts: Uint8Array[] = [encodeVarint(FRAMING_RESPONSE_KNOWN), encodeVarint(res.status)];
  if (res.headers.length > 0 || res.content.length > 0) parts.push(encodeFieldSection(res.headers));
  if (res.content.length > 0) parts.push(lengthPrefixed(res.content));
  return concatBytes(...parts);
}

export function decodeResponse(bytes: Uint8Array): BhttpResponse {
  const r = new Reader(bytes);
  const framing = r.varint('framing indicator');
  if (framing !== FRAMING_RESPONSE_KNOWN) {
    throw new BhttpError(
      `unsupported framing indicator ${framing} — this codec handles known-length responses only`,
    );
  }
  const status = r.varint('status code');
  if (status < 200 || status > 599) {
    throw new BhttpError(`status ${status} is not a final status code (1xx is out of scope)`);
  }
  const headers = r.done ? [] : decodeFieldSection(r);
  const content = r.done ? new Uint8Array(0) : r.bytes(r.varint('content length'), 'content');
  if (!r.done) {
    const trailers = decodeFieldSection(r);
    if (trailers.length > 0) throw new BhttpError('trailer fields are out of scope for this demo');
  }
  r.expectOnlyPadding();
  return { status, headers, content };
}
