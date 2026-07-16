/**
 * Known-answer tests from RFC 9458 Appendix A ("Complete Example of a Request
 * and Response") — every hex value in the appendix is checked byte-for-byte.
 *
 * The appendix pins the ephemeral X25519 SECRET key directly (not a seed),
 * and the hub's HPKE module only derives ephemerals from seeds (DeriveKeyPair,
 * RFC 9180 §7.1.3) — so the request ciphertext is reproduced from the
 * recipient side: decapsulate with skR, then seal with a sender context built
 * from the identical schedule. Same key, same base nonce, same seq 0.
 */
import { describe, expect, it } from 'vitest';
import { bytesToHex, hexToBytes, utf8 } from '@hub/hpke/bytes';
import { AEAD_AES_128_GCM } from '@hub/hpke/consts';
import { HpkeContext } from '@hub/hpke/context';
import { publicKeyOf } from '@hub/hpke/hpke';
import { decodeRequest, decodeResponse, encodeRequest, encodeResponse } from './bhttp';
import { decodeKeyConfig, encodeKeyConfig } from './keyconfig';
import { decapsulateRequest, encodeHeader, parseHeader, requestInfo } from './request';
import { decapsulateResponse, deriveResponseKeys, encapsulateResponse } from './response';

// —— the vector, verbatim from RFC 9458 Appendix A ——
const SKR = '3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a';
const KEY_CONFIG =
  '01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500080001000100010003';
const BHTTP_REQUEST = '00034745540568747470730b6578616d706c652e636f6d012f';
const SKE = 'bc51d5e930bda26589890ac7032f70ad12e4ecb37abb1b65b1256c9c48999c73';
const PKE = '4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472';
const INFO = '6d6573736167652f626874747020726571756573740001002000010001';
const ENC_REQUEST =
  '010020000100014b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472' +
  '6374e469135906992e1268c594d2a10c695d858c40a026e7965e7d86b83dd440b2c0185204b4d63525';
const BHTTP_RESPONSE = '0140c8';
const EXPORT_SECRET = '62d87a6ba569ee81014c2641f52bea36';
const RESPONSE_NONCE = 'c789e7151fcba46158ca84b04464910d';
const SALT =
  '4b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472c789e7151fcba46158ca84b04464910d';
const PRK = '979aaeae066cf211ab407b31ae49767f344e1501e475c84e8aff547cc5a683db';
const AEAD_KEY = '5d0172a080e428b16d298c4ea0db620d';
const AEAD_NONCE = 'f6bf1aeb88d6df87007fa263';
const ENC_RESPONSE =
  'c789e7151fcba46158ca84b04464910d86f9013e404feea014e7be4a441f234f857fbd';

const skR = hexToBytes(SKR);
const keyConfig = decodeKeyConfig(hexToBytes(KEY_CONFIG));

describe('RFC 9458 Appendix A — key configuration', () => {
  it('KAT: the gateway secret key yields the public key in the key config', () => {
    expect(bytesToHex(publicKeyOf(skR))).toBe(bytesToHex(keyConfig.pk));
  });

  it('KAT: decode → encode round-trips the exact key config bytes', () => {
    expect(bytesToHex(encodeKeyConfig(keyConfig))).toBe(KEY_CONFIG);
  });

  it('KAT: key config advertises key ID 1 and both symmetric suites', () => {
    expect(keyConfig.keyId).toBe(1);
    expect(keyConfig.kemId).toBe(0x0020);
    expect(keyConfig.suites).toEqual([
      { kdfId: 0x0001, aeadId: 0x0001 },
      { kdfId: 0x0001, aeadId: 0x0003 },
    ]);
  });
});

describe('RFC 9458 Appendix A — binary HTTP', () => {
  it('KAT: encoding GET https://example.com/ reproduces the 25-byte message', () => {
    const encoded = encodeRequest({
      method: 'GET',
      scheme: 'https',
      authority: 'example.com',
      path: '/',
      headers: [],
      content: new Uint8Array(0),
    });
    expect(bytesToHex(encoded)).toBe(BHTTP_REQUEST);
  });

  it('KAT: decoding the vector recovers the request fields', () => {
    const req = decodeRequest(hexToBytes(BHTTP_REQUEST));
    expect(req).toEqual({
      method: 'GET',
      scheme: 'https',
      authority: 'example.com',
      path: '/',
      headers: [],
      content: new Uint8Array(0),
    });
  });

  it('KAT: encoding a bare 200 response reproduces 0140c8', () => {
    const encoded = encodeResponse({ status: 200, headers: [], content: new Uint8Array(0) });
    expect(bytesToHex(encoded)).toBe(BHTTP_RESPONSE);
  });

  it('KAT: decoding 0140c8 yields status 200 and nothing else', () => {
    expect(decodeResponse(hexToBytes(BHTTP_RESPONSE))).toEqual({
      status: 200,
      headers: [],
      content: new Uint8Array(0),
    });
  });
});

describe('RFC 9458 Appendix A — request encapsulation', () => {
  it('KAT: the pinned ephemeral secret yields the pinned ephemeral public key', () => {
    expect(bytesToHex(publicKeyOf(hexToBytes(SKE)))).toBe(PKE);
  });

  it('KAT: info = "message/bhttp request" || 0x00 || hdr', () => {
    const hdr = encodeHeader({ keyId: 1, kemId: 0x0020, kdfId: 0x0001, aeadId: AEAD_AES_128_GCM });
    expect(bytesToHex(requestInfo(hdr))).toBe(INFO);
  });

  it('KAT: the encapsulated request parses to (keyID 1, X25519, HKDF-SHA256, AES-128-GCM) and carries pkE', () => {
    const enc = hexToBytes(ENC_REQUEST);
    expect(parseHeader(enc)).toEqual({ keyId: 1, kemId: 0x0020, kdfId: 0x0001, aeadId: 0x0001 });
    expect(bytesToHex(enc.slice(7, 39))).toBe(PKE);
  });

  it('KAT: the gateway decapsulates the vector to the exact BHTTP request', async () => {
    const result = await decapsulateRequest(hexToBytes(ENC_REQUEST), keyConfig, skR);
    expect(bytesToHex(result.plaintext)).toBe(BHTTP_REQUEST);
  });

  it('KAT: sealing with the derived schedule reproduces the exact request ciphertext', async () => {
    const result = await decapsulateRequest(hexToBytes(ENC_REQUEST), keyConfig, skR);
    const sender = new HpkeContext('sender', result.header.aeadId, result.setup.schedule);
    const { ct } = await sender.seal(new Uint8Array(0), hexToBytes(BHTTP_REQUEST));
    expect(bytesToHex(ct)).toBe(bytesToHex(result.ct));
    expect(bytesToHex(ct)).toBe(ENC_REQUEST.slice((7 + 32) * 2));
  });
});

describe('RFC 9458 Appendix A — response encapsulation', () => {
  async function gatewayContext() {
    return decapsulateRequest(hexToBytes(ENC_REQUEST), keyConfig, skR);
  }

  it('KAT: exported secret, salt, prk, key, and nonce all match the vector', async () => {
    const g = await gatewayContext();
    const s = deriveResponseKeys(g.context, g.enc, g.header.aeadId, hexToBytes(RESPONSE_NONCE));
    expect(bytesToHex(s.secret)).toBe(EXPORT_SECRET);
    expect(bytesToHex(s.salt)).toBe(SALT);
    expect(bytesToHex(s.prk)).toBe(PRK);
    expect(bytesToHex(s.aeadKey)).toBe(AEAD_KEY);
    expect(bytesToHex(s.aeadNonce)).toBe(AEAD_NONCE);
  });

  it('KAT: sealing the 200 with the pinned nonce reproduces the encapsulated response', async () => {
    const g = await gatewayContext();
    const res = await encapsulateResponse(
      g.context,
      g.enc,
      g.header.aeadId,
      hexToBytes(BHTTP_RESPONSE),
      hexToBytes(RESPONSE_NONCE),
    );
    expect(bytesToHex(res.encapsulated)).toBe(ENC_RESPONSE);
  });

  it('KAT: the client opens the vector response to the 200', async () => {
    // Rebuild the client context from the same exchange: recipient schedule + sender role.
    const g = await gatewayContext();
    const client = new HpkeContext('sender', g.header.aeadId, g.setup.schedule);
    const opened = await decapsulateResponse(client, g.enc, g.header.aeadId, hexToBytes(ENC_RESPONSE));
    expect(bytesToHex(opened.plaintext)).toBe(BHTTP_RESPONSE);
    expect(decodeResponse(opened.plaintext).status).toBe(200);
  });

  it('KAT: request and response schedules are genuinely different keys', async () => {
    const g = await gatewayContext();
    const s = deriveResponseKeys(g.context, g.enc, g.header.aeadId, hexToBytes(RESPONSE_NONCE));
    expect(bytesToHex(s.aeadKey)).not.toBe(bytesToHex(g.context.key));
    expect(bytesToHex(s.aeadNonce)).not.toBe(bytesToHex(g.context.baseNonce));
  });

  it('KAT: the exported response secret is bound to the export label', async () => {
    const g = await gatewayContext();
    const right = g.context.export(utf8('message/bhttp response'), 16);
    const wrong = g.context.export(utf8('message/bhttp respons!'), 16);
    expect(bytesToHex(right)).toBe(EXPORT_SECRET);
    expect(bytesToHex(wrong)).not.toBe(EXPORT_SECRET);
  });
});
