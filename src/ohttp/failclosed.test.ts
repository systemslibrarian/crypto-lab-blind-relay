/**
 * Fail-closed behavior: every malformed, tampered, or mis-keyed input is
 * rejected with an explicit error — and the relay, holding no key, genuinely
 * cannot decrypt what it carries. These tests ARE the security invariants.
 */
import { describe, expect, it } from 'vitest';
import { OpenError } from '@hub/hpke/aead';
import { hexToBytes, utf8 } from '@hub/hpke/bytes';
import { AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305 } from '@hub/hpke/consts';
import { generateKeyPair } from '@hub/hpke/dhkem';
import { encodeRequest } from './bhttp';
import { decodeKeyConfig, KeyConfigError, selectSuite } from './keyconfig';
import { decapsulateRequest, encapsulateRequest, RequestError } from './request';
import { decapsulateResponse, encapsulateResponse, ResponseError } from './response';
import { buildKeyConfig } from '../relay/exchange';

const REQ = encodeRequest({
  method: 'GET',
  scheme: 'https',
  authority: 'example.com',
  path: '/search?q=secret',
  headers: [],
  content: new Uint8Array(0),
});

async function freshExchange(aeadId: 0x0001 | 0x0003 = AEAD_AES_128_GCM) {
  const keys = generateKeyPair();
  const config = buildKeyConfig(1, keys.pk);
  const enc = await encapsulateRequest(config, REQ, aeadId);
  return { keys, config, enc };
}

describe('request decapsulation fails closed', () => {
  it('a flipped ciphertext byte is rejected by the real AEAD', async () => {
    const { keys, config, enc } = await freshExchange();
    const tampered = enc.encapsulated.slice();
    tampered[tampered.length - 1] ^= 0x01;
    await expect(decapsulateRequest(tampered, config, keys.sk)).rejects.toThrow(OpenError);
  });

  it('a flipped header byte is rejected — the header is bound via info', async () => {
    const { keys, config, enc } = await freshExchange();
    const tampered = enc.encapsulated.slice();
    tampered[6] ^= 0x02; // flip AES-128-GCM (0x0001) to ChaCha20-Poly1305 (0x0003)
    await expect(decapsulateRequest(tampered, config, keys.sk)).rejects.toThrow();
  });

  it('the wrong private key is rejected (this is the relay’s position)', async () => {
    const { config, enc } = await freshExchange();
    const notTheGateway = generateKeyPair();
    await expect(decapsulateRequest(enc.encapsulated, config, notTheGateway.sk)).rejects.toThrow(
      OpenError,
    );
  });

  it('an unknown key ID is rejected before any crypto runs', async () => {
    const { keys, enc } = await freshExchange();
    const otherConfig = buildKeyConfig(2, keys.pk);
    await expect(decapsulateRequest(enc.encapsulated, otherConfig, keys.sk)).rejects.toThrow(
      /unknown key ID/,
    );
  });

  it('an unsupported KEM / KDF in the header is rejected', async () => {
    const { keys, config, enc } = await freshExchange();
    const badKem = enc.encapsulated.slice();
    badKem[2] = 0x10; // KEM 0x0010
    await expect(decapsulateRequest(badKem, config, keys.sk)).rejects.toThrow(/unsupported KEM/);
    const badKdf = enc.encapsulated.slice();
    badKdf[4] = 0x02;
    await expect(decapsulateRequest(badKdf, config, keys.sk)).rejects.toThrow(/unsupported KDF/);
  });

  it('a truncated encapsulated request is rejected', async () => {
    const { keys, config, enc } = await freshExchange();
    await expect(decapsulateRequest(enc.encapsulated.slice(0, 20), config, keys.sk)).rejects.toThrow(
      RequestError,
    );
  });
});

describe('response decapsulation fails closed', () => {
  it('a tampered response nonce breaks the derived key — rejected', async () => {
    const { keys, config, enc } = await freshExchange();
    const g = await decapsulateRequest(enc.encapsulated, config, keys.sk);
    const res = await encapsulateResponse(g.context, g.enc, g.header.aeadId, hexToBytes('0140c8'));
    const tampered = res.encapsulated.slice();
    tampered[0] ^= 0x01;
    await expect(
      decapsulateResponse(enc.context, enc.enc, enc.header.aeadId, tampered),
    ).rejects.toThrow(OpenError);
  });

  it('a tampered response ciphertext is rejected', async () => {
    const { keys, config, enc } = await freshExchange();
    const g = await decapsulateRequest(enc.encapsulated, config, keys.sk);
    const res = await encapsulateResponse(g.context, g.enc, g.header.aeadId, hexToBytes('0140c8'));
    const tampered = res.encapsulated.slice();
    tampered[tampered.length - 1] ^= 0x80;
    await expect(
      decapsulateResponse(enc.context, enc.enc, enc.header.aeadId, tampered),
    ).rejects.toThrow(OpenError);
  });

  it('a response bound to a different request’s enc does not open', async () => {
    const a = await freshExchange();
    const b = await freshExchange();
    const gA = await decapsulateRequest(a.enc.encapsulated, a.config, a.keys.sk);
    const res = await encapsulateResponse(gA.context, gA.enc, gA.header.aeadId, hexToBytes('0140c8'));
    // Client of exchange B tries to open A's response: wrong context AND wrong enc.
    await expect(
      decapsulateResponse(b.enc.context, b.enc.enc, b.enc.header.aeadId, res.encapsulated),
    ).rejects.toThrow(OpenError);
  });

  it('a too-short encapsulated response is rejected before key derivation', async () => {
    const { enc } = await freshExchange();
    await expect(
      decapsulateResponse(enc.context, enc.enc, enc.header.aeadId, new Uint8Array(10)),
    ).rejects.toThrow(ResponseError);
  });

  it('ChaCha20-Poly1305 uses a 32-byte response nonce (max(Nn, Nk))', async () => {
    const { keys, config, enc } = await freshExchange(AEAD_CHACHA20_POLY1305);
    const g = await decapsulateRequest(enc.encapsulated, config, keys.sk);
    const res = await encapsulateResponse(g.context, g.enc, g.header.aeadId, hexToBytes('0140c8'));
    expect(res.schedule.responseNonce.length).toBe(32);
    const opened = await decapsulateResponse(enc.context, enc.enc, enc.header.aeadId, res.encapsulated);
    expect(opened.plaintext).toEqual(hexToBytes('0140c8'));
  });
});

describe('key config validation fails closed', () => {
  it('rejects a key config with a foreign KEM', () => {
    // keyId 01, KEM 0x0011 (P-256), 32-byte key, one suite
    const bytes = new Uint8Array([1, 0x00, 0x11, ...new Uint8Array(32), 0, 4, 0, 1, 0, 1]);
    expect(() => decodeKeyConfig(bytes)).toThrow(KeyConfigError);
  });

  it('rejects a suite list whose length is not a multiple of 4', () => {
    const bytes = new Uint8Array([1, 0x00, 0x20, ...new Uint8Array(32), 0, 6, 0, 1, 0, 1, 0, 1]);
    expect(() => decodeKeyConfig(bytes)).toThrow(/multiple of 4/);
  });

  it('client refuses a key config with no mutually supported suite', async () => {
    const keys = generateKeyPair();
    const config = {
      keyId: 1,
      kemId: 0x0020,
      pk: keys.pk,
      suites: [{ kdfId: 0x0003, aeadId: 0xffff }], // HKDF-SHA512 + reserved AEAD
    };
    expect(() => selectSuite(config)).toThrow(/no mutually supported suite/);
    await expect(encapsulateRequest(config, REQ)).rejects.toThrow(KeyConfigError);
  });

  it('client refuses to encapsulate under an AEAD the config does not advertise', async () => {
    const keys = generateKeyPair();
    const config = {
      keyId: 1,
      kemId: 0x0020,
      pk: keys.pk,
      suites: [{ kdfId: 0x0001, aeadId: AEAD_AES_128_GCM }],
    };
    await expect(encapsulateRequest(config, REQ, AEAD_CHACHA20_POLY1305)).rejects.toThrow(
      /does not advertise/,
    );
  });

  it('rejects sealing an empty-ish request under a truncated public key', () => {
    expect(() =>
      buildKeyConfig(1, utf8('short')),
    ).not.toThrow(); // buildKeyConfig itself is a plain struct...
    const config = buildKeyConfig(1, utf8('short'));
    // ...but using it fails closed at the KEM boundary.
    return expect(encapsulateRequest(config, REQ)).rejects.toThrow();
  });
});
