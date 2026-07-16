/**
 * The knowledge split, tested as data: the relay's computed view must contain
 * the client IP and only ciphertext; the gateway's must contain the plaintext
 * and no client IP; the collusion join must recover both. If these fail, the
 * lab's headline claim is false.
 */
import { describe, expect, it } from 'vitest';
import { bytesToHex, utf8 } from '@hub/hpke/bytes';
import { AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305 } from '@hub/hpke/consts';
import { ADDRESSES, collude, computeViews, runExchange, targetAnswer } from './exchange';
import { decodeResponse } from '../ohttp/bhttp';

const INPUT = {
  method: 'GET',
  authority: 'api.example.com',
  path: '/search?q=chest+pain+symptoms',
  headers: [] as [string, string][],
  content: new Uint8Array(0),
  aeadId: AEAD_AES_128_GCM as 0x0001,
};

describe('end-to-end exchange', () => {
  it('round-trips: what the gateway reads is what the client sent, what the client reads is what the target answered', async () => {
    const x = await runExchange(INPUT);
    expect(x.requestAsSeenByGateway).toEqual(x.request);
    expect(x.responseAsSeenByClient).toEqual(x.response);
    expect(x.responseAsSeenByClient.status).toBe(200);
  });

  it('works under ChaCha20-Poly1305 too', async () => {
    const x = await runExchange({ ...INPUT, aeadId: AEAD_CHACHA20_POLY1305 });
    expect(x.responseAsSeenByClient).toEqual(x.response);
  });

  it('round-trips a POST with headers and a body', async () => {
    const x = await runExchange({
      ...INPUT,
      method: 'POST',
      path: '/v1/submit',
      headers: [['content-type', 'application/json']],
      content: utf8('{"a":1}'),
    });
    expect(x.requestAsSeenByGateway.content).toEqual(utf8('{"a":1}'));
    expect(decodeResponse(x.clientDecap.plaintext).status).toBe(200);
  });

  it('two runs of the same request produce different ciphertexts (fresh ephemeral)', async () => {
    const a = await runExchange(INPUT);
    const b = await runExchange(INPUT);
    expect(bytesToHex(a.encRequest.encapsulated)).not.toBe(bytesToHex(b.encRequest.encapsulated));
  });
});

describe('the knowledge split (computed views)', () => {
  it('the relay view holds the client IP and ciphertext, and no plaintext fact at all', async () => {
    const x = await runExchange(INPUT);
    const relay = computeViews(x).find((v) => v.party === 'relay')!;
    expect(relay.knows.some((f) => f.value === ADDRESSES.client.ip)).toBe(true);
    expect(relay.knows.some((f) => f.kind === 'plaintext')).toBe(false);
    expect(relay.knows.some((f) => f.kind === 'key')).toBe(false);
    // The ciphertext the relay holds must not contain the query as a substring.
    const ctHex = relay.knows.find((f) => f.kind === 'ciphertext')!.value;
    expect(ctHex).toBe(bytesToHex(x.encRequest.encapsulated));
    expect(ctHex.includes(bytesToHex(utf8('chest')))).toBe(false);
  });

  it('the gateway view holds the plaintext request and no client identity fact', async () => {
    const x = await runExchange(INPUT);
    const gateway = computeViews(x).find((v) => v.party === 'gateway')!;
    expect(gateway.knows.some((f) => f.kind === 'plaintext' && f.value.includes('chest'))).toBe(true);
    expect(gateway.knows.some((f) => f.value.includes(ADDRESSES.client.ip))).toBe(false);
    // The transport source the gateway sees is the relay, not the client.
    const src = gateway.knows.find((f) => f.label.includes('connection source'))!;
    expect(src.value).toContain(ADDRESSES.relay.name);
  });

  it('the target sees the request but its requester is the gateway', async () => {
    const x = await runExchange(INPUT);
    const target = computeViews(x).find((v) => v.party === 'target')!;
    expect(target.knows.some((f) => f.value.includes(ADDRESSES.gateway.name))).toBe(true);
    expect(target.knows.some((f) => f.value.includes(ADDRESSES.client.ip))).toBe(false);
  });
});

describe('collusion', () => {
  it('joining the relay and gateway views recovers WHO asked WHAT — with no extra decryption', async () => {
    const x = await runExchange(INPUT);
    const record = collude(computeViews(x));
    expect(record.complete).toBe(true);
    expect(record.who).toBe(ADDRESSES.client.ip);
    expect(record.what).toContain('chest+pain+symptoms');
  });
});

describe('the target stub', () => {
  it('answers a GET with a query echo and anything else with a generic echo', () => {
    const r1 = targetAnswer({
      method: 'GET',
      scheme: 'https',
      authority: 'api.example.com',
      path: '/search?q=hello',
      headers: [],
      content: new Uint8Array(0),
    });
    expect(r1.status).toBe(200);
    expect(new TextDecoder().decode(r1.content)).toContain('hello');
    const r2 = targetAnswer({
      method: 'POST',
      scheme: 'https',
      authority: 'api.example.com',
      path: '/x',
      headers: [],
      content: utf8('zz'),
    });
    expect(new TextDecoder().decode(r2.content)).toContain('"received":2');
  });
});
