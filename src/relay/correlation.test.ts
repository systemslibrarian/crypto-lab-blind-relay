/**
 * The passive-correlation model: distinct ciphertext sizes let anyone join
 * the relay's log to the gateway's log with no key material; RFC 9292 zero
 * padding collapses the join into one anonymity set. The sizes are the real
 * lengths of real encapsulations — if these tests fail, the exhibit lies.
 */
import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '@hub/hpke/dhkem';
import { decodeRequest, padMessage } from '../ohttp/bhttp';
import { CROWD_IPS, CROWD_QUERIES, joinBySize, joinByTiming, runCrowd } from './correlation';

const PAD_TO = 256;

describe('correlation without collusion', () => {
  it('unpadded: every request is identified by size alone', async () => {
    const run = await runCrowd(generateKeyPair());
    const join = joinBySize(run);
    expect(join.matched).toHaveLength(CROWD_QUERIES.length);
    expect(join.ambiguous).toHaveLength(0);
    // And the join is CORRECT: each recovered pair is the true one.
    for (const [i, x] of run.exchanges.entries()) {
      const m = join.matched.find((p) => p.clientIp === CROWD_IPS[i]);
      expect(m?.requestLine).toBe(`GET ${x.requestAsSeenByGateway.path}`);
      expect(m?.size).toBe(x.encRequest.encapsulated.length);
    }
  });

  it('padded: sizes are uniform and the join collapses to one anonymity set', async () => {
    const run = await runCrowd(generateKeyPair(), PAD_TO);
    const sizes = new Set(run.relayLog.map((r) => r.size));
    expect(sizes.size).toBe(1);
    const join = joinBySize(run);
    expect(join.matched).toHaveLength(0);
    expect(join.ambiguous).toHaveLength(1);
    expect(join.ambiguous[0].clientIps).toHaveLength(CROWD_QUERIES.length);
  });

  it('timing join identifies everyone even when padding defeats the size join', async () => {
    const run = await runCrowd(generateKeyPair(), PAD_TO);
    expect(joinBySize(run).matched).toHaveLength(0); // size is dead...
    const timing = joinByTiming(run);
    expect(timing.matched).toHaveLength(CROWD_QUERIES.length); // ...timing is not
    expect(timing.unmatched).toHaveLength(0);
    // And the recovered pairs are the TRUE pairs.
    for (const [i, x] of run.exchanges.entries()) {
      const m = timing.matched.find((p) => p.clientIp === CROWD_IPS[i]);
      expect(m?.requestLine).toBe(`GET ${x.requestAsSeenByGateway.path}`);
    }
  });

  it('timing join reports ambiguity instead of guessing when arrivals overlap', async () => {
    const run = await runCrowd(generateKeyPair(), PAD_TO);
    // Force every message to "arrive" in the same instant — a crude batch.
    const batched = {
      ...run,
      relayLog: run.relayLog.map((r) => ({ ...r, at: 0 })),
      gatewayLog: run.gatewayLog.map((g) => ({ ...g, at: 2 })),
    };
    const timing = joinByTiming(batched);
    expect(timing.matched).toHaveLength(0);
    expect(timing.unmatched).toHaveLength(CROWD_QUERIES.length);
  });

  it('padding does not change what the gateway reads', async () => {
    const run = await runCrowd(generateKeyPair(), PAD_TO);
    for (const [i, x] of run.exchanges.entries()) {
      expect(x.requestAsSeenByGateway.path).toContain(
        encodeURIComponent(CROWD_QUERIES[i]).replace(/%20/g, '+'),
      );
      expect(x.responseAsSeenByClient.status).toBe(200);
    }
  });

  it('padMessage round-trips through the decoder and fails closed when too small', () => {
    const min = new Uint8Array([0x00, 0x03, 0x47, 0x45, 0x54, 0x05, 0x68, 0x74, 0x74, 0x70, 0x73,
      0x0b, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d, 0x01, 0x2f]);
    const padded = padMessage(min, 64);
    expect(padded.length).toBe(64);
    expect(decodeRequest(padded)).toEqual(decodeRequest(min));
    expect(() => padMessage(padded, 10)).toThrow(/cannot pad/);
  });
});
