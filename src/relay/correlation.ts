/**
 * Correlation WITHOUT collusion — the passive version of the attack.
 *
 * The collusion toggle shows an active join. This model shows something
 * quieter: even two parties who never talk can be correlated by anyone who
 * later reads both logs, because OHTTP hides content, not METADATA. The
 * ciphertext sizes here are the real lengths of real HPKE encapsulations;
 * only the arrival clock is simulated (and labeled as such in the UI).
 *
 * The countermeasure shown is the one the RFCs actually offer: BHTTP zero
 * padding (RFC 9292 §3.8) makes sizes uniform. Timing needs batching/mixing,
 * which OHTTP does not provide — that honesty is part of the exhibit.
 */
import { AEAD_AES_128_GCM } from '@hub/hpke/consts';
import type { KeyPair } from '@hub/hpke/dhkem';
import { runExchange, type Exchange } from './exchange';

/** Distinct documentation-range clients for the crowd (RFC 5737). */
export const CROWD_IPS = ['203.0.113.7', '203.0.113.21', '203.0.113.42', '203.0.113.99'] as const;

export const CROWD_QUERIES = [
  'flu',
  'chest pain symptoms',
  'bankruptcy lawyer near me',
  'how do I delete my search history forever',
] as const;

export interface RelayLogEntry {
  /** Simulated arrival time, ms — the one non-real value here. */
  at: number;
  clientIp: string;
  /** Real length of the real encapsulated request. */
  size: number;
}

export interface GatewayLogEntry {
  at: number;
  requestLine: string;
  size: number;
}

export interface CrowdRun {
  exchanges: Exchange[];
  /** What the relay's access log would hold: who + when + how big. */
  relayLog: RelayLogEntry[];
  /** What the gateway's log would hold: what + when + how big. */
  gatewayLog: GatewayLogEntry[];
  padTo?: number;
}

/**
 * Run one exchange per query, all "arriving" within a few tens of ms.
 * Arrival offsets are deterministic so the exhibit is replayable.
 */
export async function runCrowd(gatewayKeys: KeyPair, padTo?: number): Promise<CrowdRun> {
  const exchanges: Exchange[] = [];
  for (const query of CROWD_QUERIES) {
    exchanges.push(
      await runExchange(
        {
          method: 'GET',
          authority: 'api.example.com',
          path: `/search?q=${encodeURIComponent(query).replace(/%20/g, '+')}`,
          headers: [],
          content: new Uint8Array(0),
          aeadId: AEAD_AES_128_GCM,
          padTo,
        },
        { gatewayKeys },
      ),
    );
  }
  const relayLog: RelayLogEntry[] = exchanges.map((x, i) => ({
    at: i * 17 + ((i * 13) % 9),
    clientIp: CROWD_IPS[i],
    size: x.encRequest.encapsulated.length,
  }));
  // The gateway sees each message ~2ms later; its log is sorted by size so
  // the learner cannot match rows by their order on screen.
  const gatewayLog: GatewayLogEntry[] = exchanges
    .map((x, i) => ({
      at: relayLog[i].at + 2,
      requestLine: `${x.requestAsSeenByGateway.method} ${x.requestAsSeenByGateway.path}`,
      size: x.encRequest.encapsulated.length,
    }))
    .sort((a, b) => a.size - b.size || a.requestLine.localeCompare(b.requestLine));
  return { exchanges, relayLog, gatewayLog, padTo };
}

export interface SizeJoin {
  /** Unambiguous (unique-size) matches: who asked what, recovered from metadata alone. */
  matched: { clientIp: string; requestLine: string; size: number }[];
  /** Sizes shared by more than one message — anonymity sets, not identifications. */
  ambiguous: { size: number; clientIps: string[]; requestLines: string[] }[];
}

/** The passive attack: JOIN the two logs on ciphertext size. No key material used. */
export function joinBySize(run: CrowdRun): SizeJoin {
  const sizes = new Map<number, { relay: RelayLogEntry[]; gateway: GatewayLogEntry[] }>();
  for (const r of run.relayLog) {
    const g = sizes.get(r.size) ?? { relay: [], gateway: [] };
    g.relay.push(r);
    sizes.set(r.size, g);
  }
  for (const g of run.gatewayLog) {
    const e = sizes.get(g.size) ?? { relay: [], gateway: [] };
    e.gateway.push(g);
    sizes.set(g.size, e);
  }
  const matched: SizeJoin['matched'] = [];
  const ambiguous: SizeJoin['ambiguous'] = [];
  for (const [size, group] of [...sizes.entries()].sort((a, b) => a[0] - b[0])) {
    if (group.relay.length === 1 && group.gateway.length === 1) {
      matched.push({ clientIp: group.relay[0].clientIp, requestLine: group.gateway[0].requestLine, size });
    } else {
      ambiguous.push({
        size,
        clientIps: group.relay.map((r) => r.clientIp),
        requestLines: group.gateway.map((g) => g.requestLine),
      });
    }
  }
  return { matched, ambiguous };
}
