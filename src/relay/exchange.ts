/**
 * The three-party exchange this lab visualizes, run end-to-end with real
 * crypto in one browser tab.
 *
 * There is NO real network here (in-page simulation, labeled as such in the
 * UI) — but every byte each party "holds" below is the genuine artifact of a
 * genuine HPKE/BHTTP exchange: the relay's view really is the ciphertext, the
 * gateway's view really is the decrypted plaintext. The knowledge split is
 * computed from what the math yields each party, never asserted.
 */
import { bytesToHex, utf8 } from '@hub/hpke/bytes';
import { AEAD_NAMES, type AeadId, KDF_ID, KEM_ID } from '@hub/hpke/consts';
import { generateKeyPair, type KeyPair } from '@hub/hpke/dhkem';
import {
  type BhttpRequest,
  type BhttpResponse,
  decodeRequest,
  decodeResponse,
  encodeRequest,
  encodeResponse,
  padMessage,
} from '../ohttp/bhttp';
import { type KeyConfig } from '../ohttp/keyconfig';
import {
  decapsulateRequest,
  type DecapsulateRequestResult,
  encapsulateRequest,
  type EncapsulateRequestResult,
} from '../ohttp/request';
import {
  decapsulateResponse,
  type DecapsulateResponseResult,
  encapsulateResponse,
  type EncapsulateResponseResult,
} from '../ohttp/response';

/**
 * Simulated transport identities (RFC 5737 / RFC 2606 documentation ranges).
 * These stand in for what the TCP/TLS layer would reveal — the one thing
 * encryption cannot hide.
 */
export const ADDRESSES = {
  client: { name: 'you', ip: '203.0.113.7' },
  relay: { name: 'relay.example.net', ip: '192.0.2.44' },
  gateway: { name: 'gateway.example.com', ip: '198.51.100.9' },
  target: { name: 'api.example.com', ip: '198.51.100.9' }, // co-located with the gateway, as in the RFC example
} as const;

export interface ExchangeInput {
  method: string;
  authority: string;
  path: string;
  headers: [string, string][];
  content: Uint8Array;
  aeadId: AeadId;
  /** Pad the BHTTP message to this many bytes before sealing (RFC 9292 §3.8). */
  padTo?: number;
}

/** Everything a completed exchange produced, for the party views and pipeline. */
export interface Exchange {
  input: ExchangeInput;
  gatewayKeys: KeyPair;
  keyConfig: KeyConfig;
  request: BhttpRequest;
  bhttpRequest: Uint8Array;
  encRequest: EncapsulateRequestResult;
  gatewayDecap: DecapsulateRequestResult;
  /** What the gateway read — decoded from the decrypted bytes, not from `request`. */
  requestAsSeenByGateway: BhttpRequest;
  response: BhttpResponse;
  bhttpResponse: Uint8Array;
  encResponse: EncapsulateResponseResult;
  clientDecap: DecapsulateResponseResult;
  /** What the client read back — decoded from the decrypted bytes. */
  responseAsSeenByClient: BhttpResponse;
}

/**
 * The target resource: a canned lookup service. Deterministic and local —
 * the point of the demo is the envelope, not the API behind it.
 */
export function targetAnswer(request: BhttpRequest): BhttpResponse {
  const q = /[?&]q=([^&]*)/.exec(request.path);
  const query = q ? decodeURIComponent(q[1].replace(/\+/g, ' ')) : null;
  const body =
    request.method === 'GET' && query !== null
      ? JSON.stringify({ query, results: 3, top: `${query} — overview, causes, when to seek help` })
      : JSON.stringify({ echo: request.method, path: request.path, received: request.content.length });
  return {
    status: 200,
    headers: [['content-type', 'application/json']],
    content: utf8(body),
  };
}

export function buildKeyConfig(keyId: number, pk: Uint8Array): KeyConfig {
  return {
    keyId,
    kemId: KEM_ID,
    pk,
    suites: [
      { kdfId: KDF_ID, aeadId: 0x0001 }, // HKDF-SHA256, AES-128-GCM
      { kdfId: KDF_ID, aeadId: 0x0003 }, // HKDF-SHA256, ChaCha20-Poly1305
    ],
  };
}

/**
 * Run the whole flow: client encodes + seals → relay forwards bytes it cannot
 * read → gateway opens, asks the target, seals the answer back → client opens.
 * Optional deterministic seeds keep the pipeline replayable in the UI.
 */
export async function runExchange(
  input: ExchangeInput,
  seeds?: { gatewayKeys?: KeyPair; ephemeralIkm?: Uint8Array; responseNonce?: Uint8Array },
): Promise<Exchange> {
  const gatewayKeys = seeds?.gatewayKeys ?? generateKeyPair();
  const keyConfig = buildKeyConfig(1, gatewayKeys.pk);

  // — client —
  const request: BhttpRequest = {
    method: input.method,
    scheme: 'https',
    authority: input.authority,
    path: input.path,
    headers: input.headers,
    content: input.content,
  };
  const encoded = encodeRequest(request);
  const bhttpRequest = input.padTo === undefined ? encoded : padMessage(encoded, input.padTo);
  const encRequest = await encapsulateRequest(keyConfig, bhttpRequest, input.aeadId, seeds?.ephemeralIkm);

  // — relay — forwards encRequest.encapsulated verbatim; holds no key material.

  // — gateway —
  const gatewayDecap = await decapsulateRequest(encRequest.encapsulated, keyConfig, gatewayKeys.sk);
  const requestAsSeenByGateway = decodeRequest(gatewayDecap.plaintext);

  // — target —
  const response = targetAnswer(requestAsSeenByGateway);
  const bhttpResponse = encodeResponse(response);

  // — gateway seals the response back —
  const encResponse = await encapsulateResponse(
    gatewayDecap.context,
    gatewayDecap.enc,
    gatewayDecap.header.aeadId,
    bhttpResponse,
    seeds?.responseNonce,
  );

  // — relay forwards the response bytes back, equally unreadable —

  // — client —
  const clientDecap = await decapsulateResponse(
    encRequest.context,
    encRequest.enc,
    encRequest.header.aeadId,
    encResponse.encapsulated,
  );
  const responseAsSeenByClient = decodeResponse(clientDecap.plaintext);

  return {
    input,
    gatewayKeys,
    keyConfig,
    request,
    bhttpRequest,
    encRequest,
    gatewayDecap,
    requestAsSeenByGateway,
    response,
    bhttpResponse,
    encResponse,
    clientDecap,
    responseAsSeenByClient,
  };
}

// ————— party views: computed from held artifacts, never hand-written —————

export type FactKind = 'identity' | 'plaintext' | 'ciphertext' | 'key' | 'transport';

export interface Fact {
  label: string;
  value: string;
  kind: FactKind;
  /** Render the value as monospace scrollable bytes. */
  hex?: boolean;
  /** Pipeline step (0–8) at which this fact comes into the party's possession. */
  stage: number;
}

export interface PartyView {
  party: 'client' | 'relay' | 'gateway' | 'target';
  title: string;
  knows: Fact[];
  /** What this party provably cannot derive from what it holds — with the reason. */
  cannotKnow: { label: string; reason: string; stage: number }[];
}

function requestLine(r: BhttpRequest): string {
  return `${r.method} ${r.scheme}://${r.authority}${r.path}`;
}

export function computeViews(x: Exchange): PartyView[] {
  const aead = AEAD_NAMES[x.encRequest.header.aeadId];
  return [
    {
      party: 'client',
      title: 'Client',
      knows: [
        { label: 'own identity', value: `${ADDRESSES.client.ip}`, kind: 'identity', stage: 0 },
        { label: 'request (plaintext)', value: requestLine(x.request), kind: 'plaintext', stage: 0 },
        { label: 'gateway public key (from key config)', value: bytesToHex(x.keyConfig.pk), kind: 'key', hex: true, stage: 0 },
        { label: 'request as BHTTP bytes', value: bytesToHex(x.bhttpRequest), kind: 'plaintext', hex: true, stage: 1 },
        {
          label: 'sealed request: hdr ‖ enc ‖ ct',
          value: bytesToHex(x.encRequest.encapsulated),
          kind: 'ciphertext',
          hex: true,
          stage: 2,
        },
        {
          label: 'response (decrypted)',
          value: `${x.responseAsSeenByClient.status} · ${new TextDecoder().decode(x.responseAsSeenByClient.content)}`,
          kind: 'plaintext',
          stage: 8,
        },
      ],
      cannotKnow: [
        {
          label: 'whether relay and gateway are colluding',
          reason: 'non-collusion is an assumption the client cannot verify cryptographically',
          stage: 0,
        },
      ],
    },
    {
      party: 'relay',
      title: 'Relay',
      knows: [
        { label: 'client IP (TCP source)', value: ADDRESSES.client.ip, kind: 'transport', stage: 3 },
        { label: 'gateway it forwards to', value: ADDRESSES.gateway.name, kind: 'transport', stage: 3 },
        {
          label: `request it carries (HPKE ${aead} ciphertext)`,
          value: bytesToHex(x.encRequest.encapsulated),
          kind: 'ciphertext',
          hex: true,
          stage: 3,
        },
        {
          label: 'response it carries back (ciphertext)',
          value: bytesToHex(x.encResponse.encapsulated),
          kind: 'ciphertext',
          hex: true,
          stage: 7,
        },
        {
          label: 'timing + sizes',
          value: `req ${x.encRequest.encapsulated.length} B → res ${x.encResponse.encapsulated.length} B`,
          kind: 'transport',
          stage: 7,
        },
      ],
      cannotKnow: [
        {
          label: 'the request contents',
          reason: `sealed to the gateway's key — the relay holds no HPKE private key (try it below)`,
          stage: 3,
        },
        {
          label: 'the response contents',
          reason: 'sealed under keys derived from the request context',
          stage: 7,
        },
      ],
    },
    {
      party: 'gateway',
      title: 'Gateway',
      knows: [
        { label: 'HPKE private key', value: bytesToHex(x.gatewayKeys.sk), kind: 'key', hex: true, stage: 4 },
        {
          label: 'request (decrypted)',
          value: requestLine(x.requestAsSeenByGateway),
          kind: 'plaintext',
          stage: 4,
        },
        {
          label: 'connection source (TCP)',
          value: `${ADDRESSES.relay.name} (${ADDRESSES.relay.ip})`,
          kind: 'transport',
          stage: 4,
        },
      ],
      cannotKnow: [
        {
          label: 'the client IP / network identity',
          reason: 'the protocol shows it only the relay; anything more must leak from the request body itself',
          stage: 4,
        },
        {
          label: 'which requests came from the same client',
          reason: 'each request uses a fresh ephemeral HPKE key',
          stage: 4,
        },
      ],
    },
    {
      party: 'target',
      title: 'Target',
      knows: [
        { label: 'request (served)', value: requestLine(x.requestAsSeenByGateway), kind: 'plaintext', stage: 5 },
        { label: 'requester it sees', value: ADDRESSES.gateway.name, kind: 'transport', stage: 5 },
      ],
      cannotKnow: [
        { label: 'the client IP', reason: 'the request arrives from the gateway', stage: 5 },
      ],
    },
  ];
}

/**
 * The collusion join: nothing is decrypted that was not already decryptable.
 * The relay contributes WHO, the gateway contributes WHAT; the intersection
 * key is the exchange itself (the same ciphertext bytes seen by both).
 */
export interface CollusionRecord {
  who: string;
  what: string;
  joinedOn: string;
  complete: boolean;
}

export function collude(views: PartyView[]): CollusionRecord {
  const relay = views.find((v) => v.party === 'relay');
  const gateway = views.find((v) => v.party === 'gateway');
  const who = relay?.knows.find((f) => f.kind === 'transport' && f.label.includes('client IP'))?.value;
  const what = gateway?.knows.find((f) => f.kind === 'plaintext')?.value;
  return {
    who: who ?? '(missing)',
    what: what ?? '(missing)',
    joinedOn: 'the encapsulated request bytes both parties handled',
    complete: who !== undefined && what !== undefined,
  };
}
