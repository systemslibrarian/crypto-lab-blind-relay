/**
 * OHTTP request encapsulation (RFC 9458 §4.3).
 *
 * The HPKE itself is the hub's (crypto-lab-hpke-envelope) — consumed, not
 * rebuilt. What is hand-rolled here is exactly what RFC 9458 adds around
 * HPKE: the 7-byte header, the `info` binding, and the wire format
 *   Encapsulated Request = hdr(7) || enc(32) || ct
 * so the lab can show that the "anonymous envelope" is nothing more exotic
 * than HPKE Base mode with a domain-separated info string.
 */
import { concatBytes, i2osp, utf8 } from '@hub/hpke/bytes';
import { AEAD_NAMES, type AeadId, KDF_ID, KEM_ID, NPK, NT } from '@hub/hpke/consts';
import type { HpkeContext } from '@hub/hpke/context';
import { MODE_BASE, setupSender, setupRecipient, type SetupResult } from '@hub/hpke/hpke';
import { type KeyConfig, KeyConfigError, selectSuite } from './keyconfig';

export class RequestError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RequestError';
  }
}

const HDR_LEN = 7; // key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2)
const REQUEST_INFO_LABEL = 'message/bhttp request';

export interface EncapsulatedRequestHeader {
  keyId: number;
  kemId: number;
  kdfId: number;
  aeadId: AeadId;
}

/** hdr = key_id(1) || kem_id(2) || kdf_id(2) || aead_id(2), network byte order. */
export function encodeHeader(h: EncapsulatedRequestHeader): Uint8Array {
  return concatBytes(i2osp(h.keyId, 1), i2osp(h.kemId, 2), i2osp(h.kdfId, 2), i2osp(h.aeadId, 2));
}

/** info = "message/bhttp request" || 0x00 || hdr — binds the ciphertext to this key config. */
export function requestInfo(hdr: Uint8Array): Uint8Array {
  return concatBytes(utf8(REQUEST_INFO_LABEL), new Uint8Array([0]), hdr);
}

export interface EncapsulateRequestResult {
  /** The wire message the relay carries: hdr || enc || ct. */
  encapsulated: Uint8Array;
  header: EncapsulatedRequestHeader;
  hdr: Uint8Array;
  info: Uint8Array;
  enc: Uint8Array;
  ct: Uint8Array;
  /** Client keeps this context alive to open the response later. */
  context: HpkeContext;
  /** Every HPKE intermediate, for the pipeline view. */
  setup: SetupResult;
}

/**
 * Client side: seal a BHTTP-encoded request to the gateway's key config.
 * `ephemeralIkm` makes the ephemeral key deterministic (KATs / replayable UI).
 */
export async function encapsulateRequest(
  config: KeyConfig,
  bhttpRequest: Uint8Array,
  preferredAead?: AeadId,
  ephemeralIkm?: Uint8Array,
): Promise<EncapsulateRequestResult> {
  const suite = selectSuite(config, preferredAead);
  const header: EncapsulatedRequestHeader = {
    keyId: config.keyId,
    kemId: config.kemId,
    kdfId: suite.kdfId,
    aeadId: suite.aeadId as AeadId,
  };
  const hdr = encodeHeader(header);
  const info = requestInfo(hdr);
  const setup = setupSender({
    mode: MODE_BASE,
    aeadId: header.aeadId,
    pkR: config.pk,
    info,
    ephemeralIkm,
  });
  // RFC 9458 §4.3: Seal with empty aad; the binding lives in `info`, not aad.
  const { ct } = await setup.context.seal(new Uint8Array(0), bhttpRequest);
  return {
    encapsulated: concatBytes(hdr, setup.enc, ct),
    header,
    hdr,
    info,
    enc: setup.enc,
    ct,
    context: setup.context,
    setup,
  };
}

export interface DecapsulateRequestResult {
  /** The decrypted BHTTP request bytes. */
  plaintext: Uint8Array;
  header: EncapsulatedRequestHeader;
  enc: Uint8Array;
  ct: Uint8Array;
  /** Gateway keeps this context to seal the response. */
  context: HpkeContext;
  setup: SetupResult;
}

export function parseHeader(encapsulated: Uint8Array): EncapsulatedRequestHeader {
  if (encapsulated.length < HDR_LEN) {
    throw new RequestError(`encapsulated request too short for the 7-byte header`);
  }
  return {
    keyId: encapsulated[0],
    kemId: (encapsulated[1] << 8) | encapsulated[2],
    kdfId: (encapsulated[3] << 8) | encapsulated[4],
    aeadId: ((encapsulated[5] << 8) | encapsulated[6]) as AeadId,
  };
}

/**
 * Gateway side: parse hdr || enc || ct, check the header names a key and
 * suite this gateway actually holds, then HPKE-open. Every check fails
 * closed — an attacker-controlled header never selects "roughly right".
 */
export async function decapsulateRequest(
  encapsulated: Uint8Array,
  config: KeyConfig,
  skR: Uint8Array,
): Promise<DecapsulateRequestResult> {
  const header = parseHeader(encapsulated);
  if (header.keyId !== config.keyId) {
    throw new RequestError(`unknown key ID ${header.keyId} (gateway holds key ID ${config.keyId})`);
  }
  if (header.kemId !== KEM_ID) {
    throw new RequestError(`unsupported KEM 0x${header.kemId.toString(16).padStart(4, '0')}`);
  }
  if (header.kdfId !== KDF_ID) {
    throw new RequestError(`unsupported KDF 0x${header.kdfId.toString(16).padStart(4, '0')}`);
  }
  if (!(header.aeadId in AEAD_NAMES)) {
    throw new RequestError(`unsupported AEAD 0x${header.aeadId.toString(16).padStart(4, '0')}`);
  }
  if (!config.suites.some((s) => s.kdfId === header.kdfId && s.aeadId === header.aeadId)) {
    throw new KeyConfigError('header names a suite this key config does not advertise');
  }
  if (encapsulated.length < HDR_LEN + NPK + NT) {
    throw new RequestError('encapsulated request too short for enc + a sealed message');
  }
  const enc = encapsulated.slice(HDR_LEN, HDR_LEN + NPK);
  const ct = encapsulated.slice(HDR_LEN + NPK);
  const hdr = encapsulated.slice(0, HDR_LEN);
  const setup = setupRecipient({
    mode: MODE_BASE,
    aeadId: header.aeadId,
    enc,
    skR,
    info: requestInfo(hdr),
  });
  // Any mismatch (wrong key, tampered hdr, flipped ct byte) surfaces here as
  // the hub's OpenError — one indistinguishable failure, per AEAD semantics.
  const { pt } = await setup.context.open(new Uint8Array(0), ct);
  return { plaintext: pt, header, enc, ct, context: setup.context, setup };
}
