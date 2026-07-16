/**
 * OHTTP response encapsulation (RFC 9458 §4.4) — deliberately NOT the same
 * key schedule as the request, and that asymmetry is a teaching point:
 *
 *   request:  full HPKE — KEM encap + labeled key schedule + sequence nonces
 *   response: no second KEM. The gateway EXPORTS a secret from the request's
 *             HPKE context, mixes in a fresh public response_nonce, and runs
 *             plain HKDF → one AEAD seal:
 *
 *   secret         = context.Export("message/bhttp response", max(Nn, Nk))
 *   salt           = enc || response_nonce
 *   prk            = Extract(salt, secret)
 *   aead_key       = Expand(prk, "key",   Nk)
 *   aead_nonce     = Expand(prk, "nonce", Nn)
 *   Encapsulated Response = response_nonce || Seal(aead_key, aead_nonce, "", response)
 *
 * The response needs no KEM because both ends already share the request
 * context; the response_nonce exists so a gateway answering many requests
 * under one key never reuses (key, nonce). The plain (unlabeled) HKDF here
 * vs the labeled HPKE schedule on the request path is straight from the RFC.
 */
import { extract, expand } from '@noble/hashes/hkdf';
import { sha256 } from '@noble/hashes/sha2';
import { aeadOpen, aeadSeal } from '@hub/hpke/aead';
import { concatBytes, randomBytes, utf8 } from '@hub/hpke/bytes';
import { AEAD_NK, type AeadId, NN } from '@hub/hpke/consts';
import type { HpkeContext } from '@hub/hpke/context';

export class ResponseError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ResponseError';
  }
}

const RESPONSE_EXPORT_LABEL = 'message/bhttp response';

export interface ResponseKeySchedule {
  /** max(Nn, Nk) — also the response_nonce length. */
  secretLength: number;
  secret: Uint8Array;
  responseNonce: Uint8Array;
  salt: Uint8Array;
  prk: Uint8Array;
  aeadKey: Uint8Array;
  aeadNonce: Uint8Array;
}

/**
 * Both ends run this identically — the gateway to seal, the client to open.
 * `enc` is the KEM share from the REQUEST: reusing it in the salt binds the
 * response to the exact request exchange it answers.
 */
export function deriveResponseKeys(
  context: HpkeContext,
  enc: Uint8Array,
  aeadId: AeadId,
  responseNonce: Uint8Array,
): ResponseKeySchedule {
  const nk = AEAD_NK[aeadId];
  const secretLength = Math.max(NN, nk);
  if (responseNonce.length !== secretLength) {
    throw new ResponseError(`response nonce must be ${secretLength} bytes, got ${responseNonce.length}`);
  }
  const secret = context.export(utf8(RESPONSE_EXPORT_LABEL), secretLength);
  const salt = concatBytes(enc, responseNonce);
  // noble signature: extract(hash, ikm, salt)
  const prk = extract(sha256, secret, salt);
  const aeadKey = expand(sha256, prk, utf8('key'), nk);
  const aeadNonce = expand(sha256, prk, utf8('nonce'), NN);
  return { secretLength, secret, responseNonce, salt, prk, aeadKey, aeadNonce };
}

export interface EncapsulateResponseResult {
  /** The wire message: response_nonce || ct. */
  encapsulated: Uint8Array;
  ct: Uint8Array;
  schedule: ResponseKeySchedule;
}

/** Gateway side. `responseNonce` may be pinned for KATs; omit for fresh randomness. */
export async function encapsulateResponse(
  context: HpkeContext,
  enc: Uint8Array,
  aeadId: AeadId,
  bhttpResponse: Uint8Array,
  responseNonce?: Uint8Array,
): Promise<EncapsulateResponseResult> {
  const nonceLen = Math.max(NN, AEAD_NK[aeadId]);
  const schedule = deriveResponseKeys(context, enc, aeadId, responseNonce ?? randomBytes(nonceLen));
  const ct = await aeadSeal(aeadId, schedule.aeadKey, schedule.aeadNonce, new Uint8Array(0), bhttpResponse);
  return { encapsulated: concatBytes(schedule.responseNonce, ct), ct, schedule };
}

export interface DecapsulateResponseResult {
  plaintext: Uint8Array;
  schedule: ResponseKeySchedule;
}

/** Client side: split nonce || ct, re-derive, open. Fails closed on any tamper. */
export async function decapsulateResponse(
  context: HpkeContext,
  enc: Uint8Array,
  aeadId: AeadId,
  encapsulated: Uint8Array,
): Promise<DecapsulateResponseResult> {
  const nonceLen = Math.max(NN, AEAD_NK[aeadId]);
  if (encapsulated.length < nonceLen + 16) {
    throw new ResponseError('encapsulated response too short for nonce + a sealed message');
  }
  const responseNonce = encapsulated.slice(0, nonceLen);
  const ct = encapsulated.slice(nonceLen);
  const schedule = deriveResponseKeys(context, enc, aeadId, responseNonce);
  const plaintext = await aeadOpen(aeadId, schedule.aeadKey, schedule.aeadNonce, new Uint8Array(0), ct);
  return { plaintext, schedule };
}
