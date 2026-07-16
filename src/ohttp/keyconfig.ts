/**
 * OHTTP key configuration (RFC 9458 §3) — how the gateway's HPKE public key
 * and supported suites reach the client. The encoding is tiny but it IS the
 * trust root of the whole scheme: whoever controls what key config a client
 * sees controls who can read that client's requests.
 */
import { bytesToHex, concatBytes, i2osp } from '@hub/hpke/bytes';
import {
  AEAD_AES_128_GCM,
  AEAD_CHACHA20_POLY1305,
  type AeadId,
  KDF_ID,
  KEM_ID,
  NPK,
} from '@hub/hpke/consts';

export class KeyConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'KeyConfigError';
  }
}

export interface SymmetricSuite {
  kdfId: number;
  aeadId: number;
}

export interface KeyConfig {
  keyId: number;
  kemId: number;
  /** Gateway's HPKE public key (X25519, 32 bytes). */
  pk: Uint8Array;
  suites: SymmetricSuite[];
}

export function encodeKeyConfig(config: KeyConfig): Uint8Array {
  if (!Number.isInteger(config.keyId) || config.keyId < 0 || config.keyId > 0xff) {
    throw new KeyConfigError(`key ID must fit one byte: ${config.keyId}`);
  }
  if (config.kemId !== KEM_ID) {
    throw new KeyConfigError(`unsupported KEM 0x${config.kemId.toString(16)} — this lab's suite is DHKEM(X25519, HKDF-SHA256)`);
  }
  if (config.pk.length !== NPK) throw new KeyConfigError(`public key must be ${NPK} bytes`);
  if (config.suites.length === 0) throw new KeyConfigError('at least one symmetric suite is required');
  const suiteBytes = concatBytes(
    ...config.suites.map((s) => concatBytes(i2osp(s.kdfId, 2), i2osp(s.aeadId, 2))),
  );
  return concatBytes(
    i2osp(config.keyId, 1),
    i2osp(config.kemId, 2),
    config.pk,
    i2osp(suiteBytes.length, 2),
    suiteBytes,
  );
}

export function decodeKeyConfig(bytes: Uint8Array): KeyConfig {
  // 1 (key id) + 2 (kem) + 32 (pk) + 2 (algs length) + at least one 4-byte suite
  if (bytes.length < 1 + 2 + NPK + 2 + 4) {
    throw new KeyConfigError(`key config too short: ${bytes.length} bytes`);
  }
  const keyId = bytes[0];
  const kemId = (bytes[1] << 8) | bytes[2];
  if (kemId !== KEM_ID) {
    throw new KeyConfigError(
      `unsupported KEM 0x${kemId.toString(16).padStart(4, '0')} — expected DHKEM(X25519, HKDF-SHA256) 0x0020`,
    );
  }
  const pk = bytes.slice(3, 3 + NPK);
  const algsLen = (bytes[3 + NPK] << 8) | bytes[4 + NPK];
  const algsStart = 5 + NPK;
  if (algsLen === 0 || algsLen % 4 !== 0) {
    throw new KeyConfigError(`symmetric algorithms length must be a positive multiple of 4: ${algsLen}`);
  }
  if (algsStart + algsLen !== bytes.length) {
    throw new KeyConfigError(
      `symmetric algorithms length ${algsLen} does not match remaining ${bytes.length - algsStart} bytes`,
    );
  }
  const suites: SymmetricSuite[] = [];
  for (let off = algsStart; off < bytes.length; off += 4) {
    suites.push({
      kdfId: (bytes[off] << 8) | bytes[off + 1],
      aeadId: (bytes[off + 2] << 8) | bytes[off + 3],
    });
  }
  return { keyId, kemId, pk, suites };
}

/** The (KDF, AEAD) pairs the hub HPKE module can actually run. */
export function suiteSupported(suite: SymmetricSuite): boolean {
  return (
    suite.kdfId === KDF_ID &&
    (suite.aeadId === AEAD_AES_128_GCM || suite.aeadId === AEAD_CHACHA20_POLY1305)
  );
}

/** Client-side suite selection: first advertised suite we support, fail closed. */
export function selectSuite(config: KeyConfig, preferredAead?: AeadId): SymmetricSuite {
  if (preferredAead !== undefined) {
    const match = config.suites.find((s) => s.kdfId === KDF_ID && s.aeadId === preferredAead);
    if (!match) {
      throw new KeyConfigError(
        `gateway key config does not advertise the requested AEAD 0x${preferredAead.toString(16).padStart(4, '0')}`,
      );
    }
    return match;
  }
  const first = config.suites.find(suiteSupported);
  if (!first) {
    throw new KeyConfigError(
      `no mutually supported suite in key config (advertised: ${config.suites
        .map((s) => `(0x${s.kdfId.toString(16)}, 0x${s.aeadId.toString(16)})`)
        .join(', ')})`,
    );
  }
  return first;
}

export function keyConfigHex(config: KeyConfig): string {
  return bytesToHex(encodeKeyConfig(config));
}
