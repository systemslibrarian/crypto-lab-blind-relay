/**
 * Exhibit 3 — break it yourself, against the real primitive and the real
 * verifier. Every button runs genuine decapsulation on the genuine bytes of
 * the current exchange; the outcomes (and their error strings) come from the
 * hub's HPKE, not from an if-statement pretending to be one.
 */
import { bytesToHex } from '@hub/hpke/bytes';
import { generateKeyPair } from '@hub/hpke/dhkem';
import { decapsulateRequest } from '../ohttp/request';
import type { Exchange } from '../relay/exchange';
import { esc, hexPretty } from './dom';

export function breakItPanel(): string {
  return `
  <section class="panel" aria-labelledby="break-h">
    <h2 id="break-h">Break it yourself</h2>
    <p class="panel-lede">Take the relay's seat. You are holding the actual encapsulated request from the
    exchange above — here are the three things a malicious relay could try. All three run the real
    decapsulation code path.</p>
    <div class="controls">
      <button type="button" class="btn" id="attack-wrongkey" disabled>1 · Decrypt with a key you generate</button>
      <button type="button" class="btn" id="attack-tamper" disabled>2 · Flip one byte, then forward it</button>
      <button type="button" class="btn btn-danger" id="attack-leak" disabled>3 · Decrypt with the gateway's leaked key</button>
    </div>
    <div id="attack-out" role="status" aria-live="polite"></div>
  </section>`;
}

function verdicts(crypto: string, verdictOk: boolean, verdict: string): string {
  return `
    <div class="verdicts">
      <div class="verdict verdict-neutral">
        <span class="verdict-kicker">Cryptographic result</span>
        <span class="verdict-body">${crypto}</span>
      </div>
      <div class="verdict ${verdictOk ? 'verdict-ok' : 'verdict-alarm'}">
        <span class="verdict-kicker">Privacy verdict</span>
        <span class="verdict-body">${verdictOk ? '✓' : '✗'} ${verdict}</span>
      </div>
    </div>`;
}

export async function attackWrongKey(out: HTMLElement, x: Exchange): Promise<void> {
  const guess = generateKeyPair();
  let errText = '';
  try {
    await decapsulateRequest(x.encRequest.encapsulated, x.keyConfig, guess.sk);
    errText = '(unreachable — decryption with a wrong key succeeded, which would be a broken AEAD)';
  } catch (e) {
    errText = `${(e as Error).name}: ${(e as Error).message}`;
  }
  out.innerHTML = `
    <div class="attack-out">
      <p>You generated a fresh X25519 key and ran the gateway's exact decapsulation code on the bytes you carry:</p>
      <p class="mono note">your key: ${esc(hexPretty(bytesToHex(guess.sk)))}</p>
      <p class="err">${esc(errText)}</p>
      <p class="note">The DH with the wrong private key derives a different shared secret, so the AEAD tag cannot
      verify. Note the error carries no detail — a wrong key, a tampered header, and a flipped ciphertext byte are
      deliberately indistinguishable.</p>
      ${verdicts(
        'AEAD tag did not verify — decryption failed.',
        true,
        'HOLDS — the relay position learns nothing without the gateway key.',
      )}
    </div>`;
}

export async function attackTamper(out: HTMLElement, x: Exchange): Promise<void> {
  const bytes = x.encRequest.encapsulated.slice();
  const idx = 7 + 32 + Math.floor(Math.random() * (bytes.length - 39));
  bytes[idx] ^= 0x01;
  let errText = '';
  try {
    await decapsulateRequest(bytes, x.keyConfig, x.gatewayKeys.sk);
    errText = '(unreachable — a tampered ciphertext opened, which would be a broken AEAD)';
  } catch (e) {
    errText = `${(e as Error).name}: ${(e as Error).message}`;
  }
  out.innerHTML = `
    <div class="attack-out">
      <p>You flipped the low bit of byte ${idx} (inside the ciphertext) and forwarded it. The real gateway,
      with the real key, tried to open it:</p>
      <p class="err">${esc(errText)}</p>
      <p class="note">The request is dropped; no partial plaintext ever exists. A relay can always destroy
      traffic (it carries it) — what it cannot do is read it or alter it undetected.</p>
      ${verdicts(
        'AEAD tag did not verify — the gateway rejected the message.',
        true,
        'HOLDS — tampering is detected and fails closed; nothing leaked.',
      )}
    </div>`;
}

export async function attackLeakedKey(out: HTMLElement, x: Exchange): Promise<void> {
  const result = await decapsulateRequest(x.encRequest.encapsulated, x.keyConfig, x.gatewayKeys.sk);
  const text = `${x.requestAsSeenByGateway.method} https://${x.requestAsSeenByGateway.authority}${x.requestAsSeenByGateway.path}`;
  out.innerHTML = `
    <div class="attack-out">
      <p>Now suppose the gateway hands its private key to the relay (or one company quietly runs both).
      Same bytes, same code path — but this time the key is right:</p>
      <p class="mono note">decrypted BHTTP: ${esc(hexPretty(bytesToHex(result.plaintext)))}</p>
      <p class="mono note">…which decodes to: ${esc(text)}</p>
      <p class="note">And the relay still knows your IP. This is collusion in one line of key material —
      the decryption <em>succeeding</em> is the alarm.</p>
      ${verdicts(
        'Decryption succeeded — a valid open, exactly as HPKE promises the key holder.',
        false,
        `BROKEN — the party that knows your identity now also reads your request. The system failed while every primitive held.`,
      )}
    </div>`;
}
