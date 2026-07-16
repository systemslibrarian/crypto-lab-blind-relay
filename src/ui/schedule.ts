/**
 * Exhibit 4 — the request/response asymmetry, computed both sides and
 * compared byte-for-byte. The response path has no second KEM; showing the
 * two derivations side by side with the real bytes of the current exchange
 * is what makes that asymmetry visible rather than asserted.
 */
import { bytesToHex } from '@hub/hpke/bytes';
import type { Exchange } from '../relay/exchange';
import { esc, hexPretty } from './dom';

export function schedulePanel(): string {
  return `
  <section class="panel" aria-labelledby="sched-h">
    <h2 id="sched-h">Two directions, two key schedules</h2>
    <p class="panel-lede">The request rides full HPKE. The response does not run a second KEM — the gateway
    <em>exports</em> a secret from the request's context and mixes in a fresh public nonce. Both derivations
    below use the live bytes of your current exchange.</p>
    <div id="sched-out"><p class="note">Run an exchange above to populate the schedules.</p></div>
    <details class="expert">
      <summary>Why no second KEM — and why the nonce?</summary>
      <p class="note">A KEM is only needed to establish a shared secret with someone you have no state with.
      After the request, gateway and client already share the HPKE context, so the response can key itself from
      <code>context.Export("message/bhttp response", max(Nn,Nk))</code> — saving a DH and 32 bytes on the wire.
      The <code>response_nonce</code> is public and random: it salts the derivation so a gateway answering many
      requests under one key pair never reuses an (AEAD key, nonce) pair, and it re-binds the response to this
      exact request by concatenating with the request's <code>enc</code>. The Expand labels are the literal
      strings <code>"key"</code> and <code>"nonce"</code> — plain HKDF, not the labeled HPKE variant the request
      path uses.</p>
    </details>
  </section>`;
}

function hexLine(label: string, hex: string): string {
  return `<li>${esc(label)}<span class="hex">${esc(hexPretty(hex))}</span></li>`;
}

export function renderSchedules(out: HTMLElement, x: Exchange): void {
  const req = x.encRequest;
  const gw = x.encResponse.schedule; // derived by the gateway to seal
  const cl = x.clientDecap.schedule; // derived independently by the client to open
  const keysMatch = bytesToHex(gw.aeadKey) === bytesToHex(cl.aeadKey);
  const noncesMatch = bytesToHex(gw.aeadNonce) === bytesToHex(cl.aeadNonce);
  out.innerHTML = `
    <div class="sched-grid">
      <div class="sched">
        <h3>Request path — full HPKE (RFC 9180)</h3>
        <ol>
          ${hexLine('KEM encapsulation enc = pkE', bytesToHex(req.enc))}
          ${hexLine('info = "message/bhttp request" ‖ 0x00 ‖ hdr', bytesToHex(req.info))}
          ${hexLine('labeled key schedule → AEAD key', bytesToHex(req.context.key))}
          ${hexLine('base_nonce (seq-XORed per message)', bytesToHex(req.context.baseNonce))}
        </ol>
      </div>
      <div class="sched">
        <h3>Response path — export + HKDF (RFC 9458 §4.4)</h3>
        <ol>
          ${hexLine('secret = Export("message/bhttp response")', bytesToHex(gw.secret))}
          ${hexLine('response_nonce (fresh, public)', bytesToHex(gw.responseNonce))}
          ${hexLine('salt = enc ‖ response_nonce', bytesToHex(gw.salt))}
          ${hexLine('prk = Extract(salt, secret)', bytesToHex(gw.prk))}
          ${hexLine('key = Expand(prk, "key")', bytesToHex(gw.aeadKey))}
          ${hexLine('nonce = Expand(prk, "nonce")', bytesToHex(gw.aeadNonce))}
        </ol>
      </div>
    </div>
    <p class="match-row" role="status">Client re-derivation vs gateway derivation:
      <span class="${keysMatch ? 'match-ok' : 'match-bad'}">${keysMatch ? '✓ AEAD keys byte-identical' : '✗ AEAD KEYS DIFFER'}</span> ·
      <span class="${noncesMatch ? 'match-ok' : 'match-bad'}">${noncesMatch ? '✓ nonces byte-identical' : '✗ NONCES DIFFER'}</span>
      — two parties, zero response-path messages about keys.</p>`;
}
