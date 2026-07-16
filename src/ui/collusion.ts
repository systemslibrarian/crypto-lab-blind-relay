/**
 * Exhibit 2 — the collusion toggle. The honest centerpiece: flipping it
 * performs a plain JOIN over data each party ALREADY legitimately holds.
 * No cipher is broken; that is the entire point, and the verdict indicators
 * keep the two claims separate (crypto result ≠ security verdict).
 */
import { collude, computeViews, type Exchange } from '../relay/exchange';
import { esc } from './dom';
import { LABS } from './links';

export function collusionPanel(): string {
  return `
  <section class="panel" aria-labelledby="collude-h">
    <h2 id="collude-h">The collusion toggle</h2>
    <p class="panel-lede">Everything above holds under one assumption: <strong>the relay and the gateway do not
    compare notes.</strong> That assumption is organizational — a contract, a jurisdiction, a reputation — not
    cryptographic. Flip it and watch.</p>
    <div class="collusion-toggle-row">
      <button type="button" class="switch" id="collude-switch" role="switch" aria-checked="false" disabled>
        <span class="knob" aria-hidden="true"></span>
        <span id="collude-switch-label">Relay and gateway compare notes</span>
      </button>
      <span class="note" id="collude-hint">Run an exchange first.</span>
    </div>
    <div id="collude-out" role="status" aria-live="polite"></div>
    <details class="expert">
      <summary>Why this is the honest headline, not a footnote</summary>
      <p class="note">OHTTP's guarantee is <em>organizational</em>: two named parties must stay separate.
      Contrast information-theoretic PIR (<a href="${LABS.patronShield}">patron-shield</a>,
      <a href="${LABS.obliviousShelf}">oblivious-shelf</a>), where even unbounded computation by fewer than all
      servers reveals nothing — no promise required, only non-collusion of <em>any</em> one server out of n.
      OHTTP accepts the weaker assumption to get something PIR cannot offer: general HTTP to unmodified targets
      at one extra hop of cost.</p>
    </details>
  </section>`;
}

export function renderCollusion(out: HTMLElement, x: Exchange, on: boolean): void {
  if (!on) {
    out.innerHTML = `
      <div class="verdicts">
        <div class="verdict verdict-neutral">
          <span class="verdict-kicker">Cryptographic result</span>
          <span class="verdict-body">Every HPKE seal/open verified — nothing failed, nothing was forged.</span>
        </div>
        <div class="verdict verdict-ok">
          <span class="verdict-kicker">Privacy verdict</span>
          <span class="verdict-body">✓ HOLDS — no single party knows both who you are and what you asked.</span>
        </div>
      </div>`;
    return;
  }
  const record = collude(computeViews(x));
  out.innerHTML = `
    <div class="collusion-join">
      <h3>\u{1F91D} Joined log — relay's column + gateway's column</h3>
      <p class="note">Nothing below was decrypted for this view. The relay contributes the identity it always had;
      the gateway contributes the plaintext it always had; the join key is ${esc(record.joinedOn)}.</p>
      <p class="join-record">WHO: ${esc(record.who)}<br />WHAT: ${esc(record.what)}<br />JOINED ON: matching ciphertext bytes + timing</p>
    </div>
    <div class="verdicts">
      <div class="verdict verdict-neutral">
        <span class="verdict-kicker">Cryptographic result</span>
        <span class="verdict-body">Every HPKE seal/open verified — the mathematics did exactly what it promises.</span>
      </div>
      <div class="verdict verdict-alarm">
        <span class="verdict-kicker">Privacy verdict</span>
        <span class="verdict-body">✗ BROKEN — ${esc(record.who)} asked "${esc(record.what)}". Complete and instant; the crypto never noticed.</span>
      </div>
    </div>
    <p class="note">This is the whole lesson: encryption was never the guarantee here. The guarantee was two
    organizations refusing to run this join — privacy as an architecture, revocable by a business decision.</p>`;
}
