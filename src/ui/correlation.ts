/**
 * Exhibit — correlation WITHOUT collusion. The collusion toggle needs the two
 * parties to talk; this shows they don't have to: anyone reading both logs
 * later can join them on metadata. Sizes are the real encapsulation lengths;
 * the learner performs the join, then turns on RFC 9292 padding and watches
 * it collapse into an anonymity set — while timing honestly stays exposed.
 */
import type { KeyPair } from '@hub/hpke/dhkem';
import { type CrowdRun, joinBySize, runCrowd } from '../relay/correlation';
import { esc } from './dom';

export const PAD_TO = 256;

export function correlationPanel(): string {
  return `
  <section class="panel" aria-labelledby="corr-h">
    <h2 id="corr-h">Correlation without collusion</h2>
    <p class="panel-lede">The toggle above required the relay and gateway to actively compare notes. Here is the
    quieter failure: they never talk — someone (a court order, a breach, an acquisition) simply reads both logs
    later. Four clients send four different queries "at the same time"; every byte is genuinely encrypted;
    watch what the logs give away anyway.</p>
    <div class="controls">
      <button type="button" class="btn btn-primary" id="crowd-btn">Simulate 4 clients at once</button>
      <div class="ctl ctl-check">
        <label for="crowd-pad"><input type="checkbox" id="crowd-pad" /> Pad every request to ${PAD_TO} bytes (RFC 9292 §3.8)</label>
      </div>
      <button type="button" class="btn" id="crowd-join" disabled>Join the two logs on size</button>
    </div>
    <div id="crowd-out" role="status" aria-live="polite"></div>
    <details class="expert">
      <summary>What padding does and does not fix</summary>
      <p class="note">Zero padding is part of BHTTP itself: trailing zero bytes decode to the identical request,
      so the gateway notices nothing while every ciphertext becomes the same length. That kills the size join.
      It does <em>not</em> kill the timing join — with sparse traffic, "the only request in this second" is its
      own identifier. Defeating timing needs batching or mixing, which OHTTP deliberately does not provide;
      that trade is what separates it from Tor and mixnets in the comparison below.</p>
    </details>
  </section>`;
}

function logTables(run: CrowdRun): string {
  const relayRows = run.relayLog
    .map(
      (r) => `<tr><td>t+${r.at} ms</td><td class="mono">${esc(r.clientIp)}</td><td>${r.size} B</td></tr>`,
    )
    .join('');
  const gatewayRows = run.gatewayLog
    .map(
      (g) => `<tr><td>t+${g.at} ms</td><td>${g.size} B</td><td class="mono">${esc(g.requestLine)}</td></tr>`,
    )
    .join('');
  return `
    <div class="sched-grid">
      <div class="sched">
        <h3>Relay's access log (knows WHO)</h3>
        <table class="cmp log-table">
          <thead><tr><th scope="col">arrival*</th><th scope="col">client IP</th><th scope="col">ciphertext size</th></tr></thead>
          <tbody>${relayRows}</tbody>
        </table>
      </div>
      <div class="sched">
        <h3>Gateway's log (knows WHAT, sorted by size)</h3>
        <table class="cmp log-table">
          <thead><tr><th scope="col">arrival*</th><th scope="col">ciphertext size</th><th scope="col">decrypted request</th></tr></thead>
          <tbody>${gatewayRows}</tbody>
        </table>
      </div>
    </div>
    <p class="note">* the sizes are the real lengths of the real encapsulated requests; the arrival clock is
    simulated (all four parties live in this tab).</p>`;
}

export function renderCrowd(out: HTMLElement, run: CrowdRun): void {
  out.innerHTML =
    logTables(run) +
    `<p class="note">${
      run.padTo === undefined
        ? 'Four queries, four different lengths — HPKE adds a constant overhead, so plaintext length shows straight through the encryption.'
        : `Every request padded to ${run.padTo} bytes of BHTTP before sealing — the gateway decodes the identical queries, but the wire sizes are now uniform.`
    } Now join the logs.</p>`;
}

export function renderJoin(out: HTMLElement, run: CrowdRun): void {
  const join = joinBySize(run);
  const matchedRows = join.matched
    .map(
      (m) =>
        `<li class="fact"><span class="fact-label">size ${m.size} B appears once in each log</span>
         <span class="fact-value mono">${esc(m.clientIp)} → ${esc(m.requestLine)}</span></li>`,
    )
    .join('');
  const ambiguousRows = join.ambiguous
    .map(
      (a) =>
        `<li class="fact fact-cannot"><span class="fact-label">size ${a.size} B appears ${a.clientIps.length}× in each log</span>
         <span class="fact-reason">anonymity set: any of {${esc(a.clientIps.join(', '))}} could have sent any of the ${a.requestLines.length} requests</span></li>`,
    )
    .join('');
  const broken = join.matched.length > 0;
  out.innerHTML =
    logTables(run) +
    `<h3>Join result — no key material used</h3>
     <ul class="facts" role="list">${matchedRows}${ambiguousRows}</ul>
     <div class="verdicts">
       <div class="verdict verdict-neutral">
         <span class="verdict-kicker">Cryptographic result</span>
         <span class="verdict-body">Every request stayed encrypted end to end — nothing was decrypted for this join.</span>
       </div>
       <div class="verdict ${broken ? 'verdict-alarm' : 'verdict-ok'}">
         <span class="verdict-kicker">Privacy verdict</span>
         <span class="verdict-body">${
           broken
             ? `✗ BROKEN for ${join.matched.length} of ${run.relayLog.length} clients — identified by ciphertext size alone, no collusion required.`
             : `✓ size no longer identifies anyone — all ${run.relayLog.length} clients share one anonymity set (timing still correlates when traffic is sparse).`
         }</span>
       </div>
     </div>`;
}

export type CrowdRunner = (padTo?: number) => Promise<CrowdRun>;

/** Wire the exhibit; crypto runs through the same session gateway keys. */
export function wireCorrelation(gatewayKeys: KeyPair): void {
  const btn = document.getElementById('crowd-btn') as HTMLButtonElement;
  const joinBtn = document.getElementById('crowd-join') as HTMLButtonElement;
  const pad = document.getElementById('crowd-pad') as HTMLInputElement;
  const out = document.getElementById('crowd-out') as HTMLElement;
  let run: CrowdRun | null = null;
  btn.addEventListener('click', () => {
    void (async () => {
      btn.disabled = true;
      try {
        run = await runCrowd(gatewayKeys, pad.checked ? PAD_TO : undefined);
        renderCrowd(out, run);
        joinBtn.disabled = false;
      } finally {
        btn.disabled = false;
      }
    })();
  });
  joinBtn.addEventListener('click', () => {
    if (run) renderJoin(out, run);
  });
  pad.addEventListener('change', () => {
    // A padding change invalidates the current crowd — force a fresh run.
    run = null;
    joinBtn.disabled = true;
    out.innerHTML = `<p class="note">Padding ${pad.checked ? 'ON' : 'OFF'} — simulate the crowd again to see the effect.</p>`;
  });
}
