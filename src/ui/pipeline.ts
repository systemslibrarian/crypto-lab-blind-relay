/**
 * Exhibit 1 — the knowledge-split pipeline. Steps a real exchange through the
 * four parties; each party card is populated ONLY from the facts the crypto
 * actually yields that party at that step (computeViews), never hand-drawn.
 */
import { ADDRESSES, computeViews, type Exchange, type FactKind } from '../relay/exchange';
import { esc, hexPretty } from './dom';

export interface StepDef {
  title: string;
  desc: string;
  /** Which party column (0–3) holds the message during this step. */
  at: 0 | 1 | 2 | 3;
  chip: string;
}

export const STEPS: StepDef[] = [
  {
    title: 'Setup',
    at: 0,
    chip: 'request (plaintext)',
    desc: 'The client holds the request and its own identity, and has fetched the gateway’s key configuration (its HPKE public key) out of band.',
  },
  {
    title: 'Encode',
    at: 0,
    chip: 'BHTTP bytes',
    desc: 'The HTTP request becomes a self-contained binary message (Binary HTTP, RFC 9292) — a request you can carry as bytes, with no TCP connection attached to its meaning.',
  },
  {
    title: 'Seal',
    at: 0,
    chip: 'hdr ‖ enc ‖ ct',
    desc: 'HPKE Base mode seals the BHTTP bytes to the gateway’s public key, with the key-config header bound into the info string. A fresh ephemeral key makes this request unlinkable to any other.',
  },
  {
    title: 'Relay',
    at: 1,
    chip: 'ciphertext →',
    desc: 'The relay sees two things: where the bytes came from (your IP) and where they go (the gateway). What it carries is ciphertext it cannot open — its panel below shows the actual bytes it holds.',
  },
  {
    title: 'Gateway opens',
    at: 2,
    chip: 'plaintext',
    desc: 'The gateway’s private key opens the envelope. It reads your request in full — but the connection it sees comes from the relay, not from you.',
  },
  {
    title: 'Target answers',
    at: 3,
    chip: 'response',
    desc: 'The target serves the request. Its “client” is the gateway.',
  },
  {
    title: 'Seal the answer',
    at: 2,
    chip: 'nonce ‖ ct',
    desc: 'No second KEM: the gateway exports a secret from the request’s HPKE context, mixes in a fresh public response nonce, and derives one-shot response keys (the asymmetry is shown in the key-schedule panel below).',
  },
  {
    title: 'Relay returns',
    at: 1,
    chip: '← ciphertext',
    desc: 'The relay carries the response ciphertext back to you. Same blindness, opposite direction.',
  },
  {
    title: 'Client opens',
    at: 0,
    chip: 'response (plaintext)',
    desc: 'The client re-derives the identical response keys and opens the answer. Round trip complete — and no single party ever held both your identity and your request.',
  },
];

const KIND_ICON: Record<FactKind, string> = {
  identity: '\u{1F464}',
  plaintext: '\u{1F4C4}',
  ciphertext: '\u{1F512}',
  key: '\u{1F511}',
  transport: '\u{1F4E1}',
};

const PARTY_META: Record<string, { emoji: string; addr: string; role: string }> = {
  client: { emoji: '\u{1F9D1}‍\u{1F4BB}', addr: ADDRESSES.client.ip, role: 'wants to ask without being profiled' },
  relay: { emoji: '\u{1F500}', addr: `${ADDRESSES.relay.name} · ${ADDRESSES.relay.ip}`, role: 'forwards bytes; terminates your TCP/TLS connection' },
  gateway: { emoji: '\u{1F6AA}', addr: `${ADDRESSES.gateway.name} · ${ADDRESSES.gateway.ip}`, role: 'holds the HPKE private key; decrypts and forwards' },
  target: { emoji: '\u{1F3AF}', addr: ADDRESSES.target.name, role: 'the resource you actually wanted' },
};

export function pipelinePanel(): string {
  return `
  <section class="panel" aria-labelledby="pipe-h">
    <h2 id="pipe-h">The knowledge split, live</h2>
    <p class="panel-lede">Type a query you would rather not have attached to your name, then step the request
    through the system. Every fact in every card below is computed from the real bytes each party holds —
    the relay's card shows genuine HPKE ciphertext, the gateway's shows the genuine decryption.</p>
    <div class="controls">
      <div class="ctl">
        <label for="query-input">Your sensitive input (query, or note body for POST)</label>
        <input type="text" id="query-input" value="chest pain symptoms" maxlength="120" />
      </div>
      <div class="ctl">
        <label for="method-select">Request shape</label>
        <select id="method-select">
          <option value="GET" selected>GET /search?q=…</option>
          <option value="POST">POST /v1/submit + JSON body</option>
        </select>
      </div>
      <div class="ctl">
        <label for="aead-select">AEAD (both advertised in the key config)</label>
        <select id="aead-select">
          <option value="1" selected>AES-128-GCM</option>
          <option value="3">ChaCha20-Poly1305</option>
        </select>
      </div>
      <button type="button" class="btn btn-primary" id="run-btn">Run the exchange</button>
    </div>
    <div class="step-controls">
      <button type="button" class="btn" id="play-btn" disabled>&#9654; Play all steps</button>
      <button type="button" class="btn" id="back-btn" disabled>&larr; Back</button>
      <button type="button" class="btn" id="next-btn" disabled>Next step &rarr;</button>
      <button type="button" class="btn" id="all-btn" disabled>Jump to end</button>
      <p class="step-status" id="step-status" role="status" aria-live="polite">
        No exchange yet — press <strong>Run the exchange</strong> to seal a real request.
      </p>
    </div>
    <div class="wire" aria-hidden="true"><span class="wire-chip" id="wire-chip" hidden></span></div>
    <div class="parties" id="parties"></div>
    <p class="note">The addresses are RFC 5737 documentation placeholders — all four parties run in this tab
    (no packet leaves the page), but the bytes they hold are the real cryptographic artifacts.</p>
    <details class="expert">
      <summary>Expert detail: what the sealed request actually is</summary>
      <p class="note">Encapsulated Request = <code>key_id(1) ‖ kem_id(2) ‖ kdf_id(2) ‖ aead_id(2) ‖ enc(32) ‖ ct</code>.
      The header is not encrypted — the relay can read <em>which gateway key</em> you sealed to (it must not
      be per-user, or the key config itself becomes a tracking cookie; RFC 9458 §7 requires key consistency).
      HPKE runs in Base mode with <code>info = "message/bhttp request" ‖ 0x00 ‖ hdr</code>, so a header
      tampered in transit changes the derived key and the AEAD tag fails. The client is anonymous to the
      gateway by construction: Base mode authenticates no sender.</p>
    </details>
  </section>`;
}

export function renderStepStatus(step: number): string {
  const s = STEPS[step];
  return `Step ${step + 1} of ${STEPS.length} — <strong>${esc(s.title)}</strong>: ${esc(s.desc)}`;
}

export function renderParties(container: HTMLElement, x: Exchange | null, step: number): void {
  const views = x ? computeViews(x) : null;
  const order: ('client' | 'relay' | 'gateway' | 'target')[] = ['client', 'relay', 'gateway', 'target'];
  container.innerHTML = order
    .map((party, i) => {
      const meta = PARTY_META[party];
      const view = views?.find((v) => v.party === party);
      const active = x !== null && STEPS[step].at === i;
      const facts =
        view === undefined
          ? `<li class="fact"><span class="fact-label">nothing yet</span><span class="fact-value">runs when you start an exchange</span></li>`
          : view.knows
              .filter((f) => f.stage <= step)
              .map(
                (f) => `<li class="fact fact-${f.kind}">
                  <span class="fact-label">${KIND_ICON[f.kind]} knows: ${esc(f.label)}</span>
                  <span class="fact-value${f.hex ? ' mono' : ''}">${esc(f.hex ? hexPretty(f.value) : f.value)}</span>
                </li>`,
              )
              .join('') +
            view.cannotKnow
              .filter((c) => c.stage <= step)
              .map(
                (c) => `<li class="fact fact-cannot">
                  <span class="fact-label">\u{1F6AB} cannot know: ${esc(c.label)}</span>
                  <span class="fact-reason">${esc(c.reason)}</span>
                </li>`,
              )
              .join('');
      const title = party.charAt(0).toUpperCase() + party.slice(1);
      return `<article class="party${active ? ' active' : ''}" aria-label="${esc(`${title} — ${meta.addr}${active ? ' (message is here)' : ''}`)}">
        <h3><span aria-hidden="true">${meta.emoji}</span> ${title}</h3>
        <p class="addr">${esc(meta.addr)}</p>
        <p class="role-note">${esc(meta.role)}</p>
        <ul class="facts" role="list">${facts}</ul>
      </article>`;
    })
    .join('');
}
