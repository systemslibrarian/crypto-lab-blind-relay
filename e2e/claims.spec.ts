/**
 * Claim assertions — every load-bearing verdict, counter and failure path the
 * page renders, checked against the page's OWN computed values.
 *
 * The rule throughout: never assert a constant the page could have printed
 * without doing the work. Assert that two independently rendered artifacts
 * agree (the relay's ciphertext vs the client's sealed request; the schedule
 * panel's `salt` vs `enc ‖ response_nonce`; the leaked-key attack's plaintext
 * vs the client's BHTTP bytes), or that a rendered count matches the rows it
 * claims to summarise.
 */
import { expect, test, type Page } from '@playwright/test';

/** hexPretty() groups hex in 8-char words; strip that back to raw hex. */
const raw = (s: string): string => s.replace(/\s+/g, '');

interface PartyDump {
  title: string;
  knows: { label: string; value: string }[];
  cannot: { label: string; reason: string }[];
}

async function dumpParties(page: Page): Promise<PartyDump[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('#parties article.party')).map((a) => ({
      title: (a.querySelector('h3')?.textContent ?? '').trim(),
      // `.fact-none` is the placeholder a card shows when the message has not
      // reached that party yet — it is the ABSENCE of a fact, not a fact, and
      // it exists so the `role="list"` is never empty (aria-required-children).
      knows: Array.from(a.querySelectorAll('li.fact:not(.fact-cannot):not(.fact-none)')).map((li) => ({
        label: (li.querySelector('.fact-label')?.textContent ?? '').replace(/^[\s\S]*?knows:\s*/, '').trim(),
        value: (li.querySelector('.fact-value')?.textContent ?? '').trim(),
      })),
      cannot: Array.from(a.querySelectorAll('li.fact.fact-cannot')).map((li) => ({
        label: (li.querySelector('.fact-label')?.textContent ?? '').replace(/^[\s\S]*?cannot know:\s*/, '').trim(),
        reason: (li.querySelector('.fact-reason')?.textContent ?? '').trim(),
      })),
    })),
  );
}

function knows(p: PartyDump, labelPrefix: string): string {
  const hit = p.knows.find((k) => k.label.startsWith(labelPrefix));
  expect(hit, `party "${p.title}" has no fact labelled "${labelPrefix}…" (has: ${p.knows.map((k) => k.label).join(' | ')})`).toBeTruthy();
  return hit!.value;
}

/** The key-schedule exhibit, as an ordered list of {label, hex}. */
async function dumpSchedule(page: Page): Promise<{ label: string; hex: string }[]> {
  return page.evaluate(() =>
    Array.from(document.querySelectorAll('#sched-out .sched ol li')).map((li) => {
      const hexEl = li.querySelector('.hex');
      const hex = hexEl?.textContent ?? '';
      return { label: (li.textContent ?? '').replace(hex, '').trim(), hex: hex.replace(/\s+/g, '') };
    }),
  );
}

function sched(rows: { label: string; hex: string }[], prefix: string): string {
  const hit = rows.find((r) => r.label.startsWith(prefix));
  expect(hit, `no key-schedule row starting "${prefix}" (have: ${rows.map((r) => r.label).join(' | ')})`).toBeTruthy();
  return hit!.hex;
}

async function crowdLogs(page: Page): Promise<{ relay: string[][]; gateway: string[][] }> {
  return page.evaluate(() => {
    const tables = document.querySelectorAll('#crowd-out table.log-table');
    const rows = (t: Element | undefined): string[][] =>
      t === undefined
        ? []
        : Array.from(t.querySelectorAll('tbody tr')).map((tr) =>
            Array.from(tr.querySelectorAll('td')).map((td) => (td.textContent ?? '').trim()),
          );
    return { relay: rows(tables[0]), gateway: rows(tables[1]) };
  });
}

/** Run one exchange with the given query and jump to the final step. */
async function runFull(page: Page, query: string): Promise<void> {
  await page.locator('#query-input').fill(query);
  await page.locator('#run-btn').click();
  await expect(page.locator('#next-btn')).toBeEnabled();
  await page.locator('#all-btn').click();
  await expect(page.locator('#step-status')).toContainText('Step 9 of 9');
}

async function simulateCrowd(page: Page): Promise<void> {
  await page.locator('#crowd-btn').click();
  await expect(page.locator('#crowd-join')).toBeEnabled();
  await expect(page.locator('#crowd-join-time')).toBeEnabled();
}

// ————————————————————————————————————————————————————————————————
// Exhibit 1 — the knowledge split
// ————————————————————————————————————————————————————————————————

test('pipeline: the wire bytes the relay carries ARE the client\'s sealed request, and the header on the wire is the header bound into `info`', async ({
  page,
}) => {
  await page.goto('.');
  await runFull(page, 'chest pain symptoms');

  const parties = await dumpParties(page);
  expect(parties.map((p) => p.title.replace(/\s+/g, ' ').trim())).toEqual([
    '🧑‍💻 Client',
    '🔀 Relay',
    '🚪 Gateway',
    '🎯 Target',
  ]);
  const [client, relay, gateway, target] = parties;

  const sealed = raw(knows(client, 'sealed request'));
  const carried = raw(knows(relay, 'request it carries'));
  // Cross-path agreement: the relay's exhibit is not a redraw of the client's,
  // it is the same Uint8Array rendered from the other party's view.
  expect(carried).toBe(sealed);

  // hdr(7) ‖ enc(32) ‖ ct — structure asserted against the schedule exhibit's enc.
  const rows = await dumpSchedule(page);
  const enc = sched(rows, 'KEM encapsulation enc');
  expect(enc).toHaveLength(64);
  expect(sealed.slice(14, 78)).toBe(enc);
  expect(sealed.length).toBeGreaterThan(78);

  // info = "message/bhttp request" ‖ 0x00 ‖ hdr — the last 8 bytes of the info
  // string must be 0x00 followed by the exact 7 header bytes on the wire.
  const info = sched(rows, 'info =');
  const label = Buffer.from('message/bhttp request', 'utf8').toString('hex');
  expect(info).toBe(`${label}00${sealed.slice(0, 14)}`);

  // The relay's own size counter must equal the byte length of the bytes it shows.
  const sizes = knows(relay, 'timing + sizes');
  const m = /req\s+(\d+)\s*B\s*→\s*res\s+(\d+)\s*B/.exec(sizes);
  expect(m, `unparsable size fact: ${sizes}`).toBeTruthy();
  expect(Number(m![1])).toBe(sealed.length / 2);
  const carriedResponse = raw(knows(relay, 'response it carries back'));
  expect(Number(m![2])).toBe(carriedResponse.length / 2);

  // The gateway's decryption must reproduce the client's plaintext request line.
  expect(knows(gateway, 'request (decrypted)')).toBe(knows(client, 'request (plaintext)'));
  expect(knows(target, 'request (served)')).toBe(knows(client, 'request (plaintext)'));

  // …and every party card must carry at least one reasoned "cannot know".
  for (const p of parties) {
    expect(p.cannot.length, `${p.title} has no cannot-know entries`).toBeGreaterThan(0);
    for (const c of p.cannot) expect(c.reason.length, `${p.title} / ${c.label}`).toBeGreaterThan(10);
  }
});

test('pipeline: the sealed request really is sealed — the query is visible to the client and gateway, absent from the relay', async ({
  page,
}) => {
  await page.goto('.');
  const marker = 'zebra marker query';
  await runFull(page, marker);

  const [client, relay, gateway] = await dumpParties(page);
  const sealed = raw(knows(client, 'sealed request'));
  const bhttp = raw(knows(client, 'request as BHTTP bytes'));
  const markerHex = Buffer.from(marker.replace(/ /g, '+'), 'utf8').toString('hex');

  // Plaintext side: the marker is in the BHTTP encoding and in both plaintext views.
  expect(bhttp).toContain(markerHex);
  expect(knows(client, 'request (plaintext)')).toContain('zebra+marker+query');
  expect(knows(gateway, 'request (decrypted)')).toContain('zebra+marker+query');

  // Ciphertext side: neither the marker nor the whole BHTTP body survives into
  // the bytes the relay holds. If encryption were skipped this fails loudly.
  const relayText = JSON.stringify(relay);
  expect(relayText).not.toContain('zebra');
  expect(sealed).not.toContain(markerHex);
  expect(sealed).not.toContain(bhttp);
});

test('pipeline: facts appear only at the step where the party acquires them', async ({ page }) => {
  await page.goto('.');
  await page.locator('#query-input').fill('chest pain symptoms');
  await page.locator('#run-btn').click();
  await expect(page.locator('#step-status')).toContainText('Step 1 of 9');

  // Step 1 (Setup): the relay has not seen a byte yet.
  let parties = await dumpParties(page);
  expect(parties[1].knows).toEqual([]);
  expect(parties[2].knows).toEqual([]);
  expect(parties[0].knows.length).toBeGreaterThan(0);
  // Back is disabled at the first step, Jump-to-end is not.
  await expect(page.locator('#back-btn')).toBeDisabled();
  await expect(page.locator('#all-btn')).toBeEnabled();

  // Step 4 (Relay) is where the relay first holds the ciphertext.
  for (let i = 0; i < 3; i++) await page.locator('#next-btn').click();
  await expect(page.locator('#step-status')).toContainText('Step 4 of 9');
  parties = await dumpParties(page);
  expect(parties[1].knows.length).toBeGreaterThan(0);
  expect(raw(knows(parties[1], 'request it carries'))).toBe(raw(knows(parties[0], 'sealed request')));
  // The gateway has still opened nothing.
  expect(parties[2].knows).toEqual([]);

  // Step 5 (Gateway opens) is where the plaintext appears on the gateway's card.
  await page.locator('#next-btn').click();
  await expect(page.locator('#step-status')).toContainText('Step 5 of 9');
  parties = await dumpParties(page);
  expect(knows(parties[2], 'request (decrypted)')).toBe(knows(parties[0], 'request (plaintext)'));

  // The final step is the last one: Next and Jump-to-end switch off together.
  await page.locator('#all-btn').click();
  await expect(page.locator('#step-status')).toContainText('Step 9 of 9');
  await expect(page.locator('#next-btn')).toBeDisabled();
  await expect(page.locator('#all-btn')).toBeDisabled();
  await expect(page.locator('#back-btn')).toBeEnabled();
});

// ————————————————————————————————————————————————————————————————
// Exhibit 5 — two directions, two key schedules
// ————————————————————————————————————————————————————————————————

test('key schedules: salt is literally enc ‖ response_nonce, the response nonce rides the wire, and both sides derive the same key', async ({
  page,
}) => {
  await page.goto('.');
  await runFull(page, 'chest pain symptoms');

  const rows = await dumpSchedule(page);
  const enc = sched(rows, 'KEM encapsulation enc');
  const nonce = sched(rows, 'response_nonce');
  const salt = sched(rows, 'salt =');
  // RFC 9458 §4.4: salt = enc ‖ response_nonce, recomputed from the two exhibits
  // above it rather than trusted as a printed constant.
  expect(salt).toBe(enc + nonce);

  const prk = sched(rows, 'prk =');
  expect(prk).toHaveLength(64); // HKDF-SHA256 PRK
  const key = sched(rows, 'key = Expand');
  const aeadNonce = sched(rows, 'nonce = Expand');
  expect(key).toHaveLength(32); // AES-128-GCM key, 16 bytes
  expect(aeadNonce).toHaveLength(24); // 12-byte AEAD nonce
  expect(key).not.toBe(sched(rows, 'labeled key schedule'));

  // The public response nonce is the prefix of the response ciphertext the relay
  // carries — the exhibit's claim that it travels in the clear, verified.
  const [client, relay] = await dumpParties(page);
  const carriedResponse = raw(knows(relay, 'response it carries back'));
  expect(carriedResponse.startsWith(nonce)).toBe(true);

  // Both independent derivations agreed — the headline of this exhibit.
  const match = await page.locator('.match-row').innerText();
  expect(match).toContain('✓ AEAD keys byte-identical');
  expect(match).toContain('✓ nonces byte-identical');
  expect(match).not.toContain('DIFFER');

  // …and the round trip actually returned the query the user typed.
  const decoded = /^(\d+) · ([\s\S]*)$/.exec(knows(client, 'response (decrypted)'));
  expect(decoded, 'unparsable response fact').toBeTruthy();
  expect(decoded![1]).toBe('200');
  const body = JSON.parse(decoded![2]) as { query: string; results: number; top: string };
  expect(body.query).toBe('chest pain symptoms');
  expect(body.top.startsWith('chest pain symptoms')).toBe(true);
});

test('the AEAD you pick is bound into the header on the wire and changes the derived key length', async ({
  page,
}) => {
  await page.goto('.');

  await page.locator('#aead-select').selectOption('1');
  await runFull(page, 'chest pain symptoms');
  let parties = await dumpParties(page);
  let sealed = raw(knows(parties[0], 'sealed request'));
  // hdr = key_id(1) ‖ kem_id(2) ‖ kdf_id(2) ‖ aead_id(2)
  expect(sealed.slice(0, 14)).toBe('01' + '0020' + '0001' + '0001');
  expect(parties[1].knows.some((k) => k.label.includes('HPKE AES-128-GCM ciphertext'))).toBe(true);
  expect(sched(await dumpSchedule(page), 'key = Expand')).toHaveLength(32);

  await page.locator('#aead-select').selectOption('3');
  await runFull(page, 'chest pain symptoms');
  parties = await dumpParties(page);
  sealed = raw(knows(parties[0], 'sealed request'));
  expect(sealed.slice(0, 14)).toBe('01' + '0020' + '0001' + '0003');
  expect(parties[1].knows.some((k) => k.label.includes('HPKE ChaCha20-Poly1305 ciphertext'))).toBe(true);
  // ChaCha20-Poly1305 keys are 32 bytes; AES-128-GCM's are 16.
  expect(sched(await dumpSchedule(page), 'key = Expand')).toHaveLength(64);
});

test('POST shape: the gateway reads the body it was sent and the target echoes its exact byte length', async ({
  page,
}) => {
  await page.goto('.');
  await page.locator('#method-select').selectOption('POST');
  await runFull(page, 'a note about my finances');

  const [client, , gateway] = await dumpParties(page);
  expect(knows(gateway, 'request (decrypted)')).toBe('POST https://api.example.com/v1/submit');
  expect(knows(client, 'request (plaintext)')).toBe('POST https://api.example.com/v1/submit');

  const decoded = /^(\d+) · ([\s\S]*)$/.exec(knows(client, 'response (decrypted)'));
  const body = JSON.parse(decoded![2]) as { echo: string; path: string; received: number };
  expect(body.echo).toBe('POST');
  expect(body.path).toBe('/v1/submit');
  // The target's `received` counter must equal the real byte length of the JSON
  // body the client sealed — computed here, not copied from the page.
  const expected = Buffer.byteLength(JSON.stringify({ note: 'a note about my finances' }), 'utf8');
  expect(body.received).toBe(expected);
});

// ————————————————————————————————————————————————————————————————
// Exhibit 2 — the collusion toggle
// ————————————————————————————————————————————————————————————————

test('collusion: the joined row is exactly the relay\'s WHO and the gateway\'s WHAT, and the toggle is reversible', async ({
  page,
}) => {
  await page.goto('.');
  await runFull(page, 'chest pain symptoms');
  const [client, relay, gateway] = await dumpParties(page);
  const who = knows(relay, 'client IP');
  const what = knows(gateway, 'request (decrypted)');
  expect(who).toBe(knows(client, 'own identity'));

  // Before: the two indicators are rendered separately and privacy HOLDS.
  await expect(page.locator('#collude-switch')).toHaveAttribute('aria-checked', 'false');
  await expect(page.locator('#collude-out .verdict-ok')).toContainText('HOLDS');
  await expect(page.locator('#collude-out .verdict-alarm')).toHaveCount(0);

  await page.locator('#collude-switch').click();
  await expect(page.locator('#collude-switch')).toHaveAttribute('aria-checked', 'true');

  // The join record must quote the two parties' own values, not a template.
  const record = await page.locator('#collude-out .join-record').innerText();
  expect(record).toContain(`WHO: ${who}`);
  expect(record).toContain(`WHAT: ${what}`);

  // The privacy verdict is BROKEN and says why, naming both halves of the split.
  const alarm = await page.locator('#collude-out .verdict-alarm').innerText();
  expect(alarm).toContain('BROKEN');
  expect(alarm).toContain(who);
  expect(alarm).toContain(what);
  // …while the cryptographic result stays factually valid. That separation is
  // the entire teaching point of this exhibit.
  await expect(page.locator('#collude-out .verdict-neutral')).toContainText('Every HPKE seal/open verified');
  await expect(page.locator('#collude-out .verdict-ok')).toHaveCount(0);

  // Reversible: flipping back restores the HOLDS verdict.
  await page.locator('#collude-switch').click();
  await expect(page.locator('#collude-switch')).toHaveAttribute('aria-checked', 'false');
  await expect(page.locator('#collude-out .verdict-ok')).toContainText('HOLDS');
  await expect(page.locator('#collude-out .verdict-alarm')).toHaveCount(0);
});

// ————————————————————————————————————————————————————————————————
// Exhibit 4 — break it yourself
// ————————————————————————————————————————————————————————————————

test('attacks: a wrong key and a flipped byte both fail closed; the leaked key recovers the exact plaintext', async ({
  page,
}) => {
  await page.goto('.');
  await runFull(page, 'chest pain symptoms');
  const [client, relay, gateway] = await dumpParties(page);
  const sealedBytes = raw(knows(relay, 'request it carries')).length / 2;

  // 1 — a key the relay generated itself.
  await page.locator('#attack-wrongkey').click();
  const wrong = page.locator('#attack-out .attack-out');
  await expect(wrong).toBeVisible();
  const wrongText = await wrong.innerText();
  const usedKey = /your key:\s*([0-9a-f\s]+)/.exec(wrongText);
  expect(usedKey, 'attack 1 did not print the key it used').toBeTruthy();
  // It genuinely is a different key from the gateway's.
  expect(raw(usedKey![1])).not.toBe(raw(knows(gateway, 'HPKE private key')));
  expect(wrongText).toContain('OpenError');
  expect(wrongText).toContain('authentication tag did not verify');
  await expect(page.locator('#attack-out .verdict-ok')).toContainText('HOLDS');
  await expect(page.locator('#attack-out .verdict-alarm')).toHaveCount(0);
  await expect(page.locator('#attack-out .verdict-neutral')).toContainText('decryption failed');

  // 2 — one bit flipped inside the ciphertext, opened with the RIGHT key.
  await page.locator('#attack-tamper').click();
  const tamperText = await page.locator('#attack-out .attack-out').innerText();
  const idx = /low bit of byte (\d+)/.exec(tamperText);
  expect(idx, 'attack 2 did not name the byte it flipped').toBeTruthy();
  // The flip must land inside the ciphertext: past hdr(7) + enc(32), before the end.
  expect(Number(idx![1])).toBeGreaterThanOrEqual(39);
  expect(Number(idx![1])).toBeLessThan(sealedBytes);
  expect(tamperText).toContain('OpenError');
  expect(tamperText).toContain('authentication tag did not verify');
  await expect(page.locator('#attack-out .verdict-ok')).toContainText('fails closed');
  await expect(page.locator('#attack-out .verdict-alarm')).toHaveCount(0);

  // 3 — the gateway's key leaks: decryption SUCCEEDS, and that is the alarm.
  await page.locator('#attack-leak').click();
  await expect(page.locator('#attack-out .verdict-alarm')).toBeVisible();
  const leakText = await page.locator('#attack-out .attack-out').innerText();
  const recoveredHex = /decrypted BHTTP:\s*([0-9a-f\s]+)/.exec(leakText);
  expect(recoveredHex, 'attack 3 did not print the plaintext it recovered').toBeTruthy();
  // Cross-path agreement: the relay-seat attack reproduced, byte for byte, the
  // BHTTP encoding the client card shows — the attack decrypted, it did not replay.
  expect(raw(recoveredHex![1])).toBe(raw(knows(client, 'request as BHTTP bytes')));
  const line = /…which decodes to:\s*(.+)/.exec(leakText);
  expect(line, 'attack 3 did not print the decoded request line').toBeTruthy();
  expect(line![1].trim()).toBe(knows(gateway, 'request (decrypted)'));
  await expect(page.locator('#attack-out .verdict-alarm')).toContainText('BROKEN');
  await expect(page.locator('#attack-out .verdict-ok')).toHaveCount(0);
  await expect(page.locator('#attack-out .verdict-neutral')).toContainText('Decryption succeeded');
});

// ————————————————————————————————————————————————————————————————
// Exhibit 3 — correlation without collusion
// ————————————————————————————————————————————————————————————————

test('correlation, unpadded: the size join identifies every client, and every row it claims is backed by the logs', async ({
  page,
}) => {
  await page.goto('.');
  await simulateCrowd(page);
  await page.locator('#crowd-join').click();

  const { relay, gateway } = await crowdLogs(page);
  expect(relay).toHaveLength(4);
  expect(gateway).toHaveLength(4);

  const relaySizes = relay.map((r) => Number(/(\d+)\s*B/.exec(r[2])![1]));
  const gatewaySizes = gateway.map((g) => Number(/(\d+)\s*B/.exec(g[1])![1]));
  // Unpadded: four different plaintext lengths show straight through, and the
  // gateway's log is sorted by size exactly as its heading claims.
  expect(new Set(relaySizes).size).toBe(4);
  expect([...gatewaySizes].sort((a, b) => a - b)).toEqual(gatewaySizes);
  expect([...relaySizes].sort((a, b) => a - b)).toEqual([...gatewaySizes].sort((a, b) => a - b));
  expect(new Set(relay.map((r) => r[1])).size).toBe(4); // four distinct client IPs

  // Every "matched" row must be reconstructible from the two tables.
  const matched = await page.locator('#crowd-out ul.facts li.fact:not(.fact-cannot)').allInnerTexts();
  expect(matched).toHaveLength(4);
  for (const row of matched) {
    const size = Number(/size (\d+) B appears once in each log/.exec(row)![1]);
    const ip = /(\d+\.\d+\.\d+\.\d+)/.exec(row)![1];
    const line = /→\s*(GET .+)/.exec(row)![1].trim();
    expect(relay.find((r) => r[1] === ip && Number(/(\d+)/.exec(r[2])![1]) === size), `relay log has no ${ip} at ${size} B`).toBeTruthy();
    expect(gateway.find((g) => g[2] === line && Number(/(\d+)/.exec(g[1])![1]) === size), `gateway log has no "${line}" at ${size} B`).toBeTruthy();
  }
  await expect(page.locator('#crowd-out ul.facts li.fact-cannot')).toHaveCount(0);

  // The counter in the verdict must equal the rows it just listed, over the
  // number of clients the relay log actually holds.
  const alarm = await page.locator('#crowd-out .verdict-alarm').innerText();
  expect(alarm).toContain(`BROKEN for ${matched.length} of ${relay.length} clients`);
  expect(alarm).toContain('ciphertext size alone');
  await expect(page.locator('#crowd-out .verdict-neutral')).toContainText('nothing was decrypted');
  await expect(page.locator('#crowd-out .verdict-ok')).toHaveCount(0);

  // The timing join identifies the same four, by the clock alone.
  await page.locator('#crowd-join-time').click();
  const timed = await page.locator('#crowd-out ul.facts li.fact').allInnerTexts();
  expect(timed).toHaveLength(4);
  for (const row of timed) {
    const delta = Number(/gateway arrival (\d+) ms after a lone relay arrival/.exec(row)![1]);
    expect(delta).toBeGreaterThan(0);
    expect(delta).toBeLessThanOrEqual(5); // the model's join window
  }
  await expect(page.locator('#crowd-out .verdict-alarm')).toContainText(
    `BROKEN for ${timed.length} of ${relay.length} clients`,
  );
});

test('correlation, padded: sizes collapse to one anonymity set, timing still names everyone', async ({ page }) => {
  await page.goto('.');

  // First establish, from a different exhibit, what HPKE+OHTTP overhead costs:
  // sealed length minus BHTTP length. The padded crowd must land on padTo + that.
  await runFull(page, 'chest pain symptoms');
  const [client] = await dumpParties(page);
  const overhead =
    raw(knows(client, 'sealed request')).length / 2 - raw(knows(client, 'request as BHTTP bytes')).length / 2;
  expect(overhead).toBeGreaterThan(0);

  const padLabel = await page.locator('label[for="crowd-pad"]').innerText();
  const padTo = Number(/Pad every request to (\d+) bytes/.exec(padLabel)![1]);

  await page.locator('#crowd-pad').check();
  // Checking the box must invalidate any stale crowd rather than silently reuse it.
  await expect(page.locator('#crowd-join')).toBeDisabled();
  await expect(page.locator('#crowd-join-time')).toBeDisabled();
  await expect(page.locator('#crowd-out')).toContainText('Padding ON');

  await simulateCrowd(page);
  await page.locator('#crowd-join').click();

  const { relay, gateway } = await crowdLogs(page);
  const relaySizes = relay.map((r) => Number(/(\d+)\s*B/.exec(r[2])![1]));
  expect(new Set(relaySizes).size).toBe(1);
  // Cross-exhibit agreement: the padded wire size is the pad target plus the
  // overhead the single-exchange exhibit independently displayed.
  expect(relaySizes[0]).toBe(padTo + overhead);
  expect(gateway.map((g) => Number(/(\d+)\s*B/.exec(g[1])![1]))).toEqual(relaySizes);
  // The four distinct queries survived the padding — the gateway decoded them all.
  expect(new Set(gateway.map((g) => g[2])).size).toBe(4);

  // The join now yields one ambiguity row covering every client, and no matches.
  await expect(page.locator('#crowd-out ul.facts li.fact:not(.fact-cannot)')).toHaveCount(0);
  const amb = await page.locator('#crowd-out ul.facts li.fact-cannot').allInnerTexts();
  expect(amb).toHaveLength(1);
  expect(amb[0]).toContain(`size ${relaySizes[0]} B appears ${relay.length}× in each log`);
  for (const r of relay) expect(amb[0]).toContain(r[1]);
  expect(amb[0]).toContain(`any of the ${gateway.length} requests`);

  const ok = await page.locator('#crowd-out .verdict-ok').innerText();
  expect(ok).toContain(`all ${relay.length} clients share one anonymity set`);
  await expect(page.locator('#crowd-out .verdict-alarm')).toHaveCount(0);

  // …and the honest half: padding bought nothing against the clock.
  await page.locator('#crowd-join-time').click();
  const timed = await page.locator('#crowd-out ul.facts li.fact').allInnerTexts();
  expect(timed).toHaveLength(4);
  const alarm = await page.locator('#crowd-out .verdict-alarm').innerText();
  expect(alarm).toContain(`BROKEN for ${timed.length} of ${relay.length} clients`);
  expect(alarm).toContain('arrival time alone');
  expect(alarm).toContain('padding fixed the sizes and changed nothing here');
  await expect(page.locator('#crowd-out .verdict-ok')).toHaveCount(0);
});

// ————————————————————————————————————————————————————————————————
// Controls the README promises a reader can drive
// ————————————————————————————————————————————————————————————————

test('play advances the pipeline and pause stops it', async ({ page }) => {
  await page.goto('.');
  await page.locator('#query-input').fill('chest pain symptoms');
  await page.locator('#run-btn').click();
  await expect(page.locator('#step-status')).toContainText('Step 1 of 9');

  await page.locator('#play-btn').click();
  await expect(page.locator('#play-btn')).toContainText('Pause');
  await expect(page.locator('#step-status')).toContainText('Step 3 of 9', { timeout: 10000 });

  await page.locator('#play-btn').click();
  await expect(page.locator('#play-btn')).toContainText('Play all steps');
  const frozen = await page.locator('#step-status').innerText();
  await page.waitForTimeout(3000); // > 1 auto-advance interval
  expect(await page.locator('#step-status').innerText()).toBe(frozen);
});

test('the comparison table states an assumption for each of the four architectures', async ({ page }) => {
  await page.goto('.');
  const table = page.locator('table.cmp').first();
  await expect(table.locator('thead th')).toHaveCount(5); // property + 4 architectures
  const assume = table.locator('tr.this-row td');
  await expect(assume).toHaveCount(4);
  await expect(assume.nth(0)).toContainText('2 specific parties do not collude');
  await expect(assume.nth(3)).toContainText('information-theoretic');
});
