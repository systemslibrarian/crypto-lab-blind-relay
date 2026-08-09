# Blind Relay — Oblivious HTTP (RFC 9458)

## What It Is

An interactive browser demo of **Oblivious HTTP (RFC 9458)**: a three-party HTTP request where the
**relay** knows your address but not your request, the **gateway** knows your request but not your
address, and neither can be trusted alone.

The point it teaches: encryption stops a party from *reading* data — it does nothing about a party
*knowing that you asked*. OHTTP gets privacy from a different move entirely: splitting knowledge
between two parties who must not collude. **Privacy as an architecture, not an algorithm.**

The cryptography is real and runs in your tab:

- **HPKE (RFC 9180)** — consumed from the hub lab
  [crypto-lab-hpke-envelope](https://github.com/systemslibrarian/crypto-lab-hpke-envelope)
  (DHKEM(X25519, HKDF-SHA256) · HKDF-SHA256 · AES-128-GCM / ChaCha20-Poly1305), not reimplemented here.
- **RFC 9458 encapsulation** — hand-rolled in this repo: key configuration, the 7-byte header,
  the `info` binding, and the exported-secret response key schedule, all verified against the
  RFC 9458 Appendix A test vector.
- **Binary HTTP (RFC 9292)** — a hand-rolled known-length codec covering exactly the messages the
  demo sends (not a conformance suite).

The **network is simulated**: all four parties live in one page, and the IP addresses are
RFC 5737 documentation placeholders. Security model: OHTTP's guarantee is *organizational*
(two named parties must not collude), and the demo's centerpiece is the switch that revokes it.
**Not production crypto — a teaching demo.**

## Exhibits

1. **The knowledge split, live** — type a query (or a POST body), run a real exchange, and play or
   step it through client → relay → gateway → target. Each party's card is populated from the
   actual bytes the crypto yields that party: the relay's card shows genuine HPKE ciphertext, the
   gateway's shows the genuine decryption, complete with what each party *cannot* know and why.
2. **The collusion toggle** — the honest centerpiece. Relay and gateway compare notes: a plain
   JOIN over data each already holds recovers *who asked what*, instantly and completely. The
   cryptographic-result indicator and the privacy verdict are rendered separately — every AEAD
   verified, and privacy is BROKEN anyway.
3. **Correlation without collusion** — the quieter failure: four clients send four queries, and
   you join the relay's log to the gateway's log two ways. On ciphertext *size* (the real
   encapsulation lengths — no key material touched), RFC 9292 zero padding collapses the join into
   one anonymity set. On *timing*, padding changes nothing and everyone is identified again — the
   honest demonstration that the remaining fix (batching/mixing) is a cost OHTTP declines to pay.
4. **Break it yourself** — take the relay's seat against the real verifier: decrypt with a key you
   generate (real `OpenError`), flip one ciphertext byte and watch the gateway fail closed, then
   borrow the gateway's leaked key and watch decryption *succeed* — rendered as the alarm it is.
5. **Two directions, two key schedules** — the request rides full HPKE; the response derives from
   `context.Export("message/bhttp response")` + a fresh public nonce through plain HKDF, with the
   client's and gateway's independent derivations compared byte-for-byte.
6. **OHTTP vs VPN vs Tor vs IT-PIR** — what each hides, from whom, under what assumption, at what
   cost — honest that OHTTP has the *weakest* collusion story of the four.
7. **Where you already use this** — Apple iCloud Private Relay (same split, MASQUE-based),
   Firefox telemetry (OHTTP itself), Privacy Pass rate limiting. Named, not implemented.

## When to Use It

- Use OHTTP-style splits when the *metadata* (who asked) is the sensitive part and the two
  operators are genuinely independent — telemetry, safe-browsing lookups, token issuance.
- Use it when the target must remain an ordinary HTTP service and Tor's latency is unacceptable.
- Do **NOT** use it when your threat model includes the relay and gateway cooperating (legal
  compulsion reaches both), when request *content* identifies you (a session cookie defeats the
  entire scheme), or when timing/size correlation is in scope — OHTTP hides none of that.

## Live Demo

**<https://systemslibrarian.github.io/crypto-lab-blind-relay/>** — run an exchange, step the
request through the split, flip the collusion switch, and mount the three relay-seat attacks.

## What Can Go Wrong

- **Collusion** — the guarantee is a promise between two organizations; the demo's switch shows
  the failure is total and requires no cryptanalysis.
- **Per-user key configs** — a gateway handing each client a distinct key config turns the key
  itself into a tracking cookie (RFC 9458 §7 requires key consistency).
- **Identifying request content** — OHTTP anonymizes the envelope, not the letter; cookies or
  account tokens inside the request re-link everything.
- **Traffic analysis** — one request in, one request out: anyone reading both logs can correlate
  by size and timing without the parties "colluding" formally — exhibit 3 performs the size join
  live and shows BHTTP padding as the (partial) countermeasure.
- **Malleability is not the risk** — flipping any byte fails closed (AEAD); a hostile relay can
  deny service but cannot read or undetectably alter.

## Real-World Usage

Apple iCloud Private Relay (two-hop split via MASQUE), Firefox telemetry & search suggestions
(OHTTP proper, relay run by a separate operator), Privacy Pass rate-limited token issuance
(issuer/mediator split). See the in-page panel for the precise claims.

## How to Run Locally

This lab **consumes the hub's HPKE module** from a sibling checkout:

```bash
git clone https://github.com/systemslibrarian/crypto-lab-hpke-envelope
git clone https://github.com/systemslibrarian/crypto-lab-blind-relay
cd crypto-lab-blind-relay
npm install
npm run dev        # Vite dev server
npm test           # 60 unit tests (Vitest)
npm run build      # typecheck + production build
npm run test:a11y  # WCAG 2.1 A/AA gate, 2 themes x 2 viewports (Playwright)
```

(CI checks the hub out into `./hub/` instead; `vite.config.ts` looks in both places.)

## Related Demos

- [crypto-lab-hpke-envelope](https://systemslibrarian.github.io/crypto-lab-hpke-envelope/) — the
  HPKE internals this lab deliberately does not rebuild.
- [crypto-lab-patron-shield](https://systemslibrarian.github.io/crypto-lab-patron-shield/) and
  [crypto-lab-oblivious-shelf](https://systemslibrarian.github.io/crypto-lab-oblivious-shelf/) —
  information-theoretic PIR: the strong end of the assumption spectrum this lab compares against.
- [crypto-lab-blind-hello](https://systemslibrarian.github.io/crypto-lab-blind-hello/) — TLS
  Encrypted Client Hello, HPKE's other headline deployment.

## Build & Verify

- **60 Vitest unit tests**, all passing: **17 known-answer tests against the RFC 9458 Appendix A
  vector** (`src/ohttp/kat.test.ts` — key config bytes, BHTTP encodings, `info` construction,
  request decapsulation + ciphertext reproduction, response secret/salt/prk/key/nonce, and the
  full encapsulated response), plus BHTTP round-trips, varint and padding checks, fail-closed
  suites for request/response/key-config parsing and tampering, knowledge-split/collusion model
  tests, and the passive correlation models — size join (correct unpadded, ambiguous padded) and
  timing join (defeats padding; reports ambiguity instead of guessing when arrivals overlap).
- **16 Playwright e2e tests**: a WCAG 2.1 A/AA gate that drives the lab the way a visitor drives it
  — an exchange sealed and walked through all nine pipeline steps, auto-play started and paused,
  collusion flipped on and off, four clients simulated and joined on size and on timing with padding
  off and then on, all three attacks fired, the request re-run as a POST under ChaCha20-Poly1305,
  and every disclosure opened by its own summary — and **scans after every single step**, in both
  themes at 1280px and 380px. Nothing is injected into the page: reduced motion is asked for and
  asserted, so the lab's own `prefers-reduced-motion` handling is exercised rather than bypassed.
  `violations` is not the whole oracle — the gate also fails on axe's `incomplete` bucket, on an
  arithmetic composite-aware contrast measurement (opacity and `color-mix()` included), on
  text-control border contrast (WCAG 1.4.11), on any scrolling region with no keyboard route, on any
  horizontal document overflow, and on any visible text left at `opacity: 0`. Alongside it, two
  teaching invariants (collusion renders BROKEN while the crypto
  indicator stays factually valid; padding beats the size join while the timing join still
  identifies everyone), and a **claims suite** (`e2e/claims.spec.ts`) asserting every headline
  verdict against values the page itself computed: the relay's ciphertext is byte-identical to the
  client's sealed request, the wire header is the header bound into `info`, `salt` is literally
  `enc ‖ response_nonce`, the response nonce is the prefix of the response on the wire, the padded
  crowd's wire size equals the pad target plus the overhead a different exhibit displayed, the
  leaked-key attack reproduces the client's BHTTP bytes exactly, both fail-closed attacks reach a
  real `OpenError` and say why, the collusion join quotes the relay's WHO and the gateway's WHAT,
  and every correlation counter matches the log rows it claims to summarise.
- Deploys via GitHub Actions Pages; unit tests and the accessibility gate block the deploy.

---

*Part of the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
