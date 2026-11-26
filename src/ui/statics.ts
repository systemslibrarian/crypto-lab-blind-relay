/** The prose panels: intro, comparison, real-world, honesty/scope. */
import { LABS } from './links';

export function introPanel(): string {
  return `
  <section class="panel" aria-labelledby="intro-h">
    <h2 id="intro-h">What is this?</h2>
    <p class="panel-lede">
      When you make a web request, the server learns two things at once: <strong>what</strong> you asked,
      and <strong>who</strong> asked it (your network address). Encryption alone cannot separate those two facts —
      it hides content from outsiders, but the party that decrypts your request still sees both.
    </p>
    <p class="panel-lede">
      Oblivious HTTP (RFC 9458) splits the two facts between two different organizations: a
      <strong>relay</strong> that sees the client connection address and carries ciphertext, and a
      <strong>gateway</strong> that sees the relay’s address and decrypts the request. Even when the operators work independently,
      a name, cookie, or account identifier in the request can reveal who sent it.
      <a href="https://www.rfc-editor.org/rfc/rfc9458.html#section-6.1">RFC 9458 §6.1</a> explains how clients handle identifying state.
    </p>
  </section>`;
}

export function comparisonPanel(): string {
  return `
  <section class="panel" aria-labelledby="cmp-h">
    <h2 id="cmp-h">Where this sits: OHTTP vs VPN vs Tor vs IT-PIR</h2>
    <p class="panel-lede">Four ways to stop a server from knowing who asked. They differ in what is hidden,
    from whom, and — most importantly — in what you have to <em>assume</em> for the guarantee to hold.</p>
    <div class="cmp-wrap" role="region" aria-label="Comparison of privacy architectures" tabindex="0">
      <table class="cmp">
        <caption class="note" style="text-align:left;padding:0 0 .4rem">Trust assumptions compared — the row that decides everything is what you must assume.</caption>
        <thead>
          <tr>
            <th scope="col">Property</th>
            <th scope="col">OHTTP (this lab)</th>
            <th scope="col">VPN / trusted proxy</th>
            <th scope="col">Tor (onion routing)</th>
            <th scope="col">IT-PIR (multi-server)</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <th scope="row">Who directly sees your network address</th>
            <td>the relay only</td>
            <td>the VPN operator</td>
            <td>the guard node only</td>
            <td>every server (identity is not hidden)</td>
          </tr>
          <tr>
            <th scope="row">Who sees your request</th>
            <td>the gateway + target only</td>
            <td>the destination (and the VPN, unless TLS inside)</td>
            <td>the destination; the exit can also read plain HTTP, while HTTPS protects the request contents</td>
            <td><strong>no server</strong> — each sees a query that is statistically independent of what you fetched</td>
          </tr>
          <tr class="this-row">
            <th scope="row">What you must assume</th>
            <td><strong>2 specific parties do not collude</strong> — an organizational promise</td>
            <td>1 party is fully honest (it sees both facts)</td>
            <td>observation of the entry and exit traffic cannot be combined to link the endpoints</td>
            <td>at least 1 of n servers is honest — <em>information-theoretic</em>, holds against unlimited computation</td>
          </tr>
          <tr>
            <th scope="row">If the assumption fails</th>
            <td>who + what join instantly (flip the switch above)</td>
            <td>the operator can associate the client with the destination; HTTPS still protects request contents</td>
            <td>traffic correlation reveals who talked to whom</td>
            <td>colluding all n servers reveals the query index</td>
          </tr>
          <tr>
            <th scope="row">Cost</th>
            <td>one relay hop; this suite adds 55 bytes to the binary request before padding (7-byte header, 32-byte encapsulated key, 16-byte tag)</td>
            <td>one extra hop</td>
            <td>3+ hops, high latency</td>
            <td>every server scans the whole database per query</td>
          </tr>
        </tbody>
      </table>
    </div>
    <p class="note">These systems protect different information. OHTTP separates the client address from the HTTP content
    across two operators. Tor routes a connection through several relays; <a href="https://support.torproject.org/tor-browser/features/secure-connections/">HTTPS</a>
    protects the content between the browser and the destination. The multi-server PIR example hides the selected record from each server.
    For the information-theoretic end of this spectrum, see
    <a href="${LABS.patronShield}">patron-shield</a> and <a href="${LABS.obliviousShelf}">oblivious-shelf</a>.</p>
  </section>`;
}

export function realWorldPanel(): string {
  return `
  <section class="panel" aria-labelledby="rw-h">
    <h2 id="rw-h">Where you already use this</h2>
    <p class="panel-lede">Named, not implemented here:</p>
    <div class="rw-grid">
      <div class="rw">
        <h3>Apple iCloud Private Relay</h3>
        <p>The same split-knowledge architecture — two independently operated hops, one seeing your IP and one
        seeing your destination — built on MASQUE proxying rather than OHTTP messages. Apple runs the first hop;
        a partner CDN runs the second.</p>
      </div>
      <div class="rw">
        <h3>Firefox telemetry &amp; suggestions</h3>
        <p>Mozilla ships OHTTP itself: telemetry reports and search suggestions travel as encapsulated requests
        through a relay run by a separate operator, so Mozilla's gateway sees the data but never the IP it came from.</p>
      </div>
      <div class="rw">
        <h3>Privacy Pass rate limiting</h3>
        <p>Rate-limited token issuance splits the issuer from a mediator: one party can count how often you ask,
        the other can see what you're asking for — neither can do both. OHTTP-style key configs and encapsulation
        carry the messages.</p>
      </div>
    </div>
  </section>`;
}

export function honestyPanel(): string {
  return `
  <section class="panel" aria-labelledby="honesty-h">
    <h2 id="honesty-h">Honest scoping — what this lab does and does not show</h2>
    <div class="honesty">
      <p><strong>Real:</strong> every cryptographic byte. HPKE (RFC 9180) runs the hub lab's implementation —
      DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-128-GCM / ChaCha20-Poly1305 — and this lab adds the genuine
      RFC 9458 encapsulation around it: key config, 7-byte header, <code>info</code> binding, and the exported-secret
      response schedule, all verified against the RFC 9458 Appendix A test vector. Requests are genuinely
      BHTTP-encoded (RFC 9292). The relay panel shows the actual ciphertext; the gateway panel shows the actual
      decryption.</p>
      <p><strong>Simulated:</strong> the network. All four parties live in this one browser tab; the IP addresses
      are documentation-range placeholders standing in for what TCP would reveal. No packet leaves this page.</p>
      <p><strong>What this does NOT prove:</strong> OHTTP does not hide message <em>timing or sizes</em> — the
      correlation exhibit above demonstrates the size half of that with real ciphertext lengths, and padding fixes
      only the size half; timing correlation needs batching or mixing that OHTTP does not provide. It does not
      protect you if the request <em>content</em> identifies you (a logged-in cookie defeats the whole scheme —
      RFC 9458 requires requests carry no identifying state). It does not hide that you use OHTTP at all. And the
      non-collusion assumption is organizational: nothing cryptographic prevents the join you can perform above.</p>
      <p><strong>Not production crypto — a teaching demo.</strong></p>
    </div>
    <h3>What this isn't (scope guard)</h3>
    <ul class="whatnot">
      <li>Not an HPKE lab — the envelope's internals (KEM, key schedule, AEAD) are taught at
        <a href="${LABS.hpkeEnvelope}">hpke-envelope</a>, whose module this lab consumes.</li>
      <li>Not a real network — no relay or gateway exists; the wire view is a labeled simulation.</li>
      <li>Not Tor or a mixnet — onion routing is named and compared above, never implemented.</li>
      <li>Not a Privacy Pass implementation — token issuance is named in the real-world panel only.</li>
      <li>Not a BHTTP conformance suite — the codec covers exactly the known-length messages this demo sends.</li>
    </ul>
  </section>`;
}
