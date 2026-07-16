/** Sibling labs this demo links out to instead of rebuilding (scope guard). */
const gh = (repo: string) => `https://systemslibrarian.github.io/${repo}/`;

export const LABS = {
  catalog: 'https://crypto-lab.systemslibrarian.dev/',
  hpkeEnvelope: gh('crypto-lab-hpke-envelope'),
  patronShield: gh('crypto-lab-patron-shield'),
  obliviousShelf: gh('crypto-lab-oblivious-shelf'),
  blindHello: gh('crypto-lab-blind-hello'),
} as const;
