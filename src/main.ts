import './styles.css';
import { generateKeyPair } from '@hub/hpke/dhkem';
import { AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305, type AeadId } from '@hub/hpke/consts';
import { runExchange, type Exchange } from './relay/exchange';
import { byId } from './ui/dom';
import { pipelinePanel, renderParties, renderStepStatus, STEPS } from './ui/pipeline';
import { collusionPanel, renderCollusion } from './ui/collusion';
import { attackLeakedKey, attackTamper, attackWrongKey, breakItPanel } from './ui/breakit';
import { renderSchedules, schedulePanel } from './ui/schedule';
import { comparisonPanel, honestyPanel, introPanel, realWorldPanel } from './ui/statics';

// One gateway key pair per session (as deployed gateways rotate slowly);
// every request still gets a fresh ephemeral client key inside HPKE.
const gatewayKeys = generateKeyPair();

interface State {
  exchange: Exchange | null;
  step: number;
  colluding: boolean;
}

const state: State = { exchange: null, step: 0, colluding: false };

byId('lab-main').innerHTML =
  introPanel() +
  pipelinePanel() +
  collusionPanel() +
  breakItPanel() +
  schedulePanel() +
  comparisonPanel() +
  realWorldPanel() +
  honestyPanel();

const runBtn = byId<HTMLButtonElement>('run-btn');
const backBtn = byId<HTMLButtonElement>('back-btn');
const nextBtn = byId<HTMLButtonElement>('next-btn');
const allBtn = byId<HTMLButtonElement>('all-btn');
const stepStatus = byId('step-status');
const wireChip = byId('wire-chip');
const parties = byId('parties');
const colludeSwitch = byId<HTMLButtonElement>('collude-switch');
const colludeHint = byId('collude-hint');
const colludeOut = byId('collude-out');
const attackOut = byId('attack-out');
const schedOut = byId('sched-out');
const attackButtons = [
  byId<HTMLButtonElement>('attack-wrongkey'),
  byId<HTMLButtonElement>('attack-tamper'),
  byId<HTMLButtonElement>('attack-leak'),
];

function paint(): void {
  renderParties(parties, state.exchange, state.step);
  if (!state.exchange) return;
  stepStatus.innerHTML = renderStepStatus(state.step);
  const def = STEPS[state.step];
  wireChip.hidden = false;
  wireChip.textContent = def.chip;
  wireChip.style.left = `${def.at * 25 + 12.5}%`;
  backBtn.disabled = state.step === 0;
  nextBtn.disabled = state.step === STEPS.length - 1;
  allBtn.disabled = state.step === STEPS.length - 1;
  renderCollusion(colludeOut, state.exchange, state.colluding);
  renderSchedules(schedOut, state.exchange);
}

async function run(): Promise<void> {
  const query = byId<HTMLInputElement>('query-input').value.trim() || 'chest pain symptoms';
  const aeadId: AeadId =
    byId<HTMLSelectElement>('aead-select').value === '3' ? AEAD_CHACHA20_POLY1305 : AEAD_AES_128_GCM;
  runBtn.disabled = true;
  try {
    state.exchange = await runExchange(
      {
        method: 'GET',
        authority: 'api.example.com',
        path: `/search?q=${encodeURIComponent(query).replace(/%20/g, '+')}`,
        headers: [],
        content: new Uint8Array(0),
        aeadId,
      },
      { gatewayKeys },
    );
  } finally {
    runBtn.disabled = false;
  }
  state.step = 0;
  state.colluding = false;
  colludeSwitch.disabled = false;
  colludeSwitch.setAttribute('aria-checked', 'false');
  colludeHint.textContent = 'The join is instant — and reversible only in the sense that they promise to forget.';
  attackButtons.forEach((b) => (b.disabled = false));
  attackOut.innerHTML = '';
  paint();
}

runBtn.addEventListener('click', () => void run());
backBtn.addEventListener('click', () => {
  state.step = Math.max(0, state.step - 1);
  paint();
});
nextBtn.addEventListener('click', () => {
  state.step = Math.min(STEPS.length - 1, state.step + 1);
  paint();
});
allBtn.addEventListener('click', () => {
  state.step = STEPS.length - 1;
  paint();
});

colludeSwitch.addEventListener('click', () => {
  if (!state.exchange) return;
  state.colluding = !state.colluding;
  colludeSwitch.setAttribute('aria-checked', String(state.colluding));
  renderCollusion(colludeOut, state.exchange, state.colluding);
});

attackButtons[0].addEventListener('click', () => {
  if (state.exchange) void attackWrongKey(attackOut, state.exchange);
});
attackButtons[1].addEventListener('click', () => {
  if (state.exchange) void attackTamper(attackOut, state.exchange);
});
attackButtons[2].addEventListener('click', () => {
  if (state.exchange) void attackLeakedKey(attackOut, state.exchange);
});

// Initial paint: empty party cards with role notes, before any exchange runs.
paint();
