import './styles.css';
import { generateKeyPair } from '@hub/hpke/dhkem';
import { AEAD_AES_128_GCM, AEAD_CHACHA20_POLY1305, type AeadId } from '@hub/hpke/consts';
import { runExchange, type Exchange } from './relay/exchange';
import { byId } from './ui/dom';
import { pipelinePanel, renderParties, renderStepStatus, STEPS } from './ui/pipeline';
import { collusionPanel, renderCollusion } from './ui/collusion';
import { correlationPanel, wireCorrelation } from './ui/correlation';
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
  correlationPanel() +
  breakItPanel() +
  schedulePanel() +
  comparisonPanel() +
  realWorldPanel() +
  honestyPanel();

const runBtn = byId<HTMLButtonElement>('run-btn');
const playBtn = byId<HTMLButtonElement>('play-btn');
const backBtn = byId<HTMLButtonElement>('back-btn');
const nextBtn = byId<HTMLButtonElement>('next-btn');
const allBtn = byId<HTMLButtonElement>('all-btn');
const stepStatus = byId('step-status');
const wireChip = byId('wire-chip');
const parties = byId('parties');
const colludeSwitch = byId<HTMLButtonElement>('collude-switch');
const colludeHint = byId('collude-hint');
const colludeOut = byId('collude-out');
let attackOut = byId('attack-out');
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

let exchangeVersion = 0;
const emptyStatus = stepStatus.textContent;
const emptySchedule = schedOut.textContent;

function clearExchange(): void {
  exchangeVersion += 1;
  stopPlay();
  state.exchange = null;
  state.step = 0;
  state.colluding = false;
  for (const button of [backBtn, nextBtn, playBtn, allBtn, colludeSwitch, ...attackButtons]) button.disabled = true;
  runBtn.disabled = false;
  colludeSwitch.setAttribute('aria-checked', 'false');
  colludeHint.textContent = 'Run an exchange first.';
  stepStatus.textContent = emptyStatus;
  schedOut.textContent = emptySchedule;
  wireChip.hidden = true;
  colludeOut.replaceChildren();
  // An earlier asynchronous check may still write to its old result element.
  const freshOutput = attackOut.cloneNode(false) as HTMLElement;
  attackOut.replaceWith(freshOutput);
  attackOut = freshOutput;
  paint();
}

async function run(): Promise<void> {
  clearExchange();
  const version = exchangeVersion;
  const query = byId<HTMLInputElement>('query-input').value;
  const method = byId<HTMLSelectElement>('method-select').value === 'POST' ? 'POST' : 'GET';
  const aeadId: AeadId =
    byId<HTMLSelectElement>('aead-select').value === '3' ? AEAD_CHACHA20_POLY1305 : AEAD_AES_128_GCM;
  runBtn.disabled = true;
  try {
    const exchange = await runExchange(
      method === 'GET'
        ? {
            method,
            authority: 'api.example.com',
            path: `/search?q=${encodeURIComponent(query).replace(/%20/g, '+')}`,
            headers: [],
            content: new Uint8Array(0),
            aeadId,
          }
        : {
            method,
            authority: 'api.example.com',
            path: '/v1/submit',
            headers: [['content-type', 'application/json']],
            content: new TextEncoder().encode(JSON.stringify({ note: query })),
            aeadId,
          },
      { gatewayKeys },
    );
    if (version !== exchangeVersion) return;
    state.exchange = exchange;
  } catch {
    if (version === exchangeVersion) stepStatus.textContent = 'Exchange failed. Run the exchange to try again.';
    return;
  } finally {
    if (version === exchangeVersion) runBtn.disabled = false;
  }
  playBtn.disabled = false;
  state.step = 0;
  state.colluding = false;
  colludeSwitch.disabled = false;
  colludeSwitch.setAttribute('aria-checked', 'false');
  colludeHint.textContent = 'The join is instant — and reversible only in the sense that they promise to forget.';
  attackButtons.forEach((b) => (b.disabled = false));
  attackOut.innerHTML = '';
  paint();
}

// Auto-play: advances one step at a time so the chip visibly travels the
// wire. Any manual navigation stops it; motion is CSS-gated behind
// prefers-reduced-motion, so reduced-motion users get discrete updates.
let playTimer: number | null = null;
function stopPlay(): void {
  if (playTimer !== null) {
    window.clearInterval(playTimer);
    playTimer = null;
  }
  playBtn.textContent = '▶ Play all steps';
}
playBtn.addEventListener('click', () => {
  if (!state.exchange) return;
  if (playTimer !== null) {
    stopPlay();
    return;
  }
  if (state.step >= STEPS.length - 1) state.step = 0;
  paint();
  playBtn.textContent = '⏸ Pause';
  playTimer = window.setInterval(() => {
    if (state.step >= STEPS.length - 1) {
      stopPlay();
      return;
    }
    state.step += 1;
    paint();
  }, 1600);
});

byId('query-input').addEventListener('input', clearExchange);
byId('method-select').addEventListener('change', clearExchange);
byId('aead-select').addEventListener('change', clearExchange);
runBtn.addEventListener('click', () => void run());
backBtn.addEventListener('click', () => {
  stopPlay();
  state.step = Math.max(0, state.step - 1);
  paint();
});
nextBtn.addEventListener('click', () => {
  stopPlay();
  state.step = Math.min(STEPS.length - 1, state.step + 1);
  paint();
});
allBtn.addEventListener('click', () => {
  stopPlay();
  state.step = STEPS.length - 1;
  paint();
});

wireCorrelation(gatewayKeys);

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
