// The only module that touches the page. Everything it shows comes from the
// logic modules; user-supplied text is only ever written with textContent.

import { hasFeature } from './features.js';
import { loadState, saveState } from './storage.js';
import { estimateStrength } from './strength.js';
import { checkBreach } from './breach.js';
import { analyzeUrl } from './linkcheck.js';
import { randomPassword, passphrase, passwordEntropyBits, passphraseEntropyBits } from './generator.js';
import { CHECKLIST, toDateKey, taskForDate, checklistScore, toggleChecklistItem,
  isDoneToday, currentStreak, completeToday } from './checkup.js';

const $ = (id) => document.getElementById(id);

function replaceList(list, items) {
  list.replaceChildren(...items.map((text) => {
    const li = document.createElement('li');
    li.textContent = text;
    return li;
  }));
}

// ---------- Tabs ----------

const VIEWS = ['password', 'link', 'generator', 'checkup'];

function viewFromHash() {
  const name = location.hash.slice(1);
  return VIEWS.includes(name) ? name : VIEWS[0];
}

function showView(name, { focus = false } = {}) {
  for (const view of VIEWS) {
    const selected = view === name;
    const tab = $(`tab-${view}`);
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    $(`view-${view}`).hidden = !selected;
    if (selected && focus) tab.focus();
  }
  if (name === 'checkup') renderCheckup();
}

function goTo(name, options) {
  if (viewFromHash() !== name || location.hash === '') {
    history.replaceState(null, '', `#${name}`);
  }
  showView(name, options);
}

function setUpTabs() {
  VIEWS.forEach((view, index) => {
    const tab = $(`tab-${view}`);
    tab.addEventListener('click', () => goTo(view));
    tab.addEventListener('keydown', (event) => {
      const step = { ArrowRight: 1, ArrowLeft: -1 }[event.key];
      let target;
      if (step) target = VIEWS[(index + step + VIEWS.length) % VIEWS.length];
      else if (event.key === 'Home') target = VIEWS[0];
      else if (event.key === 'End') target = VIEWS[VIEWS.length - 1];
      if (!target) return;
      event.preventDefault();
      goTo(target, { focus: true });
    });
  });
  window.addEventListener('hashchange', () => showView(viewFromHash()));
  showView(viewFromHash());
}

// ---------- Password check ----------

const BREACH_LABEL = 'Check for breaches';
let breachRequest = 0; // lets a slow reply for an old password be ignored

function clearBreachResult() {
  breachRequest++;
  const result = $('breach-result');
  result.textContent = '';
  delete result.dataset.status;
  $('breach-button').textContent = BREACH_LABEL;
}

function renderStrength() {
  const password = $('password-input').value;
  const meter = $('strength-meter');
  const empty = password === '';

  clearBreachResult();
  $('breach-button').disabled = empty || !hasFeature('breach-lookup');
  $('strength-note').hidden = empty;

  if (empty) {
    delete meter.dataset.score;
    $('strength-label').textContent = '';
    replaceList($('strength-warnings'), []);
    replaceList($('strength-suggestions'), []);
    return;
  }
  const { score, label, warnings, suggestions } = estimateStrength(password);
  meter.dataset.score = String(score);
  $('strength-label').textContent = label;
  $('strength-label').dataset.score = String(score);
  replaceList($('strength-warnings'), warnings);
  replaceList($('strength-suggestions'), suggestions);
}

async function runBreachCheck() {
  const password = $('password-input').value;
  if (password === '' || !hasFeature('breach-lookup')) return;

  const button = $('breach-button');
  const result = $('breach-result');
  const request = ++breachRequest;
  button.disabled = true;
  button.textContent = 'Checking…';
  result.textContent = '';
  delete result.dataset.status;

  const outcome = await checkBreach(password, (url, init) => fetch(url, init));
  if (request !== breachRequest) return; // the password changed while we waited

  button.disabled = false;
  button.textContent = BREACH_LABEL;
  result.dataset.status = outcome.status;
  if (outcome.status === 'found') {
    const times = outcome.count === 1 ? 'once' : `${outcome.count.toLocaleString('en-US')} times`;
    result.textContent = `This password has appeared in known data breaches ${times}. Don't use it anywhere.`;
  } else if (outcome.status === 'clear') {
    result.textContent = "Not found in known breaches. That doesn't prove it's safe, only that it isn't on this list.";
  } else {
    result.textContent = "Couldn't check right now. Your strength result above is still valid.";
    button.textContent = 'Try again';
  }
}

function setUpPassword() {
  const input = $('password-input');
  input.addEventListener('input', renderStrength);
  $('breach-button').addEventListener('click', runBreachCheck);
  $('password-show').addEventListener('click', () => {
    const reveal = input.type === 'password';
    input.type = reveal ? 'text' : 'password';
    $('password-show').textContent = reveal ? 'Hide' : 'Show';
    $('password-show').setAttribute('aria-pressed', String(reveal));
  });
  renderStrength();
}

// ---------- Link check ----------

const VERDICT_LEVEL = {
  'Likely dangerous': 'danger',
  'Be careful': 'caution',
  'Minor concerns': 'minor',
  'No red flags found': 'neutral',
  'Not a link': 'invalid',
};

function runLinkCheck() {
  const text = $('link-input').value;
  const panel = $('link-result');
  if (text.trim() === '') {
    panel.hidden = true;
    return;
  }
  const { valid, host, flags, verdict } = analyzeUrl(text);
  panel.hidden = false;
  $('link-verdict').textContent = verdict;
  $('link-verdict').dataset.level = VERDICT_LEVEL[verdict];

  const hostLine = $('link-host');
  hostLine.hidden = host === null;
  if (host !== null) {
    const name = document.createElement('strong');
    name.textContent = host;
    hostLine.replaceChildren('This link goes to: ', name);
  }

  $('link-flags').replaceChildren(...flags.map((flag) => {
    const li = document.createElement('li');
    li.dataset.severity = flag.severity;
    li.textContent = flag.message;
    return li;
  }));

  $('link-note').textContent = valid
    ? 'This checks how the link is written, not what is on the site.'
    : "That doesn't look like a web link. Paste the full address, starting with https://";
}

function setUpLink() {
  $('link-button').addEventListener('click', runLinkCheck);
  $('link-input').addEventListener('keydown', (event) => {
    if (event.key === 'Enter') runLinkCheck();
  });
  // A verdict belongs to the exact text that was checked. Hide it as soon as
  // the text changes, so an old verdict is never read against a new link.
  $('link-input').addEventListener('input', () => {
    $('link-result').hidden = true;
  });
}

// ---------- Generator ----------

const randomValues = (array) => crypto.getRandomValues(array);

function generatorSettings() {
  if ($('gen-mode-passphrase').checked) {
    return {
      mode: 'passphrase',
      words: Number($('gen-words').value),
      separator: $('gen-separator').value,
      capitalize: $('gen-capitalize').checked,
      addNumber: $('gen-number').checked,
    };
  }
  return {
    mode: 'password',
    length: Number($('gen-length').value),
    upper: $('gen-upper').checked,
    lower: $('gen-lower').checked,
    digits: $('gen-digits').checked,
    symbols: $('gen-symbols').checked,
  };
}

function renderGeneratorOptions() {
  const settings = generatorSettings();
  const isPassphrase = settings.mode === 'passphrase';
  $('gen-password-options').hidden = isPassphrase;
  $('gen-passphrase-options').hidden = !isPassphrase;
  $('gen-length-value').textContent = $('gen-length').value;
  $('gen-words-value').textContent = $('gen-words').value;

  const noClass = !isPassphrase && !(settings.upper || settings.lower || settings.digits || settings.symbols);
  $('gen-button').disabled = noClass;
  $('gen-message').textContent = noClass ? 'Choose at least one kind of character.' : '';

  const bits = isPassphrase ? passphraseEntropyBits(settings) : passwordEntropyBits(settings);
  $('gen-entropy').textContent = noClass
    ? ''
    : `About ${Math.floor(bits)} bits of randomness. Higher is harder to guess.`;
  return { settings, noClass };
}

function generate() {
  const { settings, noClass } = renderGeneratorOptions();
  if (noClass) return;
  $('gen-output').value = settings.mode === 'passphrase'
    ? passphrase(settings, randomValues)
    : randomPassword(settings, randomValues);
  $('gen-copy').disabled = false;
}

function onGeneratorOptionChange() {
  const { noClass } = renderGeneratorOptions();
  // Keep what is shown in step with the settings, once something has been generated.
  if (!noClass && $('gen-output').value !== '') generate();
}

async function copyGenerated() {
  const value = $('gen-output').value;
  if (value === '') return;
  try {
    await navigator.clipboard.writeText(value);
    $('gen-message').textContent = 'Copied.';
  } catch {
    $('gen-output').select();
    $('gen-message').textContent = "Couldn't copy automatically. Select the text and copy it yourself.";
  }
}

function setUpGenerator() {
  for (const id of ['gen-mode-password', 'gen-mode-passphrase', 'gen-upper', 'gen-lower', 'gen-digits',
    'gen-symbols', 'gen-separator', 'gen-capitalize', 'gen-number']) {
    $(id).addEventListener('change', onGeneratorOptionChange);
  }
  for (const id of ['gen-length', 'gen-words']) $(id).addEventListener('input', onGeneratorOptionChange);
  $('gen-button').addEventListener('click', generate);
  $('gen-copy').addEventListener('click', copyGenerated);
  renderGeneratorOptions();
}

// ---------- Daily checkup ----------

function safeLocalStorage() {
  try {
    return window.localStorage;
  } catch {
    return null;
  }
}

const storage = safeLocalStorage();
let { state, persistent } = loadState(storage);

function commit(nextState) {
  state = nextState;
  if (!saveState(storage, state)) persistent = false;
  renderCheckup();
}

function renderCheckup() {
  const today = toDateKey(new Date());
  const done = isDoneToday(state, today);
  const streak = currentStreak(state, today);

  $('daily-task').textContent = taskForDate(today).text;
  $('daily-done').disabled = done;
  $('daily-done').textContent = done ? 'Done for today' : 'Mark as done';
  $('streak-current').textContent = String(streak);
  $('streak-unit').textContent = streak === 1 ? 'day' : 'days';
  $('streak-best').textContent = String(state.bestStreak);

  const score = checklistScore(state.checklist);
  $('score-value').textContent = String(score);
  $('score-bar').value = score;
  for (const box of $('checklist').querySelectorAll('input[type=checkbox]')) {
    box.checked = state.checklist[box.dataset.id] === true;
  }

  const notice = $('storage-notice');
  notice.hidden = persistent;
  notice.textContent = persistent
    ? ''
    : "Your browser is blocking saved data, so progress won't be kept after you close this page.";
}

function setUpCheckup() {
  $('checklist').replaceChildren(...CHECKLIST.map((item) => {
    const li = document.createElement('li');
    const label = document.createElement('label');
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.dataset.id = item.id;
    const text = document.createElement('span');
    const title = document.createElement('span');
    title.className = 'item-title';
    title.textContent = item.title;
    const why = document.createElement('span');
    why.className = 'item-why';
    why.textContent = item.why;
    text.append(title, why);
    label.append(box, text);
    li.append(label);
    return li;
  }));

  $('checklist').addEventListener('change', (event) => {
    const box = event.target;
    if (!(box instanceof HTMLInputElement) || !box.dataset.id) return;
    commit(toggleChecklistItem(state, box.dataset.id, box.checked));
  });
  $('daily-done').addEventListener('click', () => commit(completeToday(state, toDateKey(new Date()))));
  // A tab left open overnight should show the new day's task when it is looked at again.
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) renderCheckup();
  });
  renderCheckup();
}

// ---------- Start ----------

setUpCheckup();
setUpPassword();
setUpLink();
setUpGenerator();
setUpTabs();

// Offline support. If registration fails the app still works online.
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  });
}
