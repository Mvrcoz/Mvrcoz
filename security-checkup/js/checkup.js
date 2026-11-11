// Daily checkup: a lasting-habits checklist, one small task per day, and a
// streak. Every function is pure: state and a date key in, a value or a new
// state out. Date keys are local calendar dates written as YYYY-MM-DD.

export const CHECKLIST = Object.freeze([
  { id: 'mfa-email', title: 'Two-step sign-in is on for my main email',
    why: 'Your email can reset almost every other password, so it deserves the strongest lock.' },
  { id: 'mfa-bank', title: 'Two-step sign-in is on for banking and payments',
    why: 'A second step stops someone who has only your password.' },
  { id: 'password-manager', title: 'I use a password manager',
    why: 'It remembers long, different passwords so you do not have to.' },
  { id: 'unique-passwords', title: 'My important accounts each have their own password',
    why: 'If one site is breached, a reused password opens your other accounts too.' },
  { id: 'auto-updates', title: 'Automatic updates are on for my phone and computer',
    why: 'Updates fix security holes that attackers already know about.' },
  { id: 'screen-lock', title: 'My devices lock with a PIN, password, or biometrics',
    why: 'A lock protects everything on the device if it is lost or stolen.' },
  { id: 'backups', title: 'My important files and photos are backed up',
    why: 'A backup turns theft, loss, or ransomware into an inconvenience.' },
  { id: 'find-my-device', title: 'Find-my-device is switched on',
    why: 'It lets you locate, lock, or erase a missing phone or laptop.' },
  { id: 'recovery-info', title: 'My account recovery phone and email are up to date',
    why: 'Out-of-date recovery details can lock you out, or let someone else in.' },
  { id: 'browser-updated', title: 'My web browser is up to date',
    why: 'The browser is the program most exposed to the internet.' },
  { id: 'router-password', title: 'My home Wi-Fi router no longer uses its default admin password',
    why: 'Default router passwords are public knowledge.' },
  { id: 'breach-alerts', title: 'I am signed up for breach alerts for my email address',
    why: 'You find out quickly when an account of yours is exposed, and can change that password.' },
]);

const TASK_TEXT = [
  'Review which apps can see your location, and switch off any that do not need it.',
  'Check your email account\'s list of signed-in devices and sign out any you do not recognise.',
  'Check for updates on your phone and install any that are waiting.',
  'Check for updates on your computer and install any that are waiting.',
  'Delete one app you no longer use.',
  'Pick one important account and turn on two-step sign-in.',
  'Change one password that you know you have used on more than one site.',
  'Look through your browser extensions and remove any you do not use or recognise.',
  'Check that your screen locks by itself after a few minutes or less.',
  'Confirm your most recent backup actually finished, and note the date.',
  'Review which apps can use your camera and microphone.',
  'Check the forwarding rules in your email settings for anything you did not set up.',
  'Review the apps and services connected to your main email account and remove old ones.',
  'Check the privacy settings on one social media account.',
  'Confirm the recovery phone number and email on your main email account are current.',
  'Close one online account you no longer use.',
  'Look at your recent bank or card transactions for anything you do not recognise.',
  'Save your backup codes for two-step sign-in somewhere safe and offline.',
  'Restart your phone and your computer so pending updates can finish.',
  'Update your web browser, then restart it.',
  'Check which devices are connected to your home Wi-Fi.',
  'Make sure your home Wi-Fi password is long and not the one printed on the router.',
  'Turn off Bluetooth on one device where you are not using it.',
  'Review which apps are allowed to show notifications on your lock screen.',
  'Check which contacts or apps can see your photos.',
  'Unsubscribe from one mailing list you never read, using the sender\'s own website.',
  'Practise spotting the real sender: open a recent email and look at the full address, not just the name.',
  'Tell one family member or friend about two-step sign-in.',
  'Check that find-my-device is switched on for your phone.',
  'Remove saved payment cards from one shopping site you rarely use.',
];

export const DAILY_TASKS = Object.freeze(
  TASK_TEXT.map((text, i) => ({ id: `task-${String(i + 1).padStart(2, '0')}`, text })),
);

const CHECKLIST_IDS = new Set(CHECKLIST.map((item) => item.id));
const MS_PER_DAY = 86_400_000;
const pad = (n) => String(n).padStart(2, '0');

// Day number of a date key. Uses UTC arithmetic on the calendar date itself,
// so daylight-saving changes cannot shift a day.
function dayNumber(key) {
  const [year, month, day] = key.split('-').map(Number);
  return Math.round(Date.UTC(year, month - 1, day) / MS_PER_DAY);
}

export function toDateKey(date) {
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

export function previousDateKey(key) {
  const d = new Date((dayNumber(key) - 1) * MS_PER_DAY);
  return `${d.getUTCFullYear()}-${pad(d.getUTCMonth() + 1)}-${pad(d.getUTCDate())}`;
}

export function taskForDate(key) {
  const n = DAILY_TASKS.length;
  return DAILY_TASKS[((dayNumber(key) % n) + n) % n];
}

export function checklistScore(checklist) {
  const done = Object.keys(checklist).filter((id) => CHECKLIST_IDS.has(id) && checklist[id] === true).length;
  return Math.round((done / CHECKLIST.length) * 100);
}

export function toggleChecklistItem(state, id, done) {
  if (!CHECKLIST_IDS.has(id)) return state;
  const checklist = { ...state.checklist };
  if (done) checklist[id] = true;
  else delete checklist[id];
  return { ...state, checklist };
}

export function isDoneToday(state, todayKey) {
  return state.lastDoneDate === todayKey;
}

// The streak to show. It is still alive if the last task was done today or
// yesterday; after a missed day it shows 0.
export function currentStreak(state, todayKey) {
  const alive = state.lastDoneDate === todayKey || state.lastDoneDate === previousDateKey(todayKey);
  return alive ? state.streak : 0;
}

export function completeToday(state, todayKey) {
  if (state.lastDoneDate === todayKey) return state;
  const streak = state.lastDoneDate === previousDateKey(todayKey) ? state.streak + 1 : 1;
  return { ...state, lastDoneDate: todayKey, streak, bestStreak: Math.max(state.bestStreak, streak) };
}
