// Link red-flag checker. It reads how a link is written; it never visits it.
// "No red flags found" therefore never means "safe".

const NON_WEB_SCHEME = /^(javascript|data|vbscript|file|blob|about|mailto|tel|sms):/i;
const HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
const EMAIL_ADDRESS = /^[^\s@/:]+@[^\s@/:]+$/;
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;

const BRANDS = new Set([
  'paypal', 'apple', 'google', 'microsoft', 'amazon', 'netflix', 'facebook', 'instagram',
  'whatsapp', 'chase', 'wellsfargo', 'bankofamerica', 'usps', 'fedex', 'ups', 'dhl', 'irs',
  'coinbase', 'binance',
]);
// Second-level labels that, before a two-letter country code, form a suffix
// such as co.uk or com.au. A short stand-in for the full public suffix list.
const COUNTRY_SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'ac', 'edu']);
const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly',
  'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy',
]);
const PRESSURE_WORDS = new Set(['login', 'signin', 'verify', 'secure', 'account', 'update']);
const EXECUTABLE = /\.(exe|scr|msi|apk|bat|cmd|vbs|jar)$/;

const FLAGS = {
  'not-web': ['high', 'This is not a normal web link. Links like this can run code or open files on your device.'],
  'userinfo': ['high', 'The real destination is the part after the @ sign, not the name shown before it.'],
  'ip-host': ['high', 'This goes to a numeric address, not a named website. Genuine services rarely send links like this.'],
  'lookalike': ['high', 'The site name uses special characters that can imitate ordinary letters.'],
  'brand-mismatch': ['high', 'A well-known brand name appears in this link, but the site it leads to does not belong to that brand.'],
  'no-https': ['medium', 'This link is not encrypted (http, not https). Do not enter passwords or card details.'],
  'deep-subdomains': ['medium', 'The site name has many parts, which can hide where the link really goes.'],
  'executable': ['medium', 'This link downloads a program or installer. Only open it if you were expecting it.'],
  'shortener': ['low', 'This is a shortened link, so its real destination is hidden.'],
  'port': ['low', 'This link uses an unusual port number.'],
  'pressure-words': ['low', 'The site name uses words like "login" or "verify", a common trick to look official.'],
  'odd-shape': ['low', 'The link is unusually long or full of hyphens.'],
};
const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

const NOT_A_LINK = () => ({ valid: false, host: null, flags: [], verdict: 'Not a link' });

function verdictFor(flags) {
  if (flags.some((f) => f.severity === 'high')) return 'Likely dangerous';
  if (flags.some((f) => f.severity === 'medium')) return 'Be careful';
  if (flags.length > 0) return 'Minor concerns';
  return 'No red flags found';
}

function result(host, ids) {
  const flags = ids
    .map((id) => ({ id, severity: FLAGS[id][0], message: FLAGS[id][1] }))
    .sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return { valid: true, host, flags, verdict: verdictFor(flags) };
}

// The label a site is registered under: "paypal" for www.paypal.co.uk.
function mainName(labels) {
  const n = labels.length;
  const countrySuffix = n >= 3 && labels[n - 1].length === 2 && COUNTRY_SECOND_LEVEL.has(labels[n - 2]);
  return labels[countrySuffix ? n - 3 : n - 2];
}

export function analyzeUrl(input) {
  const text = String(input).trim();
  if (text === '') return NOT_A_LINK();
  if (NON_WEB_SCHEME.test(text)) return result(null, ['not-web']);
  if (/\s/.test(text)) return NOT_A_LINK();

  const hasScheme = HAS_SCHEME.test(text);
  if (!hasScheme && EMAIL_ADDRESS.test(text)) return NOT_A_LINK();

  let url;
  try {
    url = new URL(hasScheme ? text : `https://${text}`);
  } catch {
    return NOT_A_LINK();
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return result(null, ['not-web']);

  const host = url.hostname.replace(/\.$/, '');
  const isIp = host.startsWith('[') || IPV4.test(host);
  if (!isIp && !host.includes('.')) return NOT_A_LINK();

  const ids = [];
  if (url.username !== '' || url.password !== '') ids.push('userinfo');
  if (isIp) ids.push('ip-host');
  if (url.protocol === 'http:') ids.push('no-https');
  if (EXECUTABLE.test(url.pathname.toLowerCase())) ids.push('executable');
  if (url.port !== '') ids.push('port');

  let hyphens = 0;
  if (!isIp) {
    const labels = host.split('.');
    const main = mainName(labels);
    const pieces = labels.flatMap((label) => label.split('-'));

    if (labels.some((label) => label.startsWith('xn--'))) ids.push('lookalike');
    if (!BRANDS.has(main) && pieces.some((piece) => BRANDS.has(piece))) ids.push('brand-mismatch');
    if (labels.length >= 5) ids.push('deep-subdomains');
    if (SHORTENERS.has(host.replace(/^www\./, ''))) ids.push('shortener');
    if (main.split('-').some((piece) => PRESSURE_WORDS.has(piece))) ids.push('pressure-words');
    for (const label of labels) {
      if (!label.startsWith('xn--')) hyphens += label.split('-').length - 1;
    }
  }
  if (hyphens >= 3 || text.length > 200) ids.push('odd-shape');

  return result(host, ids);
}
