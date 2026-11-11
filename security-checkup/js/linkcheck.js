// Link red-flag checker. It reads how a link is written; it never visits it.
// "No red flags found" therefore never means "safe".

const NON_WEB_SCHEME = /^(javascript|data|vbscript|file|blob|about):/i;
// Email, phone and text links are not web links, but they are not dangerous either.
const CONTACT_SCHEME = /^(mailto|tel|sms):/i;
const NUMBER = /^[\d.]+$/;
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
// Brand-owned domains that glue the brand to another word.
const KNOWN_BRAND_DOMAINS = new Set([
  'googleapis', 'googleusercontent', 'googlevideo', 'amazonaws', 'microsoftonline', 'paypalobjects',
]);
// Endings a brand's own site normally has. A brand name on any other ending
// (paypal.xyz) is treated as suspicious.
const USUAL_ENDINGS = new Set(['com', 'net', 'org', 'gov', 'me']);
// Free hosting services where anyone can publish under their own name.
const FREE_HOSTING = new Set([
  'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com', 'github.io', 'netlify.app', 'vercel.app',
  'herokuapp.com', 'blogspot.com', 'weebly.com', 'wixsite.com',
]);
const EMBEDDED_ENDINGS = new Set(['com', 'net', 'org']);
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
  'brand-mismatch': ['high', 'A well-known brand name appears in this link, but this is not an address that brand normally uses.'],
  'embedded-domain': ['high', 'Another site\'s name has been tucked in front of the real one. The real destination is the last part of the name.'],
  'brand-lookalike': ['medium', 'The site name has a well-known brand name inside a longer word. Check that it really belongs to that brand.'],
  'no-https': ['medium', 'This link is not encrypted (http, not https). Do not enter passwords or card details.'],
  'deep-subdomains': ['medium', 'The site name has many parts, which can hide where the link really goes.'],
  'executable': ['medium', 'This link downloads a program or installer. Only open it if you were expecting it.'],
  'local-address': ['low', 'This is an address on a private or home network, such as a router\'s settings page. Only continue if that is what you expect.'],
  'free-hosting': ['low', 'This site is on a free hosting service, where anyone can publish a page under any name.'],
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

// Splits a host into the name a site is registered under ("paypal" for
// www.paypal.co.uk), the labels in front of it, and facts about its ending.
function splitHost(labels) {
  const n = labels.length;
  const lastTwo = labels.slice(-2).join('.');
  const hosted = n >= 3 && FREE_HOSTING.has(lastTwo);
  const country = n >= 3 && labels[n - 1].length === 2 && COUNTRY_SECOND_LEVEL.has(labels[n - 2]);
  const endingLength = hosted || country ? 2 : 1;
  const tld = labels[n - 1];
  return {
    main: labels[n - endingLength - 1],
    subdomains: labels.slice(0, n - endingLength - 1),
    tld,
    hosted,
    usualEnding: !hosted && (country || tld.length === 2 || USUAL_ENDINGS.has(tld)),
  };
}

function isLocalAddress(host) {
  if (host.startsWith('[')) {
    const address = host.slice(1, -1).toLowerCase();
    return address === '::1' || /^f[cd]/.test(address) || /^fe[89ab]/.test(address);
  }
  const [a, b] = host.split('.').map(Number);
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31)
    || (a === 169 && b === 254);
}

export function analyzeUrl(input) {
  const text = String(input).trim();
  if (text === '' || CONTACT_SCHEME.test(text)) return NOT_A_LINK();
  if (NON_WEB_SCHEME.test(text)) return result(null, ['not-web']);
  if (/\s/.test(text)) return NOT_A_LINK();

  const hasScheme = HAS_SCHEME.test(text);
  if (!hasScheme && EMAIL_ADDRESS.test(text)) return NOT_A_LINK();
  // A bare number such as 3.14 or 2024 is not a link, though the URL parser
  // would read it as a numeric address. A full a.b.c.d address still is.
  if (!hasScheme && NUMBER.test(text) && text.split('.').length !== 4) return NOT_A_LINK();

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

  const isLocal = isIp && isLocalAddress(host);
  const ids = [];
  if (url.username !== '' || url.password !== '') ids.push('userinfo');
  if (isIp) ids.push(isLocal ? 'local-address' : 'ip-host');
  // Home routers and similar devices rarely offer https, so do not warn about it there.
  if (url.protocol === 'http:' && !isLocal) ids.push('no-https');
  if (EXECUTABLE.test(url.pathname.toLowerCase())) ids.push('executable');
  if (url.port !== '') ids.push('port');

  let hyphens = 0;
  if (!isIp) {
    const labels = host.split('.');
    const { main, subdomains, tld, hosted, usualEnding } = splitHost(labels);
    const named = [...subdomains, main];
    const pieces = named.flatMap((label) => label.split('-'));

    if (labels.some((label) => label.startsWith('xn--'))) ids.push('lookalike');

    // Brand checks. A few brands own their whole ending (safety.google); skip those.
    if (!BRANDS.has(tld)) {
      const ownSite = BRANDS.has(main) && usualEnding;
      const gluedOk = ownSite || KNOWN_BRAND_DOMAINS.has(main);
      if (!ownSite && pieces.some((piece) => BRANDS.has(piece))) {
        ids.push('brand-mismatch');
      } else if (!gluedOk && pieces.some((piece) => [...BRANDS].some((brand) =>
        brand.length >= 6 && piece !== brand && (piece.startsWith(brand) || piece.endsWith(brand))))) {
        ids.push('brand-lookalike');
      }
    }

    if (subdomains.some((label) => EMBEDDED_ENDINGS.has(label))) ids.push('embedded-domain');
    if (subdomains.length >= 3) ids.push('deep-subdomains');
    if (hosted) ids.push('free-hosting');
    if (SHORTENERS.has(host.replace(/^www\./, ''))) ids.push('shortener');
    if (main.split('-').some((piece) => PRESSURE_WORDS.has(piece))) ids.push('pressure-words');
    for (const label of labels) {
      if (!label.startsWith('xn--')) hyphens += label.split('-').length - 1;
    }
  }
  if (hyphens >= 3 || text.length > 200) ids.push('odd-shape');

  return result(host, ids);
}
