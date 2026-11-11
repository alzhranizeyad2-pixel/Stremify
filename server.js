'use strict';
const http = require('http');
const https = require('https');
const zlib = require('zlib');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dns = require('dns');
const net = require('net');

const VERSION = require('./package.json').version;
const PORT = process.env.PORT || 3000;
const WEB = path.join(__dirname, 'public');
const UA = 'Stremify/' + VERSION;
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_SOURCES === '1';
const SUBS_PROVIDER = (process.env.SUBS_PROVIDER || 'https://opensubtitles-v3.strem.io').replace(/\/+$/, '');
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_SOURCES = 8;
// Requests per minute per client IP on /stream and /subtitles (0 = unlimited).
const RATE_LIMIT = process.env.RATE_LIMIT !== undefined ? Math.max(0, +process.env.RATE_LIMIT || 0) : 120;
// Set TRUST_PROXY=1 when running behind a reverse proxy (Render, Railway, nginx...) so the real client IP is used.
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
// The debrid key is only ever sent to these hosts (add your own Torrentio mirror via TORRENTIO_HOSTS=a.com,b.com).
const TORRENTIO_HOSTS = new Set(['torrentio.strem.fun']
  .concat(String(process.env.TORRENTIO_HOSTS || '').split(',').map((x) => x.trim().toLowerCase()).filter(Boolean)));

/* ------------------------------------------------------------------ */
/* Languages                                                           */
/* ------------------------------------------------------------------ */

// c=code, n=name, f=flags, w=full/native names (trusted anywhere in a release name),
// t=3-letter codes, two=extra 2-letter codes, st=single-token "subs in X" tags, at=audio tags
const LANG_DEFS = [
  { c: 'en', n: 'English',    f: ['🇬🇧', '🇺🇸'], w: ['english', 'eng', 'inglese', 'ingles', 'inglés', 'английский'], st: ['esub', 'esubs'] },
  { c: 'ar', n: 'Arabic',     f: ['🇸🇦', '🇦🇪', '🇪🇬'], w: ['arabic', 'ara', 'arab', 'arabe', 'arabo', 'عربي', 'عربى', 'عربية', 'عربيه', 'العربية', 'العربيه', 'арабский'] },
  { c: 'de', n: 'German',     f: ['🇩🇪'], w: ['german', 'ger', 'deu', 'deutsch', 'allemand', 'tedesco', 'немецкий'] },
  { c: 'fr', n: 'French',     f: ['🇫🇷'], w: ['french', 'fre', 'fra', 'francais', 'français', 'truefrench', 'francese', 'французский'],
    st: ['vostfr', 'stfr', 'subfrench', 'vost'], at: ['vf', 'vff', 'vfq', 'vfi', 'vf2'] },
  { c: 'es', n: 'Spanish',    f: ['🇪🇸', '🇲🇽'], w: ['spanish', 'spa', 'esp', 'espanol', 'español', 'castellano', 'latino', 'spagnolo', 'испанский'], st: ['vose'] },
  { c: 'tr', n: 'Turkish',    f: ['🇹🇷'], w: ['turkish', 'tur', 'türkçe', 'turkce', 'turco', 'турецкий'] },
  { c: 'hi', n: 'Hindi',      f: ['🇮🇳'], w: ['hindi', 'hin', 'हिन्दी', 'हिंदी'] },
  { c: 'ja', n: 'Japanese',   f: ['🇯🇵'], w: ['japanese', 'jpn', 'jap', '日本語', 'giapponese', 'японский'], two: ['jp'] },
  { c: 'pt', n: 'Portuguese', f: ['🇵🇹', '🇧🇷'], w: ['portuguese', 'portugues', 'português', 'brazilian', 'ptbr', 'portugues-br', 'português-br', 'portoghese', 'португальский'],
    t: ['por', 'pob'], two: ['pb'], st: ['legendado', 'legendas'], at: ['dublado'] },
  { c: 'it', n: 'Italian',    f: ['🇮🇹'], w: ['italian', 'italiano', 'italien', 'итальянский'], t: ['ita'], st: ['subita', 'vostit', 'sottotitolato'] },
  { c: 'ru', n: 'Russian',    f: ['🇷🇺'], w: ['russian', 'russkiy', 'русский', 'русские', 'русская', 'russo'], t: ['rus'], st: ['rusub'] },
  { c: 'zh', n: 'Chinese',    f: ['🇨🇳', '🇹🇼', '🇭🇰'], w: ['chinese', 'mandarin', 'cantonese', 'chs', 'cht', '中文', '简体', '簡體', '繁體', '繁体', 'cinese', 'китайский'],
    t: ['chi', 'zho', 'cmn', 'yue'], two: ['zh-hans', 'zh-hant'], st: ['chssub', 'chtsub'] },
  { c: 'ko', n: 'Korean',     f: ['🇰🇷'], w: ['korean', '한국어', 'coreano', 'корейский'], t: ['kor'] },
  { c: 'nl', n: 'Dutch',      f: ['🇳🇱', '🇧🇪'], w: ['dutch', 'nederlands', 'olandese', 'нидерландский', 'flemish'], t: ['dut', 'nld'] },
  { c: 'pl', n: 'Polish',     f: ['🇵🇱'], w: ['polish', 'polski', 'polacco', 'польский'], t: ['pol'], st: ['napisy'] },
  { c: 'sv', n: 'Swedish',    f: ['🇸🇪'], w: ['swedish', 'svenska', 'svedese'], t: ['swe'] },
  { c: 'da', n: 'Danish',     f: ['🇩🇰'], w: ['danish', 'dansk'], t: ['dan'] },
  { c: 'no', n: 'Norwegian',  f: ['🇳🇴'], w: ['norwegian', 'norsk', 'norvegese'], t: ['nor', 'nob', 'nno'], two: ['nb', 'nn'] },
  { c: 'fi', n: 'Finnish',    f: ['🇫🇮'], w: ['finnish', 'suomi'], t: ['fin'] },
  { c: 'el', n: 'Greek',      f: ['🇬🇷'], w: ['greek', 'ελληνικά', 'greco'], t: ['gre', 'ell'] },
  { c: 'he', n: 'Hebrew',     f: ['🇮🇱'], w: ['hebrew', 'עברית', 'ebraico'], t: ['heb'], two: ['iw'] },
  { c: 'fa', n: 'Persian',    f: ['🇮🇷'], w: ['persian', 'farsi', 'فارسی', 'فارسي', 'персидский'], t: ['per', 'fas'] },
  { c: 'ur', n: 'Urdu',       f: ['🇵🇰'], w: ['urdu', 'اردو'], t: ['urd'] },
  { c: 'bn', n: 'Bengali',    f: ['🇧🇩'], w: ['bengali', 'bangla', 'বাংলা'], t: ['ben'] },
  { c: 'ta', n: 'Tamil',      f: ['🇮🇳'], w: ['tamil', 'தமிழ்'], t: ['tam'] },
  { c: 'te', n: 'Telugu',     f: ['🇮🇳'], w: ['telugu', 'తెలుగు'], t: ['tel'] },
  { c: 'ml', n: 'Malayalam',  f: ['🇮🇳'], w: ['malayalam', 'മലയാളം'], t: ['mal'] },
  { c: 'id', n: 'Indonesian', f: ['🇮🇩'], w: ['indonesian', 'indonesia', 'bahasa'], t: ['ind'], two: ['in'] },
  { c: 'ms', n: 'Malay',      f: ['🇲🇾'], w: ['malay', 'melayu'], t: ['may', 'msa'] },
  { c: 'th', n: 'Thai',       f: ['🇹🇭'], w: ['thai', 'ไทย'], t: ['tha'] },
  { c: 'vi', n: 'Vietnamese', f: ['🇻🇳'], w: ['vietnamese', 'tiếng việt', 'vietnamita'], t: ['vie'] },
  { c: 'cs', n: 'Czech',      f: ['🇨🇿'], w: ['czech', 'cesky', 'česky', 'čeština', 'cestina'], t: ['cze', 'ces'], st: ['titulky'] },
  { c: 'sk', n: 'Slovak',     f: ['🇸🇰'], w: ['slovak', 'slovensky', 'slovenčina'], t: ['slo', 'slk'] },
  { c: 'hu', n: 'Hungarian',  f: ['🇭🇺'], w: ['hungarian', 'magyar'], t: ['hun'] },
  { c: 'ro', n: 'Romanian',   f: ['🇷🇴'], w: ['romanian', 'romana', 'română'], t: ['rum', 'ron'] },
  { c: 'bg', n: 'Bulgarian',  f: ['🇧🇬'], w: ['bulgarian', 'български'], t: ['bul'] },
  { c: 'uk', n: 'Ukrainian',  f: ['🇺🇦'], w: ['ukrainian', 'українська', 'украинский'], t: ['ukr'] },
  { c: 'hr', n: 'Croatian',   f: ['🇭🇷'], w: ['croatian', 'hrvatski'], t: ['hrv'] },
  { c: 'sr', n: 'Serbian',    f: ['🇷🇸'], w: ['serbian', 'srpski', 'српски'], t: ['srp'] },
  { c: 'sl', n: 'Slovenian',  f: ['🇸🇮'], w: ['slovenian', 'slovenščina', 'slovene'], t: ['slv'] },
  { c: 'lt', n: 'Lithuanian', f: ['🇱🇹'], w: ['lithuanian', 'lietuvių'], t: ['lit'] },
  { c: 'lv', n: 'Latvian',    f: ['🇱🇻'], w: ['latvian', 'latviešu'], t: ['lav'] },
  { c: 'et', n: 'Estonian',   f: ['🇪🇪'], w: ['estonian', 'eesti'], t: ['est'] },
  { c: 'ca', n: 'Catalan',    f: ['🇪🇸'], w: ['catalan', 'català', 'catala'], t: ['cat'] },
];

const LANGS = {};
for (const d of LANG_DEFS) {
  LANGS[d.c] = {
    name: d.n, flag: d.f[0], flags: d.f,
    words: d.w || [], three: d.t || [], two: [d.c].concat(d.two || []),
    subTags: d.st || [], audioTags: d.at || [],
  };
}

const DEBRID = {
  realdebrid: 'RD+',
  alldebrid:  'AD+',
  premiumize: 'PM+',
  torbox:     'TB+',
  debridlink: 'DL+',
};

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Lookup tables (null-prototype so tokens like "constructor" never match)
const STRONG = Object.create(null);   // full / native names (safe anywhere in a release name)
const WEAK = Object.create(null);     // short codes (only trusted right next to a "sub" word)
const CODE = Object.create(null);     // every ISO code, for exact track-language matching
const SUBTAG = Object.create(null);   // single-token "subs in language X" tags
const AUDIOTAG = Object.create(null); // single-token "audio in language X" tags
// Short codes that are also common English words: never trusted inside release names.
const RISKY_SHORT = new Set(['it', 'no', 'he', 'is', 'id', 'ms', 'me', 'in', 'iw', 'nb', 'nn']);
// 3-letter codes that are also common first names / words: never used as audio tags.
const AMBIG3 = new Set(['dan', 'ben', 'tam', 'tel', 'mal', 'ind', 'nor', 'fin', 'pol', 'est', 'lit', 'cat', 'may', 'per', 'tha']);
for (const code of Object.keys(LANGS)) {
  const L = LANGS[code];
  L.words.forEach((w) => { STRONG[w] = code; });
  L.two.forEach((w) => { CODE[w] = code; if (!RISKY_SHORT.has(w)) WEAK[w] = code; });
  L.three.forEach((w) => { CODE[w] = code; WEAK[w] = code; if (!AMBIG3.has(w)) AUDIOTAG[w] = code; });
  L.words.filter((w) => /^[a-z]{3}$/.test(w)).forEach((w) => { CODE[w] = code; });
  L.subTags.forEach((w) => { SUBTAG[w] = code; });
  L.audioTags.forEach((w) => { AUDIOTAG[w] = code; });
}

const sha = (s) => crypto.createHash('sha1').update(s).digest('hex');
const b64u = (s) => Buffer.from(s).toString('base64url');
const ub64 = (s) => Buffer.from(s, 'base64url').toString('utf8');
const safeDecode = (s) => { try { return decodeURIComponent(s); } catch (e) { return null; } };

/* ------------------------------------------------------------------ */
/* Safe outgoing requests                                              */
/* ------------------------------------------------------------------ */

const protoOk = (p) => p === 'https:' || (ALLOW_PRIVATE && p === 'http:');

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) {
    const [a, b, c] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 192 && b === 0 && c === 0) || (a === 198 && (b === 18 || b === 19)) ||
      (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v = String(ip).toLowerCase();
  if (v === '::1' || v === '::') return true;
  if (v.startsWith('::ffff:')) {
    const m = v.slice(7);
    return net.isIPv4(m) ? isPrivateIp(m) : true;
  }
  return /^(fc|fd|fe8|fe9|fea|feb)/.test(v);
}

// DNS guard used by every outgoing socket: the address that is CHECKED is the address that is USED,
// so a hostname cannot answer "public" to a check and "127.0.0.1" to the real connection (DNS rebinding).
function guardedLookup(hostname, options, cb) {
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return cb(err);
    const list = Array.isArray(address) ? address : [{ address, family }];
    if (!ALLOW_PRIVATE && list.some((a) => isPrivateIp(a.address))) return cb(new Error('blocked host'));
    cb(null, address, family);
  });
}

function safeUrl(u) {
  try {
    const x = new URL(String(u).trim().replace(/^stremio:\/\//i, 'https://'));
    if (!protoOk(x.protocol)) return null;
    if (x.username || x.password) return null;
    const h = x.hostname.toLowerCase();
    if (!ALLOW_PRIVATE && (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.local') ||
        h.endsWith('.internal') || h.startsWith('['))) return null;
    return x.origin + x.pathname.replace(/\/(manifest\.json|configure)\/?$/i, '').replace(/\/+$/, '');
  } catch (e) { return null; }
}

// One GET with: pinned-DNS private-IP guard, manual redirects (each hop re-checked), transparent decompression
// and a HARD byte cap enforced while streaming (never buffers more than maxBytes).
// opts: { headers, ms, maxBytes, partial }  partial=true -> stop quietly at maxBytes instead of failing.
function httpGet(url, opts, hops) {
  hops = hops || 0;
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { return reject(new Error('bad url')); }
    if (!protoOk(u.protocol)) return reject(new Error('https only'));
    const host = u.hostname.replace(/^\[|\]$/g, '');
    if (!ALLOW_PRIVATE && net.isIP(host) && isPrivateIp(host)) return reject(new Error('blocked host'));

    const maxBytes = opts.maxBytes || MAX_BYTES;
    let settled = false;
    let timer = null;
    let r = null;
    const done = (fn, v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(v);
    };
    timer = setTimeout(() => { if (r) r.destroy(); done(reject, new Error('timeout')); }, opts.ms || 9000);

    const lib = u.protocol === 'https:' ? https : http;
    r = lib.request(u, {
      method: 'GET',
      agent: false,
      lookup: guardedLookup,
      headers: Object.assign({ 'User-Agent': UA, 'Accept-Encoding': 'gzip, deflate, br' }, opts.headers),
    }, (res) => {
      const status = res.statusCode || 0;
      if (status >= 300 && status < 400) {
        res.resume();
        const loc = res.headers.location;
        if (!loc || hops >= 3) return done(reject, new Error('bad redirect'));
        let next;
        try { next = new URL(loc, u).href; } catch (e) { return done(reject, new Error('bad redirect')); }
        return httpGet(next, opts, hops + 1).then((v) => done(resolve, v), (e) => done(reject, e));
      }
      if (status < 200 || status >= 300) { res.resume(); return done(reject, new Error('HTTP ' + status)); }
      if (!opts.partial && (+res.headers['content-length'] || 0) > maxBytes) {
        res.destroy();
        return done(reject, new Error('too large'));
      }

      let stream = res;
      const enc = String(res.headers['content-encoding'] || '').toLowerCase();
      if (enc === 'gzip' || enc === 'x-gzip') stream = res.pipe(zlib.createGunzip());
      else if (enc === 'deflate') stream = res.pipe(zlib.createInflate());
      else if (enc === 'br') stream = res.pipe(zlib.createBrotliDecompress());

      const chunks = [];
      let got = 0;
      const finish = () => done(resolve, { status, headers: res.headers, body: Buffer.concat(chunks) });
      stream.on('data', (c) => {
        if (settled) return;
        got += c.length;
        if (got > maxBytes) {
          res.destroy();
          if (!opts.partial) return done(reject, new Error('too large'));
          chunks.push(c.subarray(0, c.length - (got - maxBytes)));
          return finish();
        }
        chunks.push(c);
      });
      stream.on('end', finish);
      stream.on('error', (e) => done(reject, e));
      res.on('error', (e) => done(reject, e));
    });
    r.on('error', (e) => done(reject, e));
    r.end();
  });
}

async function req(url, headers, ms) {
  const r = await httpGet(url, { headers: Object.assign({ 'Accept': 'application/json' }, headers), ms: ms || 9000, maxBytes: MAX_BYTES });
  return r.body.toString('utf8');
}
const getJSON = async (url, headers, ms) => JSON.parse(await req(url, headers, ms));

// Read only the first `bytes` of a remote file (Range request, redirects re-checked).
async function fetchHead(url, bytes, ms) { return fetchRange(url, 0, bytes, ms); }

async function fetchRange(url, start, bytes, ms) {
  const r = await httpGet(url, {
    headers: { 'Range': 'bytes=' + start + '-' + (start + bytes - 1), 'Accept-Encoding': 'identity' },
    ms: ms || 7000, maxBytes: bytes, partial: true,
  });
  if (start > 0 && r.status !== 206) throw new Error('range not supported');
  return r.body;
}

/* ------------------------------------------------------------------ */
/* Cache                                                               */
/* ------------------------------------------------------------------ */

const cache = new Map();
const remember = (k, v, max) => {
  cache.set(k, { t: Date.now(), v });
  if (cache.size > (max || 500)) cache.delete(cache.keys().next().value);
  return v;
};
const recall = (k, ttl) => {
  const h = cache.get(k);
  return h && Date.now() - h.t < (ttl || 600000) ? h.v : null;
};

// language|filename -> release text, so the subtitles endpoint can re-check a chosen stream.
// The language is part of the key because the verified proof ("subs in YOUR language") differs per user language.
const fileTexts = new Map();
function rememberFile(lang, fn, text, proof) {
  fileTexts.set(lang + '|' + fn, { text, proof: proof || '' });
  if (fileTexts.size > 3000) fileTexts.delete(fileTexts.keys().next().value);
}

/* ------------------------------------------------------------------ */
/* Release parsing                                                     */
/* ------------------------------------------------------------------ */

function parseRelease(text) {
  const t = String(text || '').toLowerCase();
  const has = (re) => re.test(t);

  const res = has(/2160p|\b4k\b|\buhd\b/) ? 2160
    : has(/1080[pi]/) ? 1080
    : has(/720p/) ? 720
    : has(/480p|576p/) ? 480 : 0;

  const source = has(/remux/) ? 'BluRay REMUX'
    : has(/blu-?ray|bdrip|brrip/) ? 'BluRay'
    : has(/web[ ._-]?dl/) ? 'WEB-DL'
    : has(/web[ ._-]?rip|\bweb\b/) ? 'WEBRip'
    : has(/hdtv/) ? 'HDTV'
    : has(/dvd[ ._-]?rip|\bdvd\b/) ? 'DVD'
    : has(/\bcam(?:rip)?\b|telesync|hdcam/) ? 'CAM' : '';

  const codec = has(/x265|hevc|h[ .]?265/) ? 'HEVC'
    : has(/x264|h[ .]?264|\bavc\b/) ? 'x264'
    : has(/\bav1\b/) ? 'AV1' : '';

  const hdr = has(/dolby[ .-]?vision|\bdv\b|\bdovi\b/) ? 'DV'
    : has(/hdr10\+/) ? 'HDR10+'
    : has(/\bhdr/) ? 'HDR' : '';

  const audio = has(/atmos/) ? 'Atmos'
    : has(/truehd/) ? 'TrueHD'
    : has(/dts[ -]?(?:hd|x|ma)/) ? 'DTS-HD'
    : has(/\bddp|\bdd\+|e-?ac-?3/) ? 'DD+'
    : has(/\bdd\d|\bdd\b|\bac-?3\b/) ? 'DD'
    : has(/\bdts\b/) ? 'DTS'
    : has(/\baac/) ? 'AAC' : '';

  const ch = (t.match(/(?:^|[^\d])(7\.1|5\.1|2\.0)(?!\d)/) || [])[1] || '';

  const sz = t.match(/(\d+(?:\.\d+)?)\s*(gb|gib|mb|mib)/);
  const size = sz ? (sz[2][0] === 'g' ? +sz[1] : +sz[1] / 1024) : 0;

  const se = t.match(/(?:👤|seeders?:?)\s*(\d+)/i);
  const seeders = se ? +se[1] : 0;

  return { res, source, codec, hdr, audio, ch, size, seeders };
}

const BAD_GROUP = new Set(['dl', 'rip', 'hd', 'sd', 'bd', 'hdr', 'dv', 'x264', 'x265', 'hevc', 'avc', 'webrip', 'bluray']);
function parseGroup(titleSrc) {
  const base = String(titleSrc || '').replace(/\.(mkv|mp4|avi|m4v|ts|wmv|mov)$/i, '').trim();
  const m = base.match(/-([a-z0-9]{2,12})(?:\[[^\]]*\])?$/i);
  return m && !BAD_GROUP.has(m[1].toLowerCase()) ? m[1] : '';
}

// Best "release name" line out of a raw stream object.
const looksRel = (s) => !!s && s.length > 8 &&
  /\d{3,4}p|web|blu-?ray|hdtv|x26[45]|hevc|\b(19|20)\d{2}\b|s\d{1,2}e\d{1,3}/i.test(s);

function urlFilename(u) {
  try {
    const p = decodeURIComponent(new URL(u).pathname.split('/').pop() || '');
    return /\.(mkv|mp4|avi|m4v|ts|wmv|mov|webm)$/i.test(p) ? p : '';
  } catch (e) { return ''; }
}

function pickTitleLine(s) {
  const fn = s.behaviorHints && s.behaviorHints.filename;
  if (fn) return String(fn);
  const lines = [s.title, s.description].filter(Boolean).join('\n')
    .split('\n').map((l) => l.trim()).filter(Boolean);
  const strip = (l) => l.replace(/^[^\p{L}\p{N}\[(]+/u, '').replace(/\s*[\/|].*$/, '').trim();
  const pick = lines.find((l) => /^[📂📁📄🎞🎬💿]/u.test(l) && looksRel(strip(l))) ||
    lines.find((l) => looksRel(strip(l))) || lines[0] || '';
  return strip(pick) || String(s.name || '').split('\n')[0] || '';
}

/* ------------------------------------------------------------------ */
/* Embedded subtitle detection                                         */
/* ------------------------------------------------------------------ */
/*
  Result flags (per user language):
    sub         explicit "<lang> subs" / "subs: <lang>" / VOSTFR / ESub ...
    hard        hardcoded (burned-in) subs in that language
    hardUnknown hardcoded subs, language not stated
    audio       the language appears as audio/language tag in the release
    multi       generic "multi subs / multi audio / dual audio"
    flag        only a flag emoji of that language
    addon       the source stream itself ships a subtitle in that language
*/

const SUB_MARK = new Set(['sub', 'subs', 'subbed', 'subtitle', 'subtitles', 'subtitled', 'softsub', 'softsubs',
  // other languages: "subtitles" / "subtitled" as written in release names
  'legendado', 'legendas', 'legenda', 'subtitulado', 'subtitulada', 'subtitulos', 'subtítulos', 'sottotitoli', 'sottotitolato',
  'untertitel', 'untertitelt', 'ondertiteld', 'ondertitels', 'napisy', 'altyazi', 'altyazı', 'altyazılı', 'titulky',
  'felirat', 'feliratos', 'subtitrat', 'subtitrari', 'субтитры', 'сабы', 'ترجمة', 'مترجم', 'مترجمة', 'sous-titres']);
const HARD_MARK = new Set(['hardsub', 'hardsubs', 'hardsubbed', 'hardcoded', 'hardcode', 'hc']);
const MULTI_TOK = new Set(['multi', 'msub', 'msubs', 'multisub', 'multisubs', 'multisubtitle', 'multisubtitles',
  'multiaudio', 'multilang', 'multilanguage']);
const DUAL_CTX = new Set(['audio', 'sub', 'subs', 'subtitle', 'subtitles', 'lang', 'language', 'languages']);
const CUT_RE = /^(?:(?:19|20)\d{2}|\d{3,4}p|s\d{1,2}e\d{1,3})$/;

const tokenize = (line) =>
  String(line || '').toLowerCase().replace(/[^\p{L}\p{M}\p{N}]+/gu, ' ').trim().split(' ').filter(Boolean);

const langOfToken = (t, weak) => STRONG[t] || (weak ? WEAK[t] : '') || '';

function langMatches(code, lang) {
  const full = String(code || '').toLowerCase().trim();
  if (CODE[full] === lang) return true;
  const c = full.split(/[-_]/)[0];
  return CODE[c] === lang || STRONG[c] === lang;
}

// Single token such as "arsub", "engsubs", "subara", "vostfr", "esub".
function tokenLangSub(t) {
  if (SUBTAG[t]) return SUBTAG[t];
  let m = t.match(/^(\p{L}+?)(?:subs?|subbed)$/u);
  if (m) { const lg = langOfToken(m[1], true); if (lg) return lg; }
  m = t.match(/^(?:subs?|subtitles?)(\p{L}+)$/u);
  if (m) { const lg = langOfToken(m[1], true); if (lg) return lg; }
  return '';
}

function scanLine(tokens, lang, res) {
  if (!tokens.length) return;
  const used = new Set();

  for (let i = 0; i < tokens.length; i++) {
    const t = tokens[i];
    if (MULTI_TOK.has(t) || (t === 'dual' && DUAL_CTX.has(tokens[i + 1]))) res.multi = true;

    const ls = tokenLangSub(t);
    if (ls) {
      used.add(i);
      if (ls === lang) res.sub = true;
      continue;
    }

    let isMark = false;
    let hard = false;
    if (HARD_MARK.has(t)) { isMark = true; hard = true; }
    else if (SUB_MARK.has(t)) {
      isMark = true;
      hard = i > 0 && (tokens[i - 1] === 'hard' || tokens[i - 1] === 'hardcoded');
    }
    if (!isMark) continue;
    used.add(i);

    // languages listed right before ("Arabic Subs") and right after ("Subs: eng ara")
    const found = [];
    let j = i - 1;
    while (j >= 0) {
      const lg = (j === i - 1 && tokens[j] === 'e') ? 'en' : langOfToken(tokens[j], true);
      if (!lg) break;
      found.push(lg); used.add(j); j--;
    }
    j = i + 1;
    while (j < tokens.length) {
      const lg = langOfToken(tokens[j], true);
      if (!lg) break;
      found.push(lg); used.add(j); j++;
    }

    if (found.length) {
      if (found.includes(lang)) { if (hard) res.hard = true; else res.sub = true; }
    } else if (hard) {
      res.hardUnknown = true;
    }
  }

  // Language names / audio tags: ignore the movie-title part (everything before year / resolution / SxxExx)
  let cut = -1;
  for (let i = 0; i < tokens.length; i++) {
    if (CUT_RE.test(tokens[i])) { cut = i; break; }
  }
  for (let i = cut + 1; i < tokens.length; i++) {
    if (used.has(i)) continue;
    const t = tokens[i];
    if (STRONG[t] === lang || AUDIOTAG[t] === lang) res.audio = true;
  }
}

function detectSubs(text, lang, extSubs) {
  const L = LANGS[lang];
  const res = { sub: false, hard: false, hardUnknown: false, audio: false, multi: false, flag: false, addon: false };
  if (!L) return res;
  const raw = String(text || '');
  for (const line of raw.split(/\r?\n/)) scanLine(tokenize(line), lang, res);
  if (/字幕|자막/.test(raw) &&
      L.words.some((w) => w.length >= 2 && /[^\x00-\x7f]/.test(w) && raw.includes(w))) res.sub = true;
  if (L.flags.some((f) => raw.includes(f))) res.flag = true;
  if (Array.isArray(extSubs) && extSubs.some((x) => x && langMatches(x.lang, lang))) res.addon = true;
  return res;
}

function subVerdict(r) {
  if (r.sub) return 'sub';
  if (r.addon) return 'addon';
  if (r.hard) return 'hard';
  if (r.audio) return 'audio';
  if (r.multi) return 'multi';
  if (r.hardUnknown) return 'hardx';
  if (r.flag) return 'flag';
  return 'none';
}


// Score weights (same idea as Anseb): a release that already has your language
// can outrank a higher resolution that does not.
const W_RES = { 2160: 40, 1080: 30, 720: 15, 480: 5, 0: 0 };
const W_SRC = { 'BluRay REMUX': 25, 'BluRay': 20, 'WEB-DL': 18, 'WEBRip': 12, 'HDTV': 8, 'DVD': 2, 'CAM': -200, '': 0 };
const W_SUB = { psub: 50, paudio: 45, psubimg: 40, sub: 35, addon: 35, audio: 30, hard: 25, flag: 15, multi: 5, hardx: 0, none: 0, pnone: -5 };
// Tier first, score second: a file whose embedded subtitle/audio is VERIFIED in your language always sits above
// everything else, whatever its resolution. Image-based tracks (PGS/VobSub) rank just below text tracks because
// many players cannot draw them.
const TIER = { psub: 4, paudio: 4, psubimg: 3, sub: 2, addon: 2, hard: 2, audio: 2, flag: 1, multi: 1, hardx: 1, none: 1, pnone: 0 };

function scoreStream(info, verdict) {
  let v = (W_RES[info.res] || 0) + (W_SRC[info.source] || 0) + (W_SUB[verdict] || 0);
  if (info.seeders) v += Math.min(14, Math.log10(1 + info.seeders) * 5);
  return v;
}

/* ------------------------------------------------------------------ */
/* Fetching and building streams                                       */
/* ------------------------------------------------------------------ */

/* ------------------------------------------------------------------ */
/* Verified detection: read the real track list inside an MKV file     */
/* ------------------------------------------------------------------ */

const PROBE_BYTES = 256 * 1024;

function ebmlId(b, p) {
  const f = b[p];
  if (f === undefined) return null;
  let l = 1, m = 0x80;
  while (l <= 4 && !(f & m)) { l++; m >>= 1; }
  if (l > 4 || p + l > b.length) return null;
  let v = 0;
  for (let i = 0; i < l; i++) v = v * 256 + b[p + i];
  return { id: v, len: l };
}

function ebmlSize(b, p) {
  const f = b[p];
  if (f === undefined) return null;
  let l = 1, m = 0x80;
  while (l <= 8 && !(f & m)) { l++; m >>= 1; }
  if (l > 8 || p + l > b.length) return null;
  let v = f & (m - 1);
  let allOnes = v === m - 1;
  for (let i = 1; i < l; i++) {
    v = v * 256 + b[p + i];
    if (b[p + i] !== 0xff) allOnes = false;
  }
  return { size: allOnes ? -1 : v, len: l };
}

// cb(id, dataStart, dataEnd, truncated) — return false to stop
function ebmlWalk(b, start, end, cb) {
  let p = start;
  while (p < end) {
    const id = ebmlId(b, p);
    if (!id) return;
    const sz = ebmlSize(b, p + id.len);
    if (!sz) return;
    const ds = p + id.len + sz.len;
    if (ds > end) return;
    const unknown = sz.size < 0;
    const de = unknown ? end : Math.min(ds + sz.size, end);
    const trunc = unknown || ds + sz.size > end;
    if (cb(id.id, ds, de, trunc) === false) return;
    p = de;
  }
}

function ebmlUint(b, s, e) { let v = 0; for (let i = s; i < e; i++) v = v * 256 + b[i]; return v; }
function ebmlStr(b, s, e) { return b.toString('utf8', s, e).replace(/\0+$/, ''); }

function readTracks(b, s, e) {
  const out = { subs: [], audio: [] };
  ebmlWalk(b, s, e, (id, ds, de) => {
    if (id !== 0xAE) return; // TrackEntry
    const t = { type: 0, lang: 'eng', bcp: '', name: '', codec: '', forced: false };
    ebmlWalk(b, ds, de, (i, s2, e2) => {
      if (i === 0x83) t.type = ebmlUint(b, s2, e2);
      else if (i === 0x22B59C) t.lang = ebmlStr(b, s2, e2).toLowerCase();
      else if (i === 0x22B59D) t.bcp = ebmlStr(b, s2, e2).toLowerCase();
      else if (i === 0x536E) t.name = ebmlStr(b, s2, e2);
      else if (i === 0x86) t.codec = ebmlStr(b, s2, e2);
      else if (i === 0x55AA) t.forced = ebmlUint(b, s2, e2) === 1;
    });
    if (/forced|\bsigns?\b|\bsongs?\b|commentary|karaoke/i.test(t.name)) t.forced = true;
    t.bitmap = /PGS|VOBSUB|DVBSUB|HDMV/i.test(t.codec);
    if (t.type === 17) out.subs.push(t);
    else if (t.type === 2) out.audio.push(t);
  });
  return out;
}

// Returns { subs, audio }, { incomplete: true } (MKV, but Tracks not fully inside this buffer), or null (not MKV).
function mkvTracks(b) {
  if (!b || b.length < 64 || b.readUInt32BE(0) !== 0x1a45dfa3) return null;
  let result = { incomplete: true };
  ebmlWalk(b, 0, b.length, (id, ds, de) => {
    if (id !== 0x18538067) return; // skip the EBML header, enter Segment
    ebmlWalk(b, ds, de, (id2, ds2, de2, trunc2) => {
      if (id2 === 0x1F43B675) return false; // Cluster reached: no Tracks before it
      if (id2 !== 0x1654AE6B) return;       // not Tracks
      if (!trunc2) result = readTracks(b, ds2, de2);
      return false;
    });
    return false;
  });
  return result;
}

/* ---- MP4 / M4V / MOV: read the 'moov' box ---- */

function mp4Box(b, p, end) {
  if (p + 8 > end) return null;
  let size = b.readUInt32BE(p);
  const type = b.toString('latin1', p + 4, p + 8);
  let hdr = 8;
  if (size === 1) {
    if (p + 16 > end) return null;
    size = Number(b.readBigUInt64BE(p + 8));
    hdr = 16;
  } else if (size === 0) size = end - p;
  return size < hdr ? null : { type, hdr, size, start: p };
}

function mp4Each(b, s, e, cb) {
  let p = s;
  while (p < e) {
    const x = mp4Box(b, p, e);
    if (!x) return;
    if (cb(x.type, p + x.hdr, Math.min(p + x.size, e)) === false) return;
    p += x.size;
  }
}

function mp4Find(b, s, e, type) {
  let r = null;
  mp4Each(b, s, e, (t, ds, de) => { if (t === type) { r = [ds, de]; return false; } });
  return r;
}

function mp4Lang(v) {
  if (!v || v === 0x55c4) return 'und';
  return String.fromCharCode(((v >> 10) & 31) + 0x60, ((v >> 5) & 31) + 0x60, (v & 31) + 0x60);
}

function parseMoov(b, s, e) {
  const out = { subs: [], audio: [] };
  mp4Each(b, s, e, (type, ds, de) => {
    if (type !== 'trak') return;
    const mdia = mp4Find(b, ds, de, 'mdia');
    if (!mdia) return;
    let handler = '', lang = 'und', codec = '';
    mp4Each(b, mdia[0], mdia[1], (t2, s2, e2) => {
      if (t2 === 'hdlr' && e2 - s2 >= 12) handler = b.toString('latin1', s2 + 8, s2 + 12);
      else if (t2 === 'mdhd' && e2 - s2 >= 24) {
        const v1 = b[s2] === 1;
        const off = v1 ? s2 + 32 : s2 + 20;
        if (off + 2 <= e2) lang = mp4Lang(b.readUInt16BE(off));
      } else if (t2 === 'minf') {
        const stbl = mp4Find(b, s2, e2, 'stbl');
        const stsd = stbl && mp4Find(b, stbl[0], stbl[1], 'stsd');
        if (stsd && stsd[1] - stsd[0] >= 16) codec = b.toString('latin1', stsd[0] + 12, stsd[0] + 16);
      }
    });
    let name = '';
    const udta = mp4Find(b, ds, de, 'udta');
    const nm = udta && mp4Find(b, udta[0], udta[1], 'name');
    if (nm) name = b.toString('utf8', nm[0], nm[1]).replace(/[\0-\x1f]+/g, '');
    const t = { type: 0, lang, bcp: '', name, codec, forced: /forced|\bsigns?\b|commentary/i.test(name), bitmap: /^(subp|dvds)$/i.test(codec) };
    if (handler === 'sbtl' || handler === 'subt' || handler === 'text') out.subs.push(t);
    else if (handler === 'soun') out.audio.push(t);
  });
  return out;
}

// -> { tracks } | { nextAt, need } (offset of the next top-level box we still have to read) | {}
function mp4Scan(b) {
  let p = 0;
  let nextAt = null;
  while (p + 8 <= b.length) {
    const x = mp4Box(b, p, b.length);
    if (!x) return {};
    if (x.type === 'moov') {
      if (p + x.size <= b.length) return { tracks: parseMoov(b, p + x.hdr, p + x.size) };
      return { nextAt: p, need: x.size };
    }
    if (x.size >= 0x7fffffffffff) return {};
    p += x.size;
    nextAt = p;
  }
  return { nextAt };
}

function trackMatches(t, lang) {
  if (langMatches(t.bcp || t.lang, lang)) return true;
  return tokenize(t.name).some((w) => STRONG[w] === lang);
}

function trackLabel(t) {
  const code = t.bcp || t.lang;
  for (const k of Object.keys(LANGS)) if (langMatches(code, k)) return LANGS[k].flag;
  return String(code || '?').slice(0, 3);
}

function probeVerdict(p, lang) {
  const mine = p.subs.filter((t) => trackMatches(t, lang));
  const real = mine.filter((t) => !t.forced);
  if (real.length) return { kind: 'psub', n: real.length, bitmap: real.every((t) => t.bitmap) };
  if (p.audio.some((t) => trackMatches(t, lang))) return { kind: 'paudio' };
  const has = [];
  p.subs.forEach((t) => { const l = trackLabel(t); if (!has.includes(l)) has.push(l); });
  return { kind: 'pnone', has, forcedOnly: mine.length > 0 };
}

// Only probe streams that are already cached on the debrid service, so probing
// can never make a debrid service start downloading a torrent.
const CACHED_RE = /\[\w{1,3}\+\]|⚡|cached|instant/i;
const probeCache = new Map();

async function probeMp4(url, first) {
  let buf = first;
  let base = 0;
  for (let hop = 0; hop < 4; hop++) {
    const r = mp4Scan(buf);
    if (r.tracks) return r.tracks;
    if (r.nextAt == null) return null;
    base += r.nextAt;
    buf = await fetchRange(url, base, Math.min(8 * 1024 * 1024, Math.max(2 * 1024 * 1024, (r.need || 0) + 64)), 8000);
    if (buf.length < 16) return null;
  }
  return null;
}

async function probeOne(url) {
  const k = sha(url);
  const hit = probeCache.get(k);
  if (hit && Date.now() - hit.t < (hit.v.unknown ? 30 * 60e3 : 6 * 3600e3)) return hit.v;
  let v = { unknown: true };
  try {
    let head = await fetchHead(url, PROBE_BYTES, 6000);
    if (head.length >= 64 && head.readUInt32BE(0) === 0x1a45dfa3) {
      let t = mkvTracks(head);
      if (t && t.incomplete) { head = await fetchHead(url, 2 * 1024 * 1024, 8000); t = mkvTracks(head); }
      if (t && !t.incomplete) v = t;
    } else if (head.length >= 16 && head.toString('latin1', 4, 8) === 'ftyp') {
      v = (await probeMp4(url, head)) || v;
    }
  } catch (e) { v = { unknown: true }; }
  probeCache.set(k, { t: Date.now(), v });
  if (probeCache.size > 2000) probeCache.delete(probeCache.keys().next().value);
  return v;
}

async function probeStreams(raw) {
  const out = new Map();
  const urls = [];
  for (const s of raw) {
    if (!s || !s.url || urls.includes(s.url)) continue;
    if (!CACHED_RE.test(String(s.name || ''))) continue;
    urls.push(s.url);
    if (urls.length >= 24) break;
  }
  if (!urls.length) return out;
  const jobs = urls.map(async (u) => { out.set(u, await probeOne(u)); });
  let to = null;
  await Promise.race([Promise.allSettled(jobs), new Promise((ok) => { to = setTimeout(ok, 8000); })]);
  clearTimeout(to);
  return out;
}

const DEBRID_KEYS = /(?:^|[\/|])(?:realdebrid|alldebrid|premiumize|debridlink|torbox|offcloud|putio)=/i;

// Torrentio keeps options in one path segment: /providers=a|sort=b|realdebrid=KEY/manifest.json
function withDebrid(base, debrid, key) {
  if (DEBRID_KEYS.test(base)) return base;
  const u = new URL(base);
  const segs = u.pathname.split('/').filter(Boolean);
  const add = debrid + '=' + encodeURIComponent(key);
  if (segs.length && segs[segs.length - 1].includes('=')) segs[segs.length - 1] += '|' + add;
  else segs.push(add);
  return u.origin + '/' + segs.join('/');
}

// Match the hostname exactly: a path/query that merely contains "torrentio" must never receive the key.
function isTorrentioHost(base) {
  try { return TORRENTIO_HOSTS.has(new URL(base).hostname.toLowerCase()); } catch (e) { return false; }
}

async function fetchAllStreams(sources, type, id, debrid, key) {
  const tail = '/stream/' + type + '/' + encodeURIComponent(id) + '.json';
  const tasks = sources.map(async (src) => {
    let base = safeUrl(src.url);
    if (!base) return [];
    if (debrid && key && isTorrentioHost(base)) base = withDebrid(base, debrid, key);
    try {
      const d = await getJSON(base + tail, null, 10000);
      return (Array.isArray(d.streams) ? d.streams : []).map((s) => Object.assign({}, s, { _source: src.name }));
    } catch (e) { return []; }
  });
  return (await Promise.all(tasks)).flat();
}

function buildStreams(rawList, opts) {
  const { lang, debrid, ext, probes } = opts;
  const L = LANGS[lang];
  const badge = debrid && DEBRID[debrid] ? ' [' + DEBRID[debrid] + ']' : '';
  const seen = new Set();
  const items = [];

  for (const s of rawList) {
    if (!s || (!s.url && !s.infoHash)) continue;

    const dk = s.infoHash
      ? 'h|' + String(s.infoHash).toLowerCase() + '|' + (s.fileIdx == null ? '' : s.fileIdx)
      : 'u|' + s.url;
    if (seen.has(dk)) continue;
    seen.add(dk);

    const bh = s.behaviorHints || {};
    const fn = bh.filename ? String(bh.filename) : (s.url ? urlFilename(s.url) : '');
    const text = [s.name, s.title, s.description].filter(Boolean).join('\n');
    const full = text + '\n' + fn;

    const info = parseRelease(full);
    let verdict = subVerdict(detectSubs(full, lang, s.subtitles));
    let proof = null;
    const pr = probes && s.url ? probes.get(s.url) : null;
    if (pr && !pr.unknown) {
      // the real track list beats any guess from the release name
      proof = probeVerdict(pr, lang);
      if (proof.kind === 'psub') verdict = proof.bitmap ? 'psubimg' : 'psub';
      else if (proof.kind === 'paudio') verdict = 'paudio';
      else if (verdict !== 'hard' && verdict !== 'addon') verdict = 'pnone';
    }
    if (fn) rememberFile(lang, fn, text, verdict === 'psubimg' ? 'psubimg' : (proof && proof.kind));

    // title
    const titleSrc = pickTitleLine(s);
    const base = titleSrc.replace(/\.(mkv|mp4|avi|m4v|ts|wmv|mov)$/i, '');
    const title = base
      .replace(/[._]+/g, ' ')
      .replace(/\s+/g, ' ')
      .replace(/\b(2160p|1080p|1080i|720p|576p|480p|4k|uhd|WEB[- ]?DL|WEB[- ]?Rip|BluRay|BDRip|BRRip|REMUX|HDTV|HEVC|x264|x265)\b.*$/i, '')
      .replace(/[\s(\[-]+$/, '')
      .trim() || base.trim() || 'Unknown';
    const group = parseGroup(titleSrc);

    const resLabel = info.res === 2160 ? '4K' : info.res ? info.res + 'p' : '';
    const head = [s._source || 'Source', resLabel].filter(Boolean).join(' ');

    const q3 = [];
    if (info.source) q3.push('🎥 ' + info.source);
    if (info.codec)  q3.push('🎞️ ' + info.codec);
    if (group)       q3.push('🏷️ ' + group);

    const q4 = [];
    if (info.hdr)   q4.push('📺 ' + info.hdr);
    if (info.audio) q4.push('🎧 ' + info.audio);
    if (info.ch)    q4.push('🔊 ' + info.ch);

    const q5 = [];
    if (info.size)    q5.push('📦 ' + info.size.toFixed(1) + ' GB');
    if (info.seeders) q5.push('👤 ' + info.seeders);

    const extTail = ext ? ' · external will load' : '';
    const proofNote = proof && proof.kind === 'psub' && proof.n > 1 ? ' (' + proof.n + ' tracks)' : '';
    const hasNote = proof && proof.has && proof.has.length ? ' (file has: ' + proof.has.join(' ') + ')' : '';
    const forcedNote = proof && proof.forcedOnly ? ' (only a forced track)' : '';
    const subLines = {
      psub:  '✅ ' + L.flag + ' ' + L.name + ' subs embedded · verified' + proofNote,
      psubimg: '✅ ' + L.flag + ' ' + L.name + ' subs embedded (image-based) · verified' + proofNote + (ext ? ' · text backup will load' : ''),
      paudio: '✅ 🗣️ ' + L.flag + ' ' + L.name + ' audio · verified',
      pnone: '❌ ' + L.name + ' subs NOT in file (checked)' + forcedNote + hasNote + extTail,
      sub:   '💬 ' + L.flag + ' ' + L.name + ' subs in release name · not verified',
      addon: '💬 ' + L.flag + ' ' + L.name + ' subs provided',
      hard:  '🔒 ' + L.flag + ' ' + L.name + ' hardcoded subs',
      audio: '🗣️ ' + L.flag + ' ' + L.name + ' in release name · not verified',
      multi: '❔ Multi subs in name · not verified',
      hardx: '🔒 Hardcoded subs (language unknown)',
      flag:  '🌐 ' + L.flag + ' ' + L.name + ' tag · not verified',
      none:  '🚫 No ' + L.name + ' subs found in name' + extTail,
    };

    const lines = ['📁 ' + title];
    if (q3.length) lines.push(q3.join(' '));
    if (q4.length) lines.push(q4.join(' '));
    if (q5.length) lines.push(q5.join(' '));
    lines.push(subLines[verdict]);

    const o = {
      name: head + badge,
      description: lines.join('\n'),
      behaviorHints: Object.assign({}, bh, { bingeGroup: 'stremify-' + (s._source || '') + '-' + info.res }),
    };
    o.title = o.description; // older Stremio clients read "title"

    if (!bh.filename && fn) o.behaviorHints.filename = fn; // lets Stremio pass the file name back to /subtitles
    if (s.url) o.url = s.url;
    else {
      o.infoHash = s.infoHash;
      if (s.fileIdx != null) o.fileIdx = s.fileIdx;
      if (Array.isArray(s.sources)) o.sources = s.sources;
    }
    if (Array.isArray(s.subtitles)) o.subtitles = s.subtitles;

    items.push({ o, score: scoreStream(info, verdict), tier: TIER[verdict] || 0, size: info.size });
  }

  return items
    .filter((x) => x.score > -50) // CAM / telesync releases
    .sort((a, b) => b.tier - a.tier || b.score - a.score || b.size - a.size)
    .map((x) => x.o);
}

/* ------------------------------------------------------------------ */
/* Config and manifest                                                 */
/* ------------------------------------------------------------------ */

function encodeConfig(cfg) { return b64u(JSON.stringify(cfg)); }

function decodeConfig(tok) {
  try {
    if (!tok || tok.length > 8000) return {};
    const c = JSON.parse(ub64(tok));
    if (!c || typeof c !== 'object') return {};
    const sources = (Array.isArray(c.sources) ? c.sources : [])
      .filter((s) => s && typeof s.url === 'string')
      .slice(0, MAX_SOURCES)
      .map((s) => ({ name: String(s.name || 'Source').slice(0, 40), url: s.url.slice(0, 1000) }));
    return {
      sources,
      lang: String(c.lang || ''),
      debrid: String(c.debrid || ''),
      key: String(c.key || '').slice(0, 200),
      ext: c.ext !== false,
      verify: c.verify !== false,
      pure: c.pure !== false,
    };
  } catch (e) { return {}; }
}

function buildManifest() {
  return {
    id: 'com.stremify.addon',
    version: VERSION,
    name: 'Stremify',
    description: 'Multi-source stream addon that verifies embedded subtitles (MKV + MP4) for your language and ranks those files first.',
    resources: ['stream', 'subtitles'],
    types: ['movie', 'series'],
    idPrefixes: ['tt'],
    catalogs: [],
    behaviorHints: { configurable: true, configurationRequired: false },
  };
}

/* ------------------------------------------------------------------ */
/* HTTP                                                                */
/* ------------------------------------------------------------------ */

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.png':  'image/png',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
};

function send(res, code, body, headers) {
  res.writeHead(code, Object.assign({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Content-Type': 'application/json; charset=utf-8',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  }, headers));
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function sendHtml(res, data) {
  res.writeHead(200, {
    'Content-Type': MIME['.html'],
    'Cache-Control': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer', // the page URL contains the saved config (incl. API key)
  });
  res.end(data);
}

function serveIndex(res) {
  fs.readFile(path.join(WEB, 'index.html'), (e, d) => {
    if (!e) return sendHtml(res, d);
    fs.readFile(path.join(__dirname, 'index.html'), (e2, d2) => {
      if (e2) return send(res, 404, { error: 'index.html not found' });
      sendHtml(res, d2);
    });
  });
}

function serveStatic(res, rel) {
  const dec = safeDecode(rel);
  if (dec === null) return send(res, 404, { error: 'not found' });
  const f = path.join(WEB, dec);
  if (f !== WEB && !f.startsWith(WEB + path.sep)) return send(res, 404, { error: 'not found' });
  fs.readFile(f, (err, data) => {
    if (err) return send(res, 404, { error: 'not found' });
    const ext = path.extname(f).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=86400',
      'X-Content-Type-Options': 'nosniff',
    });
    res.end(data);
  });
}

/* ---- per-IP rate limit (fixed 1-minute window) ---- */
const hits = new Map();
function clientIp(rq) {
  if (TRUST_PROXY) {
    const x = String(rq.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (x) return x;
  }
  return (rq.socket && rq.socket.remoteAddress) || '';
}
function rateLimited(rq) {
  if (!RATE_LIMIT) return false;
  const ip = clientIp(rq);
  const now = Date.now();
  let h = hits.get(ip);
  if (!h || now - h.t >= 60000) { h = { t: now, n: 0 }; hits.set(ip, h); }
  return ++h.n > RATE_LIMIT;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of hits) if (now - v.t >= 60000) hits.delete(k);
}, 60000).unref();

// identical simultaneous requests (Stremio often sends several) share one upstream fetch
const inflight = new Map();

async function handleStreams(res, tok, type, id) {
  const cfg = decodeConfig(tok);
  const lang = own(LANGS, cfg.lang) ? cfg.lang : 'en';
  const sources = Array.isArray(cfg.sources) ? cfg.sources : [];
  const debrid = own(DEBRID, cfg.debrid) ? cfg.debrid : '';
  const key = cfg.key || '';
  const ext = cfg.ext !== false;

  if (!sources.length) return send(res, 200, { streams: [] });

  const cacheKey = sha(['streams', tok, type, id].join('|'));
  const cached = recall(cacheKey, 5 * 60 * 1000);
  if (cached) return send(res, 200, cached);

  try {
    let job = inflight.get(cacheKey);
    if (!job) {
      job = (async () => {
        const raw = await fetchAllStreams(sources, type, id, debrid, key);
        const probes = cfg.verify === false ? null : await probeStreams(raw);
        const out = { streams: buildStreams(raw, { lang, debrid, ext, probes }) };
        if (out.streams.length) remember(cacheKey, out); // never cache empty/failed results
        return out;
      })().finally(() => inflight.delete(cacheKey));
      inflight.set(cacheKey, job);
    }
    return send(res, 200, await job);
  } catch (e) {
    return send(res, 200, { streams: [] });
  }
}

async function handleSubtitles(res, tok, type, id, extraRaw) {
  const cfg = decodeConfig(tok);
  const lang = own(LANGS, cfg.lang) ? cfg.lang : 'en';
  if (cfg.ext === false) return send(res, 200, { subtitles: [] });

  let extra;
  try { extra = new URLSearchParams(extraRaw || ''); } catch (e) { extra = new URLSearchParams(''); }
  const fn = extra.get('filename') || '';

  // Detection from the release name is a heuristic, so:
  //  - hardcoded subs in your language -> nothing to add
  //  - embedded subs / language audio  -> still offer ONE external subtitle as a backup
  let max = 8;
  if (fn) {
    const known = fileTexts.get(lang + '|' + fn) || {};
    const r = detectSubs((known.text || '') + '\n' + fn, lang, null);
    if (r.hard) return send(res, 200, { subtitles: [] });
    if (known.proof === 'psub' || known.proof === 'paudio') {
      // Verified text track / language audio inside the file: add NOTHING external, so the player's own
      // subtitle-language setting lands on the embedded track instead of an external one.
      if (cfg.pure !== false) return send(res, 200, { subtitles: [] });
      max = 1;
    } else if (known.proof === 'psubimg') max = 1;                         // image-only track: keep one text backup
    else if (!known.proof && (r.sub || r.audio)) max = 1;                  // name-based guess
  }

  const cacheKey = sha(['subs', lang, type, id].join('|'));
  const cached = recall(cacheKey, 30 * 60 * 1000);
  if (cached) return send(res, 200, { subtitles: cached.subtitles.slice(0, max) });

  try {
    const q = new URLSearchParams();
    ['videoHash', 'videoSize', 'filename'].forEach((k) => { if (extra.get(k)) q.set(k, extra.get(k)); });
    const qs = q.toString().replace(/\+/g, '%20');
    const url = SUBS_PROVIDER + '/subtitles/' + type + '/' + encodeURIComponent(id) + (qs ? '/' + qs : '') + '.json';
    const d = await getJSON(url, null, 10000);
    const subs = (Array.isArray(d.subtitles) ? d.subtitles : [])
      .filter((x) => x && x.url && langMatches(x.lang, lang))
      .slice(0, 8)
      .map((x) => ({ id: String(x.id || x.url), url: x.url, lang: x.lang }));
    const out = { subtitles: subs };
    if (subs.length) remember(cacheKey, out);
    return send(res, 200, { subtitles: subs.slice(0, max) });
  } catch (e) {
    return send(res, 200, { subtitles: [] });
  }
}

async function handler(rq, res) {
  if (rq.method === 'OPTIONS') return send(res, 204, '');
  const u = new URL(rq.url, 'http://x');
  const pathname = u.pathname;

  if (pathname === '/' || pathname === '/index.html' || pathname === '/configure' ||
      /^\/c\/[\w-]+\/configure\/?$/.test(pathname)) return serveIndex(res);
  if (pathname.startsWith('/public/')) return serveStatic(res, pathname.slice('/public/'.length));

  if (pathname === '/manifest.json') return send(res, 200, buildManifest());
  if (pathname === '/languages.json') {
    return send(res, 200, Object.keys(LANGS).map((c) => ({ code: c, name: LANGS[c].name, flag: LANGS[c].flag })),
      { 'Cache-Control': 'public, max-age=3600' });
  }

  const m1 = pathname.match(/^\/c\/([\w-]+)\/manifest\.json$/);
  if (m1) return send(res, 200, buildManifest());

  const m2 = pathname.match(/^\/c\/([\w-]+)\/stream\/(movie|series)\/([^/]+)\.json$/);
  if (m2) {
    if (rateLimited(rq)) return send(res, 429, { error: 'rate limited' }, { 'Retry-After': '60' });
    const id = safeDecode(m2[3]);
    if (!id) return send(res, 400, { error: 'bad id' });
    return handleStreams(res, m2[1], m2[2], id);
  }

  const m3 = pathname.match(/^\/c\/([\w-]+)\/subtitles\/(movie|series)\/([^/]+?)(?:\/([^/]*?))?\.json$/);
  if (m3) {
    if (rateLimited(rq)) return send(res, 429, { error: 'rate limited' }, { 'Retry-After': '60' });
    const id = safeDecode(m3[3]);
    if (!id) return send(res, 400, { error: 'bad id' });
    return handleSubtitles(res, m3[1], m3[2], id, m3[4]);
  }

  return send(res, 404, { error: 'not found' });
}

if (require.main === module) {
  process.on('unhandledRejection', (e) => console.error('unhandledRejection:', e && e.message ? e.message : e));
  const server = http.createServer((rq, rs) => handler(rq, rs).catch((e) => {
    console.error('handler error:', e && e.message);
    if (!rs.headersSent) send(rs, 500, { error: 'internal error' }); // never leak internals
    else rs.end();
  }));
  server.requestTimeout = 30000;
  server.headersTimeout = 15000;
  server.listen(PORT, () => console.log('Stremify ' + VERSION + ' on ' + PORT));
  const stop = () => { server.close(() => process.exit(0)); setTimeout(() => process.exit(0), 5000).unref(); };
  process.on('SIGTERM', stop);
  process.on('SIGINT', stop);
}
module.exports = { handler, LANGS, DEBRID, detectSubs, subVerdict, buildStreams, encodeConfig, decodeConfig,
  mkvTracks, mp4Scan, probeVerdict, langMatches, httpGet, isTorrentioHost };
