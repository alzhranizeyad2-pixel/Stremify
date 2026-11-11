'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');

const PORT = process.env.PORT || 3000;
const WEB = path.join(__dirname, 'public');
const UA = 'Stremify/6.0';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_SOURCES === '1';
const SUBS_PROVIDER = (process.env.SUBS_PROVIDER || 'https://opensubtitles-v3.strem.io').replace(/\/+$/, '');
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_SOURCES = 8;

/* ------------------------------------------------------------------ */
/* Languages                                                           */
/* ------------------------------------------------------------------ */

const LANGS = {
  en: { name: 'English',  flag: '🇬🇧', flags: ['🇬🇧', '🇺🇸'], two: ['en'],       words: ['english', 'eng'],
        subTags: ['esub', 'esubs'], audioTags: [] },
  ar: { name: 'Arabic',   flag: '🇸🇦', flags: ['🇸🇦', '🇦🇪', '🇪🇬'], two: ['ar'], words: ['arabic', 'ara', 'arab', 'arabe', 'عربي', 'عربى', 'عربية', 'العربية'],
        subTags: [], audioTags: [] },
  de: { name: 'German',   flag: '🇩🇪', flags: ['🇩🇪'],       two: ['de'],       words: ['german', 'ger', 'deu', 'deutsch', 'allemand'],
        subTags: [], audioTags: [] },
  fr: { name: 'French',   flag: '🇫🇷', flags: ['🇫🇷'],       two: ['fr'],       words: ['french', 'fre', 'fra', 'francais', 'français', 'truefrench'],
        subTags: ['vostfr', 'stfr', 'subfrench', 'vost'], audioTags: ['vf', 'vff', 'vfq', 'vfi', 'vf2'] },
  es: { name: 'Spanish',  flag: '🇪🇸', flags: ['🇪🇸'],       two: ['es'],       words: ['spanish', 'spa', 'esp', 'espanol', 'español', 'castellano', 'latino'],
        subTags: ['vose'], audioTags: [] },
  tr: { name: 'Turkish',  flag: '🇹🇷', flags: ['🇹🇷'],       two: ['tr'],       words: ['turkish', 'tur', 'türkçe', 'turkce'],
        subTags: [], audioTags: [] },
  hi: { name: 'Hindi',    flag: '🇮🇳', flags: ['🇮🇳'],       two: ['hi'],       words: ['hindi', 'hin'],
        subTags: [], audioTags: [] },
  ja: { name: 'Japanese', flag: '🇯🇵', flags: ['🇯🇵'],       two: ['ja', 'jp'], words: ['japanese', 'jpn', 'jap', '日本語'],
        subTags: [], audioTags: [] },
};

const DEBRID = {
  realdebrid: 'RD+',
  alldebrid:  'AD+',
  premiumize: 'PM+',
  torbox:     'TB+',
  debridlink: 'DL+',
};

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

// Lookup tables (null-prototype so tokens like "constructor" never match)
const STRONG = Object.create(null);   // full names + 3-letter codes
const WEAK = Object.create(null);     // 2-letter codes (only trusted next to a "sub" word)
const SUBTAG = Object.create(null);   // single-token "subs in language X" tags
const AUDIOTAG = Object.create(null); // single-token "audio in language X" tags
for (const code of Object.keys(LANGS)) {
  const L = LANGS[code];
  L.words.forEach((w) => { STRONG[w] = code; });
  L.two.forEach((w) => { WEAK[w] = code; });
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
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
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

async function assertPublicHost(hostname) {
  if (ALLOW_PRIVATE) return;
  if (net.isIP(hostname)) {
    if (isPrivateIp(hostname)) throw new Error('blocked host');
    return;
  }
  const addrs = await dns.lookup(hostname, { all: true });
  if (!addrs.length || addrs.some((a) => isPrivateIp(a.address))) throw new Error('blocked host');
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

async function req(url, headers, ms, hops) {
  hops = hops || 0;
  const u = new URL(url);
  if (!protoOk(u.protocol)) throw new Error('https only');
  await assertPublicHost(u.hostname);
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), ms || 9000);
  try {
    const r = await fetch(u.href, {
      headers: Object.assign({ 'User-Agent': UA, 'Accept': 'application/json' }, headers),
      redirect: 'manual',
      signal: ctrl.signal,
    });
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get('location');
      if (!loc || hops >= 3) throw new Error('bad redirect');
      return await req(new URL(loc, u).href, headers, ms, hops + 1);
    }
    if (!r.ok) throw new Error('HTTP ' + r.status);
    if ((+r.headers.get('content-length') || 0) > MAX_BYTES) throw new Error('too large');
    const text = await r.text();
    if (text.length > MAX_BYTES) throw new Error('too large');
    return text;
  } finally { clearTimeout(id); }
}
const getJSON = async (url, headers, ms) => JSON.parse(await req(url, headers, ms));

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

// filename -> release text, so the subtitles endpoint can re-check a chosen stream
const fileTexts = new Map();
function rememberFile(fn, text) {
  fileTexts.set(fn, text);
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
function pickTitleLine(s) {
  const fn = s.behaviorHints && s.behaviorHints.filename;
  if (fn) return String(fn);
  const m = [s.description, s.title].map((v) => String(v || '').match(/(?:📄|📁|📂|🎞️?|🎬|💿)\s*([^\n]+)/)).find(Boolean);
  if (m) return m[1].replace(/\s+[\/|]\s+.*$/, '').trim();
  const t = String(s.title || s.description || '').split('\n')[0];
  return t || String(s.name || '').split('\n')[0] || '';
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

const SUB_MARK = new Set(['sub', 'subs', 'subbed', 'subtitle', 'subtitles', 'subtitled', 'softsub', 'softsubs']);
const HARD_MARK = new Set(['hardsub', 'hardsubs', 'hardsubbed', 'hardcoded', 'hardcode', 'hc']);
const MULTI_TOK = new Set(['multi', 'msub', 'msubs', 'multisub', 'multisubs', 'multisubtitle', 'multisubtitles',
  'multiaudio', 'multilang', 'multilanguage']);
const DUAL_CTX = new Set(['audio', 'sub', 'subs', 'subtitle', 'subtitles', 'lang', 'language', 'languages']);
const CUT_RE = /^(?:(?:19|20)\d{2}|\d{3,4}p|s\d{1,2}e\d{1,3})$/;

const tokenize = (line) =>
  String(line || '').toLowerCase().replace(/[^\p{L}\p{M}\p{N}]+/gu, ' ').trim().split(' ').filter(Boolean);

const langOfToken = (t, weak) => STRONG[t] || (weak ? WEAK[t] : '') || '';

function langMatches(code, lang) {
  const c = String(code || '').toLowerCase().split(/[-_]/)[0];
  return STRONG[c] === lang || WEAK[c] === lang;
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
const RANK = { real: 6, sub: 5, addon: 5, audio: 5, hard: 4, multi: 3, flag: 3, forced: 2, hardx: 1, claimed: 1, realno: 1, none: 1 };

// Anseb-style weighting: a release that really carries the language (embedded = +35, unconfirmed
// "multi"/flag = +10) is ranked together with the resolution instead of strictly after it.
// Set EMB_WEIGHT to 0 to go back to pure resolution-first ordering.
const EMB_WEIGHT = 1;
const RES_SCORE = { 2160: 40, 1080: 30, 720: 15, 480: 5, 0: 0 };
const EMB_BONUS = { real: 50, sub: 35, addon: 35, audio: 35, hard: 28, multi: 10, flag: 10, forced: 5, hardx: 3, claimed: 0, realno: 0, none: 0 };
const rankScore = (res, verdict) => (RES_SCORE[res] || 0) + EMB_WEIGHT * (EMB_BONUS[verdict] || 0);

/* ------------------------------------------------------------------ */
/* Fetching and building streams                                       */
/* ------------------------------------------------------------------ */

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

async function fetchAllStreams(sources, type, id, debrid, key) {
  const tail = '/stream/' + type + '/' + encodeURIComponent(id) + '.json';
  const tasks = sources.map(async (src) => {
    let base = safeUrl(src.url);
    if (!base) return [];
    if (debrid && key && /torrentio/i.test(base)) base = withDebrid(base, debrid, key);
    try {
      const d = await getJSON(base + tail, null, 10000);
      return (Array.isArray(d.streams) ? d.streams : []).map((s) => Object.assign({}, s, { _source: src.name }));
    } catch (e) { return []; }
  });
  return (await Promise.all(tasks)).flat();
}

/* ------------------------------------------------------------------ */
/* Real verification: read the track list from the video file itself   */
/* ------------------------------------------------------------------ */
/*
  Names are only hints ("Multi subs" may or may not contain Arabic). For releases that are already
  cached on a debrid service we download the first ~1 MB of the MKV (HTTP Range request) and read
  the Matroska "Tracks" header: every subtitle track with its language code, name, codec and
  forced flag. That is the file's own list, so the answer is certain, not a guess.
    yes     a non-forced subtitle track in the user's language exists
    forced  only forced (signs/foreign parts) track(s) in that language
    no      the file has no subtitle track in that language
    unknown could not read it (not MKV, MP4 with moov at the end, timeout, host refused ...)
  Hard-coded (burned-in) subtitles are pictures inside the video and can never be detected this way.
*/

const PROBE_MAX = 1536 * 1024;   // never download more than this per file
const PROBE_WAIT = 6000;         // how long a stream request waits for probes (they keep running and fill the cache)
const MAX_PROBE = 8;             // files probed per request
const CACHED_RE = /\+\]|⚡|cached|instant/i;
const fileProbe = new Map();     // filename -> 'yes' | 'no' | 'forced' (used by the subtitles endpoint)

function ebmlId(b, p) {
  const f = b[p];
  if (f === undefined) return null;
  const n = f >= 0x80 ? 1 : f >= 0x40 ? 2 : f >= 0x20 ? 3 : f >= 0x10 ? 4 : 0;
  if (!n || p + n > b.length) return null;
  let v = 0;
  for (let i = 0; i < n; i++) v = v * 256 + b[p + i];
  return { id: v, len: n };
}
function ebmlSize(b, p) {
  const f = b[p];
  if (f === undefined) return null;
  let n = 1, m = 0x80;
  while (n <= 8 && !(f & m)) { n++; m >>= 1; }
  if (n > 8 || p + n > b.length) return null;
  let v = f & (m - 1), ones = (f & (m - 1)) === m - 1;
  for (let i = 1; i < n; i++) { v = v * 256 + b[p + i]; if (b[p + i] !== 0xff) ones = false; }
  return { size: ones ? -1 : v, len: n };
}
const ebmlUint = (b, s, e) => { let v = 0; for (let i = s; i < e; i++) v = v * 256 + b[i]; return v; };
const ebmlStr = (b, s, e) => b.toString('utf8', s, e).replace(/\0+$/, '').trim();

function* ebmlKids(b, s, e) {
  let p = s;
  while (p < e) {
    const i = ebmlId(b, p); if (!i) return;
    const z = ebmlSize(b, p + i.len); if (!z || z.size < 0) return;
    const ds = p + i.len + z.len;
    yield { id: i.id, ds, de: Math.min(e, ds + z.size) };
    p = ds + z.size;
  }
}

function readTracks(b, s, e) {
  const out = [];
  for (const k of ebmlKids(b, s, e)) {
    if (k.id !== 0xAE) continue;                       // TrackEntry
    const t = { type: 0, lang: 'eng', bcp: '', name: '', codec: '', forced: false };   // Matroska default language = eng
    for (const f of ebmlKids(b, k.ds, k.de)) {
      if (f.id === 0x83) t.type = ebmlUint(b, f.ds, f.de);              // TrackType (17 = subtitle)
      else if (f.id === 0x22B59C) t.lang = ebmlStr(b, f.ds, f.de);      // Language (ISO 639-2)
      else if (f.id === 0x22B59D) t.bcp = ebmlStr(b, f.ds, f.de);       // LanguageBCP47
      else if (f.id === 0x536E) t.name = ebmlStr(b, f.ds, f.de);         // TrackName
      else if (f.id === 0x86) t.codec = ebmlStr(b, f.ds, f.de);          // CodecID
      else if (f.id === 0x55AA) t.forced = ebmlUint(b, f.ds, f.de) === 1; // FlagForced
    }
    if (/\bforced\b/i.test(t.name)) t.forced = true;
    if (t.type === 17) out.push(t);
  }
  return out;
}

// state: need (more bytes required) | bad (not Matroska / no Tracks before the first Cluster) | done
function parseMkvTracks(b) {
  const h = ebmlId(b, 0);
  if (!h) return { state: b.length < 4 ? 'need' : 'bad' };
  if (h.id !== 0x1A45DFA3) return { state: 'bad' };           // EBML header
  const hs = ebmlSize(b, h.len);
  if (!hs || hs.size < 0) return { state: hs ? 'bad' : 'need' };
  let p = h.len + hs.len + hs.size;
  const sg = ebmlId(b, p);
  if (!sg) return { state: 'need' };
  if (sg.id !== 0x18538067) return { state: 'bad' };          // Segment
  const ss = ebmlSize(b, p + sg.len);
  if (!ss) return { state: 'need' };
  p += sg.len + ss.len;
  for (;;) {
    const i = ebmlId(b, p);
    if (!i) return { state: 'need' };
    const z = ebmlSize(b, p + i.len);
    if (!z) return { state: 'need' };
    if (i.id === 0x1F43B675 || z.size < 0) return { state: 'bad' };   // Cluster reached without Tracks
    const ds = p + i.len + z.len;
    if (i.id === 0x1654AE6B) {                                         // Tracks
      if (ds + z.size > b.length) return { state: 'need' };
      return { state: 'done', tracks: readTracks(b, ds, ds + z.size) };
    }
    p = ds + z.size;
  }
}

const trackIsLang = (t, lang) =>
  langMatches(t.bcp || t.lang, lang) || tokenize(t.name).some((w) => STRONG[w] === lang);
const CODEC_NAMES = { 'S_TEXT/UTF8': 'SRT', 'S_TEXT/ASS': 'ASS', 'S_TEXT/SSA': 'SSA', 'S_TEXT/WEBVTT': 'VTT', 'S_HDMV/PGS': 'PGS', 'S_VOBSUB': 'VobSub' };

function judgeTracks(tracks, lang) {
  const mine = tracks.filter((t) => trackIsLang(t, lang));
  const full = mine.filter((t) => !t.forced);
  const pick = full[0] || mine[0];
  return {
    state: full.length ? 'yes' : mine.length ? 'forced' : 'no',
    total: tracks.length,
    codec: pick ? (CODEC_NAMES[pick.codec] || pick.codec.replace(/^S_/, '')) : '',
  };
}

async function probeFile(url, lang) {
  const ck = sha('probe|' + lang + '|' + url);
  const hit = recall(ck, 24 * 3600 * 1000);
  if (hit) return hit;
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 9000);
  try {
    let cur = url, r;
    for (let hops = 0; ; hops++) {
      const u = new URL(cur);
      if (!protoOk(u.protocol)) throw new Error('https only');
      await assertPublicHost(u.hostname);
      r = await fetch(u.href, {
        headers: { 'User-Agent': UA, 'Range': 'bytes=0-' + (PROBE_MAX - 1) },
        redirect: 'manual',
        signal: ctrl.signal,
      });
      if (r.status >= 300 && r.status < 400) {
        const loc = r.headers.get('location');
        try { await r.body.cancel(); } catch (e) { /* ignore */ }
        if (!loc || hops >= 4) throw new Error('bad redirect');
        cur = new URL(loc, u).href;
        continue;
      }
      break;
    }
    if (!r.ok || !r.body) throw new Error('HTTP ' + r.status);

    const reader = r.body.getReader();
    const chunks = [];
    let total = 0, next = 128 * 1024, result = null;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (value) { chunks.push(value); total += value.length; }
        if (done || total >= next || total >= PROBE_MAX) {
          const p = parseMkvTracks(Buffer.concat(chunks));
          if (p.state === 'done') { result = judgeTracks(p.tracks, lang); break; }
          if (p.state === 'bad' || done || total >= PROBE_MAX) break;
          next *= 3;
        }
      }
    } finally { try { await reader.cancel(); } catch (e) { /* ignore */ } }
    return result ? remember(ck, result, 1000) : { state: 'unknown' };
  } finally { clearTimeout(timer); }
}

// Combine what the name suggested with what the file really contains.
function finalVerdict(v, pr) {
  if (!pr) return v;
  if (pr.state === 'yes') return 'real';
  if (pr.state === 'forced') return 'forced';
  if (pr.state === 'no') {
    if (v === 'sub') return 'claimed';                       // name says it, the file does not have it
    if (v === 'multi' || v === 'flag' || v === 'hardx' || v === 'none') return 'realno';
  }
  return v;
}

async function buildStreams(rawList, opts) {
  const { lang, debrid, ext } = opts;
  const L = LANGS[lang];
  const badge = debrid && DEBRID[debrid] ? ' [' + DEBRID[debrid] + ']' : '';
  const seen = new Set();
  const recs = [];

  // pass 1: parse every stream and guess from the text
  for (const s of rawList) {
    if (!s || (!s.url && !s.infoHash)) continue;

    const dk = s.infoHash
      ? 'h|' + String(s.infoHash).toLowerCase() + '|' + (s.fileIdx == null ? '' : s.fileIdx)
      : 'u|' + s.url;
    if (seen.has(dk)) continue;
    seen.add(dk);

    const bh = s.behaviorHints || {};
    const fn = bh.filename ? String(bh.filename) : '';
    const text = [s.name, s.title, s.description].filter(Boolean).join('\n');
    const full = text + '\n' + fn;

    const info = parseRelease(full);
    const verdict = subVerdict(detectSubs(full, lang, s.subtitles));
    if (fn) rememberFile(fn, text);
    recs.push({ s, bh, fn, full, info, verdict, probe: null });
  }

  // pass 2: verify the uncertain ones by reading the real file (cached debrid links only,
  // so nothing is ever added to the user's debrid account by this check)
  let pending = false;
  if (opts.probe !== false) {
    const prio = { multi: 0, flag: 0, hardx: 0, none: 1, sub: 2 };
    const cands = recs
      .filter((r) => r.s.url && CACHED_RE.test(String(r.s.name || '')) && prio[r.verdict] !== undefined)
      .sort((a, b) => prio[a.verdict] - prio[b.verdict] || b.info.res - a.info.res || b.info.seeders - a.info.seeders)
      .slice(0, MAX_PROBE);
    if (cands.length) {
      let timedOut = false, timer;
      const jobs = cands.map(async (r) => {
        const pr = await probeFile(r.s.url, lang).catch(() => ({ state: 'unknown' }));
        r.probe = pr;
        if (r.fn && pr.state !== 'unknown') fileProbe.set(r.fn, pr.state);
      });
      const wait = new Promise((ok) => { timer = setTimeout(() => { timedOut = true; ok(); }, PROBE_WAIT); });
      await Promise.race([Promise.allSettled(jobs).then(() => clearTimeout(timer)), wait]);
      pending = timedOut;
    }
  }

  // pass 3: render
  const items = [];
  for (const r of recs) {
    const { s, bh, fn, info } = r;
    const verdict = finalVerdict(r.verdict, r.probe);

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

    const pr = r.probe || {};
    const extNote = ext ? ' · external will load' : '';
    const subLines = {
      real:    '✅ ' + L.flag + ' ' + L.name + ' subs CONFIRMED inside the file' +
               (pr.codec || pr.total ? ' (' + [pr.codec, pr.total ? pr.total + ' sub tracks' : ''].filter(Boolean).join(' · ') + ')' : ''),
      forced:  '🔸 ' + L.flag + ' ' + L.name + ' forced subs only (inside the file)' + extNote,
      claimed: '⚠️ Name says ' + L.name + ' subs but the file has none' + extNote,
      realno:  '🚫 File checked: no ' + L.name + ' subs inside' + extNote,
      sub:   '💬 ' + L.flag + ' ' + L.name + ' subs embedded',
      addon: '💬 ' + L.flag + ' ' + L.name + ' subs provided',
      hard:  '🔒 ' + L.flag + ' ' + L.name + ' hardcoded subs',
      audio: '🗣️ ' + L.flag + ' ' + L.name + ' audio/tag',
      multi: '💬 Multi subs/audio (may include ' + L.name + ')',
      hardx: '🔒 Hardcoded subs (language unknown)',
      flag:  '🌐 ' + L.flag + ' ' + L.name + ' tag',
      none:  ext ? '🚫 No ' + L.name + ' subs found · external will load' : '🚫 No ' + L.name + ' subs found',
    };

    const lines = ['📁 ' + title];
    if (q3.length) lines.push(q3.join(' '));
    if (q4.length) lines.push(q4.join(' '));
    if (q5.length) lines.push(q5.join(' '));
    lines.push(subLines[verdict]);

    const o = {
      name: head + badge + (verdict === 'real' ? ' ' + L.flag + '✅' : ''),
      description: lines.join('\n'),
      behaviorHints: Object.assign({}, bh, { bingeGroup: 'stremify-' + (s._source || '') + '-' + info.res }),
    };
    o.title = o.description; // older Stremio clients read "title"

    if (s.url) o.url = s.url;
    else {
      o.infoHash = s.infoHash;
      if (s.fileIdx != null) o.fileIdx = s.fileIdx;
      if (Array.isArray(s.sources)) o.sources = s.sources;
    }
    if (Array.isArray(s.subtitles)) o.subtitles = s.subtitles;

    items.push({ o, res: info.res, rank: RANK[verdict], score: rankScore(info.res, verdict), seeders: info.seeders, size: info.size });
  }

  items.sort((a, b) => b.score - a.score || b.res - a.res || b.rank - a.rank || b.seeders - a.seeders || b.size - a.size);
  const out = items.map((x) => x.o);
  out.pending = pending;   // not an index property, so it never reaches the JSON
  return out;
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
      probe: c.probe !== false,
    };
  } catch (e) { return {}; }
}

function buildManifest() {
  return {
    id: 'com.stremify.addon',
    version: '6.1.0',
    name: 'Stremify',
    description: 'Multi-source stream addon that detects embedded subtitles for your preferred language.',
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
  }, headers));
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

function sendHtml(res, data) {
  res.writeHead(200, {
    'Content-Type': MIME['.html'],
    'Cache-Control': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
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
    const raw = await fetchAllStreams(sources, type, id, debrid, key);
    const list = await buildStreams(raw, { lang, debrid, ext, probe: cfg.probe !== false });
    const out = { streams: list };
    // never cache empty/failed results, nor a list whose file checks are still running
    if (out.streams.length && !list.pending) remember(cacheKey, out);
    return send(res, 200, out);
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

  // The chosen file already carries the language -> no external subtitle needed
  if (fn) {
    const checked = fileProbe.get(fn);   // result of reading the real file, if we did
    if (checked === 'yes') return send(res, 200, { subtitles: [] });
    if (checked !== 'no' && checked !== 'forced') {
      const r = detectSubs((fileTexts.get(fn) || '') + '\n' + fn, lang, null);
      if (r.sub || r.audio || r.hard) return send(res, 200, { subtitles: [] });
    }
  }

  const cacheKey = sha(['subs', lang, type, id].join('|'));
  const cached = recall(cacheKey, 30 * 60 * 1000);
  if (cached) return send(res, 200, cached);

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
    return send(res, 200, out);
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

  const m1 = pathname.match(/^\/c\/([\w-]+)\/manifest\.json$/);
  if (m1) return send(res, 200, buildManifest());

  const m2 = pathname.match(/^\/c\/([\w-]+)\/stream\/(movie|series)\/([^/]+)\.json$/);
  if (m2) {
    const id = safeDecode(m2[3]);
    if (!id) return send(res, 400, { error: 'bad id' });
    return handleStreams(res, m2[1], m2[2], id);
  }

  const m3 = pathname.match(/^\/c\/([\w-]+)\/subtitles\/(movie|series)\/([^/]+?)(?:\/([^/]*?))?\.json$/);
  if (m3) {
    const id = safeDecode(m3[3]);
    if (!id) return send(res, 400, { error: 'bad id' });
    return handleSubtitles(res, m3[1], m3[2], id, m3[4]);
  }

  return send(res, 404, { error: 'not found' });
}

if (require.main === module) {
  http.createServer((rq, rs) => handler(rq, rs).catch((e) => send(rs, 500, { error: e.message })))
    .listen(PORT, () => console.log('Stremify on ' + PORT));
}
module.exports = { handler, LANGS, DEBRID, detectSubs, subVerdict, buildStreams, encodeConfig, decodeConfig, parseMkvTracks, judgeTracks, probeFile };
