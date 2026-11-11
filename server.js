'use strict';
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const net = require('net');

const PORT = process.env.PORT || 3000;
const WEB = path.join(__dirname, 'public');
const UA = 'Stremify/6.3';
const ALLOW_PRIVATE = process.env.ALLOW_PRIVATE_SOURCES === '1';
const SUBS_PROVIDER = (process.env.SUBS_PROVIDER || 'https://opensubtitles-v3.strem.io').replace(/\/+$/, '');
const MAX_BYTES = 5 * 1024 * 1024;
const MAX_SOURCES = 8;

/* ------------------------------------------------------------------ */
/* Languages & Precision Matchers                                     */
/* ------------------------------------------------------------------ */

const LANGS = {
  en: { name: 'English',  flag: '🇬🇧', flags: ['🇬🇧', '🇺🇸'], two: ['en'],       words: ['english', 'eng'],
        subTags: ['esub', 'esubs', 'en-sub', 'english-sub'], audioTags: ['eng', 'english'] },
  ar: { name: 'Arabic',   flag: '🇸🇦', flags: ['🇸🇦', '🇦🇪', '🇪🇬', '🇶🇦', '🇰🇼', '🇲🇦'], two: ['ar'], words: ['arabic', 'ara', 'arab', 'arabe', 'عربي', 'عربى', 'عربية', 'العربية', 'ar-sub', 'arsub'],
        subTags: ['arsub', 'arsubs', 'ar-sub', 'arabic-sub', 'sub-ar', 'subarabic', 'vostar'], audioTags: ['ara', 'arabic', 'عربي'] },
  de: { name: 'German',   flag: '🇩🇪', flags: ['🇩🇪'],       two: ['de'],       words: ['german', 'ger', 'deu', 'deutsch', 'allemand'],
        subTags: ['german-sub', 'ger-sub', 'de-sub'], audioTags: ['ger', 'german', 'deutsch'] },
  fr: { name: 'French',   flag: '🇫🇷', flags: ['🇫🇷'],       two: ['fr'],       words: ['french', 'fre', 'fra', 'francais', 'français', 'truefrench'],
        subTags: ['vostfr', 'stfr', 'subfrench', 'vost', 'french-sub'], audioTags: ['vf', 'vff', 'vfq', 'vfi', 'vf2', 'french'] },
  es: { name: 'Spanish',  flag: '🇪🇸', flags: ['🇪🇸'],       two: ['es'],       words: ['spanish', 'spa', 'esp', 'espanol', 'español', 'castellano', 'latino'],
        subTags: ['vose', 'spanish-sub', 'spa-sub', 'es-sub'], audioTags: ['spa', 'spanish', 'espanol', 'latino'] },
  tr: { name: 'Turkish',  flag: '🇹🇷', flags: ['🇹🇷'],       two: ['tr'],       words: ['turkish', 'tur', 'türkçe', 'turkce'],
        subTags: ['turkce-sub', 'turkish-sub'], audioTags: ['tur', 'turkish', 'türkçe'] },
  hi: { name: 'Hindi',    flag: '🇮🇳', flags: ['🇮🇳'],       two: ['hi'],       words: ['hindi', 'hin'],
        subTags: ['hindi-sub'], audioTags: ['hin', 'hindi'] },
  ja: { name: 'Japanese', flag: '🇯🇵', flags: ['🇯🇵'],       two: ['ja', 'jp'], words: ['japanese', 'jpn', 'jap', '日本語'],
        subTags: ['japanese-sub', 'jp-sub'], audioTags: ['jpn', 'japanese', '日本語'] },
};

const DEBRID = {
  realdebrid: 'RD+',
  alldebrid:  'AD+',
  premiumize: 'PM+',
  torbox:     'TB+',
  debridlink: 'DL+',
};

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

const STRONG = Object.create(null);   
const WEAK = Object.create(null);     
const SUBTAG = Object.create(null);   
const AUDIOTAG = Object.create(null); 
for (const code of Object.keys(LANGS)) {
  const L = LANGS[code];
  L.words.forEach((w) => { STRONG[w.toLowerCase()] = code; });
  L.two.forEach((w) => { WEAK[w.toLowerCase()] = code; });
  L.subTags.forEach((w) => { SUBTAG[w.toLowerCase()] = code; });
  L.audioTags.forEach((w) => { AUDIOTAG[w.toLowerCase()] = code; });
}

const sha = (s) => crypto.createHash('sha1').update(s).digest('hex');
const b64u = (s) => Buffer.from(s).toString('base64url');
const ub64 = (s) => Buffer.from(s, 'base64url').toString('utf8');
const safeDecode = (s) => { try { return decodeURIComponent(s); } catch (e) { return null; } };

/* ------------------------------------------------------------------ */
/* Safe outgoing requests & File Header Probing                       */
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

async function fetchHead(url, bytes, ms, hops) {
  hops = hops || 0;
  const u = new URL(url);
  if (!protoOk(u.protocol)) throw new Error('https only');
  await assertPublicHost(u.hostname);
  const ctrl = new AbortController();
  const id = setTimeout(() => ctrl.abort(), ms || 7000);
  try {
    const r = await fetch(u.href, {
      headers: { 'User-Agent': UA, 'Range': 'bytes=0-' + (bytes - 1) },
      redirect: 'manual',
      signal: ctrl.signal,
    });
    if (r.status >= 300 && r.status < 400) {
      const loc = r.headers.get('location');
      if (!loc || hops >= 3) throw new Error('bad redirect');
      return await fetchHead(new URL(loc, u).href, bytes, ms, hops + 1);
    }
    if (r.status !== 200 && r.status !== 206) throw new Error('HTTP ' + r.status);
    if (!r.body) throw new Error('no body');
    const reader = r.body.getReader();
    const chunks = [];
    let got = 0;
    while (got < bytes) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value));
      got += value.length;
    }
    try { await reader.cancel(); } catch (e) {}
    return Buffer.concat(chunks).subarray(0, bytes);
  } finally { clearTimeout(id); }
}

async function probeFileHeadersForLang(videoUrl, lang) {
  if (!videoUrl || !videoUrl.startsWith('http')) return false;
  try {
    const buffer = await fetchHead(videoUrl, 1536000, 3000);
    const headerStr = buffer.toString('latin1').toLowerCase();
    const L = LANGS[lang];
    if (!L) return false;
    
    for (const code of L.two) {
      if (
        headerStr.includes(code) || 
        headerStr.includes('lang_' + code) || 
        headerStr.includes('\x00' + code + '\x00') ||
        headerStr.includes('language=' + code)
      ) {
        return true;
      }
    }
    for (const w of L.words) {
      if (headerStr.includes(w)) return true;
    }
    return false;
  } catch (e) {
    return false;
  }
}

/* ------------------------------------------------------------------ */
/* Cache                                                              */
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

const fileTexts = new Map();
function rememberFile(fn, text) {
  fileTexts.set(fn, text);
  if (fileTexts.size > 3000) fileTexts.delete(fileTexts.keys().next().value);
}

/* ------------------------------------------------------------------ */
/* Release parsing                                                    */
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

function pickTitleLine(s) {
  const fn = s.behaviorHints && s.behaviorHints.filename;
  if (fn) return String(fn);
  const desc = String(s.description || '');
  const m = desc.match(/(?:📄|📁|📂)\s*([^\n]+)/);
  if (m) return m[1].trim();
  const t = String(s.title || s.description || '').split('\n')[0];
  return t || String(s.name || '').split('\n')[0] || '';
}

/* ------------------------------------------------------------------ */
/* Ultra-Precise Subtitle Engine                                      */
/* ------------------------------------------------------------------ */

function detectSubs(text, lang, extSubs) {
  const L = LANGS[lang];
  const res = { sub: false, hard: false, audio: false, flag: false, addon: false, probed: false };
  if (!L) return res;
  
  const raw = String(text || '').toLowerCase();
  
  for (const st of L.subTags) {
    if (raw.includes(st)) {
      res.sub = true;
      break;
    }
  }

  const subKeywords = ['sub', 'subs', 'subbed', 'subtitle', 'subtitles', 'subtitled'];
  const hardKeywords = ['hardsub', 'hardsubs', 'hardcoded', 'hc', 'hard'];

  for (const word of L.words) {
    if (raw.includes(word)) {
      const hasSubContext = subKeywords.some(sk => raw.includes(sk));
      const hasHardContext = hardKeywords.some(hk => raw.includes(hk));

      if (hasHardContext) {
        res.hard = true;
      } else if (hasSubContext || raw.includes(word + '-sub') || raw.includes('sub-' + word)) {
        res.sub = true;
      } else {
        res.audio = true;
      }
    }
  }

  if (L.flags.some((f) => raw.includes(f))) {
    res.flag = true;
    res.sub = true;
  }

  if (Array.isArray(extSubs) && extSubs.some((x) => x && (x.lang === lang || x.lang === L.name || (x.lang && x.lang.toLowerCase().includes(lang))))) {
    res.addon = true;
  }

  return res;
}

function subVerdict(r) {
  if (r.hard) return 'hard';
  if (r.sub || r.probed) return 'sub';
  if (r.addon) return 'addon';
  if (r.audio) return 'audio';
  if (r.flag) return 'flag';
  return 'none';
}

const RANK = { hard: 6, sub: 5, addon: 5, audio: 4, flag: 3, none: 1 };

/* ------------------------------------------------------------------ */
/* Fetching and building streams                                      */
/* ------------------------------------------------------------------ */

const DEBRID_KEYS = /(?:^|[\/|])(?:realdebrid|alldebrid|premiumize|debridlink|torbox|offcloud|putio)=/i;

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

async function buildStreams(rawList, opts) {
  const { lang, debrid, ext, verify } = opts;
  const L = LANGS[lang] || LANGS['en'];
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
    const fn = bh.filename ? String(bh.filename) : '';
    const text = [s.name, s.title, s.description].filter(Boolean).join('\n');
    const full = text + '\n' + fn;

    const info = parseRelease(full);
    const detection = detectSubs(full, lang, s.subtitles);

    // Deep probing check if requested
    if (verify && !detection.sub && !detection.hard && s.url) {
      const isProbed = await probeFileHeadersForLang(s.url, lang);
      if (isProbed) {
        detection.probed = true;
      }
    }

    const verdict = subVerdict(detection);
    if (fn) rememberFile(fn, text);

    const titleSrc = pickTitleLine(s);
    const base = titleSrc.replace(/\.(mkv|mp4|avi|m4v|ts|wmv|mov)$/i, '');
    const title = base
      .replace(/[._]+/g, ' ')
      .replace(/\s+/g, ' ')
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

    // Cleaned output: Only Flag & Concise description
    const subLines = {
      hard:  '🔒 ' + L.flag + ' ' + L.name + ' hardcoded subs',
      sub:   '💬 ' + L.flag + ' ' + L.name + ' subs embedded',
      addon: '💬 ' + L.flag + ' ' + L.name + ' subs provided',
      audio: '🗣️ ' + L.flag + ' ' + L.name + ' audio',
      flag:  '🌐 ' + L.flag + ' ' + L.name + ' tag',
      none:  ext ? '🚫 No ' + L.name + ' subs found · external will load' : '🚫 No ' + L.name + ' subs found',
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
    o.title = o.description;

    if (s.url) o.url = s.url;
    else {
      o.infoHash = s.infoHash;
      if (s.fileIdx != null) o.fileIdx = s.fileIdx;
      if (Array.isArray(s.sources)) o.sources = s.sources;
    }
    if (Array.isArray(s.subtitles)) o.subtitles = s.subtitles;

    items.push({ o, res: info.res, rank: RANK[verdict], seeders: info.seeders, size: info.size });
  }

  items.sort((a, b) => b.res - a.res || b.rank - a.rank || b.seeders - a.seeders || b.size - a.size);
  return items.map((x) => x.o);
}

/* ------------------------------------------------------------------ */
/* Config and manifest                                                */
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
      verify: c.verify !== false || c.probe !== false,
    };
  } catch (e) { return {}; }
}

function buildManifest() {
  return {
    id: 'com.stremify.addon',
    version: '6.3.0',
    name: 'Stremify',
    description: 'Multi-source stream addon with universal file header probing and precise subtitle verification.',
    resources: ['stream', 'subtitles'],
    types: ['movie', 'series'],
    idPrefixes: ['tt'],
    catalogs: [],
    behaviorHints: { configurable: true, configurationRequired: false },
  };
}

/* ------------------------------------------------------------------ */
/* HTTP                                                               */
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
  const verify = cfg.verify !== false;

  if (!sources.length) return send(res, 200, { streams: [] });

  const cacheKey = sha(['streams', tok, type, id].join('|'));
  const cached = recall(cacheKey, 5 * 60 * 1000);
  if (cached) return send(res, 200, cached);

  try {
    const raw = await fetchAllStreams(sources, type, id, debrid, key);
    const streamsResult = await buildStreams(raw, { lang, debrid, ext, verify });
    const out = { streams: streamsResult };
    if (out.streams.length) remember(cacheKey, out);
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

  if (fn) {
    const r = detectSubs((fileTexts.get(fn) || '') + '\n' + fn, lang, null);
    if (r.sub || r.audio || r.hard) return send(res, 200, { subtitles: [] });
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
      .filter((x) => x && x.url && (x.lang === lang || x.lang === LANGS[lang].name))
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
    .listen(PORT, () => console.log('Stremify running on port ' + PORT));
}
module.exports = { handler, LANGS, DEBRID, detectSubs, subVerdict, buildStreams, encodeConfig, decodeConfig, probeFileHeadersForLang };
