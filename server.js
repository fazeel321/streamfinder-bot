// StreamFinder server - multi Twitch keys via admin panel - Node 18+
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(line => {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.*?)\s*$/);
    if (m) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch (e) {}

const DATA_DIR = process.env.DATA_DIR || __dirname;
try { fs.mkdirSync(DATA_DIR, { recursive: true }); } catch (e) {}

const ADMIN_ID = (process.env.ADMIN_ID || '').trim().toLowerCase();
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const PORT = process.env.PORT || 3000;
const REDIRECT_URI = process.env.TWITCH_REDIRECT_URI || ('http://localhost:' + PORT + '/auth/callback');
const DEFAULT_MAX_SUB = 10;

const USERS_FILE = path.join(DATA_DIR, 'users.json');
let users = {};
try { users = JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); } catch (e) { users = {}; }
const saveUsers = () => fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));

function hashPw(pw, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString('hex') };
}
function checkPw(u, pw) {
  const h = crypto.scryptSync(pw, u.salt, 64);
  const b = Buffer.from(u.hash, 'hex');
  return b.length === h.length && crypto.timingSafeEqual(b, h);
}

const existingAdmin = Object.keys(users).find(k => users[k].role === 'admin');
if (ADMIN_ID && ADMIN_PASSWORD) {
  if (existingAdmin && existingAdmin !== ADMIN_ID) {
    console.log('Ignoring ADMIN_ID "' + ADMIN_ID + '": admin "' + existingAdmin + '" already exists.');
  } else {
    const cur = users[ADMIN_ID];
    if (!cur || cur.role !== 'admin' || cur.disabled || !checkPw(cur, ADMIN_PASSWORD)) {
      users[ADMIN_ID] = { ...hashPw(ADMIN_PASSWORD), role: 'admin', disabled: false, created: (cur && cur.created) || Date.now() };
      saveUsers();
      console.log('Admin account "' + ADMIN_ID + '" ready.');
    }
  }
}
const hasAdmin = () => Object.values(users).some(u => u.role === 'admin');
if (!hasAdmin()) console.log('\n*** No admin yet. Open http://localhost:' + PORT + ' to create one.\n');

const SESSION_MS = 12 * 60 * 60 * 1000;
const sessions = new Map();
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(p => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  });
  return out;
}
function currentUser(req) {
  const token = parseCookies(req).sid;
  const s = token && sessions.get(token);
  if (!s) return null;
  if (s.exp < Date.now()) { sessions.delete(token); return null; }
  const u = users[s.id];
  if (!u || u.disabled) { sessions.delete(token); return null; }
  return { id: s.id, role: u.role, canCreate: u.role === 'admin' || !!u.canCreate };
}
function dropSessionsOf(id) {
  for (const [t, s] of sessions) if (s.id === id) sessions.delete(t);
}
const attempts = new Map();

const SAVED_FILE = path.join(DATA_DIR, 'saved.json');
let saved = {};
try { saved = JSON.parse(fs.readFileSync(SAVED_FILE, 'utf8')); } catch (e) { saved = {}; }
const seen = new Set(Object.keys(saved));
function persist() {
  try { fs.writeFileSync(SAVED_FILE, JSON.stringify(saved, null, 2)); } catch (e) { console.log('saved.json write failed:', e.message); }
}

const KEYS_FILE = path.join(DATA_DIR, 'keys.json');
let twitchKeys = [];
try {
  const raw = JSON.parse(fs.readFileSync(KEYS_FILE, 'utf8'));
  if (Array.isArray(raw)) twitchKeys = raw;
} catch (e) { twitchKeys = []; }
const saveKeys = () => {
  try { fs.writeFileSync(KEYS_FILE, JSON.stringify(twitchKeys, null, 2)); } catch (e) { console.log('keys.json write failed:', e.message); }
};

async function getKeyToken(k) {
  if (k.token && k.tokenExpiry && Date.now() < k.tokenExpiry) return k.token;
  const r = await fetch('https://id.twitch.tv/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ client_id: k.clientId, client_secret: k.clientSecret, grant_type: 'client_credentials' })
  });
  const j = await r.json();
  if (!r.ok) throw new Error('Key "' + k.name + '" rejected: ' + (j.message || r.status));
  k.token = j.access_token;
  k.tokenExpiry = Date.now() + (j.expires_in - 300) * 1000;
  saveKeys();
  return k.token;
}

let rrIndex = 0;
function pickKey() {
  if (!twitchKeys.length) throw new Error('No Twitch keys configured. Add one in the admin panel.');
  const k = twitchKeys[rrIndex % twitchKeys.length];
  rrIndex++;
  return k;
}

async function helixWith(k, p) {
  const t = await getKeyToken(k);
  const r = await fetch('https://api.twitch.tv/helix/' + p, {
    headers: { 'Client-Id': k.clientId, 'Authorization': 'Bearer ' + t }
  });
  if (!r.ok) {
    if (r.status === 401) {
      k.token = null; k.tokenExpiry = 0; saveKeys();
      const t2 = await getKeyToken(k);
      const r2 = await fetch('https://api.twitch.tv/helix/' + p, {
        headers: { 'Client-Id': k.clientId, 'Authorization': 'Bearer ' + t2 }
      });
      if (!r2.ok) throw new Error('Twitch API error ' + r2.status + ' (key ' + k.name + ')');
      return r2.json();
    }
    throw new Error('Twitch API error ' + r.status + ' (key ' + k.name + ')');
  }
  return r.json();
}

async function helix(p) {
  const tried = new Set();
  for (let attempt = 0; attempt < Math.max(1, twitchKeys.length); attempt++) {
    const k = pickKey();
    if (tried.has(k.id)) continue;
    tried.add(k.id);
    try { return await helixWith(k, p); }
    catch (e) {
      if (attempt === twitchKeys.length - 1) throw e;
      console.log('Key failed, trying next:', e.message);
    }
  }
  throw new Error('All Twitch keys failed');
}

const TOKENS_FILE = path.join(DATA_DIR, 'tokens.json');
let oauthTokens = null;
try { oauthTokens = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8')); } catch (e) { oauthTokens = null; }
const saveTokens = () => {
  try { fs.writeFileSync(TOKENS_FILE, JSON.stringify(oauthTokens, null, 2)); } catch (e) { console.log('tokens.json write failed:', e.message); }
};

function activeOauthKey() {
  if (!oauthTokens || !oauthTokens.keyId) return null;
  return twitchKeys.find(k => k.id === oauthTokens.keyId) || null;
}

async function refreshUserTokenIfNeeded() {
  if (!oauthTokens) return null;
  if (oauthTokens.expires_at && Date.now() < oauthTokens.expires_at - 60000) return oauthTokens.access_token;
  const k = activeOauthKey();
  if (!k || !oauthTokens.refresh_token) return null;
  try {
    const r = await fetch('https://id.twitch.tv/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: k.clientId,
        client_secret: k.clientSecret,
        grant_type: 'refresh_token',
        refresh_token: oauthTokens.refresh_token
      })
    });
    const j = await r.json();
    if (!r.ok) throw new Error(j.message || 'refresh failed');
    oauthTokens = {
      access_token: j.access_token,
      refresh_token: j.refresh_token || oauthTokens.refresh_token,
      expires_at: Date.now() + (j.expires_in - 60) * 1000,
      scope: j.scope || oauthTokens.scope,
      keyId: k.id
    };
    saveTokens();
    console.log('User token refreshed.');
    return oauthTokens.access_token;
  } catch (e) {
    console.log('User token refresh failed:', e.message);
    return null;
  }
}

async function helixUser(p) {
  const t = await refreshUserTokenIfNeeded();
  const k = activeOauthKey();
  if (!t || !k) throw new Error('No valid user token. Connect Twitch in the admin panel.');
  const r = await fetch('https://api.twitch.tv/helix/' + p, {
    headers: { 'Client-Id': k.clientId, 'Authorization': 'Bearer ' + t }
  });
  if (!r.ok) throw new Error('Twitch user API error ' + r.status);
  return r.json();
}

const followersCache = new Map();
async function getFollowers(broadcasterId) {
  const cached = followersCache.get(broadcasterId);
  if (cached && Date.now() - cached.ts < 10 * 60 * 1000) return cached.count;
  const j = await helixUser('channels/followers?first=1&broadcaster_id=' + encodeURIComponent(broadcasterId));
  const count = j.total || 0;
  followersCache.set(broadcasterId, { count, ts: Date.now() });
  return count;
}

let searching = Promise.resolve();

async function search(q, who) {
  const minV = +q.minv || 0;
  const maxV = +q.maxv || Infinity;
  const maxA = +q.maxa || Infinity;
  const maxF = +q.maxf || Infinity;
  const target = +q.target || 20;
  const cats = (q.cats || '').split(',').map(s => s.trim()).filter(Boolean);
  const langs = (q.langs || '').split(',').map(s => s.trim().toLowerCase()).filter(l => /^[a-z]{2,5}$/.test(l)).slice(0, 20);
  const langParam = langs.map(l => '&language=' + encodeURIComponent(l)).join('');

  const needFollowers = isFinite(maxF) && maxF > 0;
  if (needFollowers && !oauthTokens) throw new Error('Followers filter needs Twitch login. Connect it in the admin panel.');

  let gameIds;
  if (cats.length) {
    gameIds = (await helix('games?' + cats.map(c => 'name=' + encodeURIComponent(c)).join('&'))).data.map(g => g.id);
  } else {
    gameIds = (await helix('games/top?first=20')).data.map(g => g.id);
  }

  const results = [];
  for (const gid of gameIds) {
    if (results.length >= target) break;
    let cursor = '';
    for (let page = 0; page < 40 && results.length < target; page++) {
      const resp = await helix('streams?first=100&game_id=' + gid + langParam + (cursor ? '&after=' + cursor : ''));
      const streams = resp.data;
      if (!streams.length) break;
      cursor = resp.pagination && resp.pagination.cursor;

      const cand = streams.filter(s => s.viewer_count >= minV && s.viewer_count <= maxV && !seen.has(s.user_id));
      if (cand.length) {
        const users_ = (await helix('users?' + cand.map(s => 'id=' + s.user_id).join('&'))).data;
        for (const s of cand) {
          if (results.length >= target) break;
          const u = users_.find(x => x.id === s.user_id);
          if (!u) continue;
          const age = Math.floor((Date.now() - new Date(u.created_at)) / 864e5);
          if (age > maxA) continue;

          let fcount = 0;
          if (needFollowers) {
            try { fcount = await getFollowers(s.user_id); } catch (e) { continue; }
            if (fcount > maxF) continue;
          }

          seen.add(s.user_id);
          const rec = {
            name: s.user_name, login: s.user_login, game: s.game_name,
            lang: s.language || '', viewers: s.viewer_count, ageDays: age,
            followers: fcount || null, by: who
          };
          saved[s.user_id] = rec;
          results.push(rec);
        }
        persist();
      }
      if (streams[streams.length - 1].viewer_count < minV) break;
      if (!cursor) break;
    }
  }
  return results;
}

const ID_RE = /^[a-z0-9_.-]{3,32}$/;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 10000) { reject(new Error('Body too large')); req.destroy(); } });
    req.on('end', () => { try { resolve(data ? JSON.parse(data) : {}); } catch (e) { reject(new Error('Bad JSON')); } });
    req.on('error', reject);
  });
}
function sendPage(res, file) {
  fs.readFile(path.join(__dirname, file), (err, data) => {
    if (err) { res.writeHead(404); return res.end(file + ' not found'); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(data);
  });
}

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const p = url.pathname;
  const json = (code, obj, headers) => {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...(headers || {}) });
    res.end(JSON.stringify(obj));
  };
  const redirect = to => { res.writeHead(302, { Location: to }); res.end(); };

  try {
    const me = currentUser(req);

    if (req.method === 'GET' && p === '/login') return me ? redirect('/') : sendPage(res, 'login.html');
    if (req.method === 'GET' && p === '/admin') {
      if (!me) return redirect('/login');
      return me.canCreate ? sendPage(res, 'admin.html') : redirect('/');
    }
    if (req.method === 'GET' && p === '/') return me ? sendPage(res, 'index.html') : redirect('/login');

    if (req.method === 'GET' && p === '/auth/twitch') {
      if (!me) return redirect('/login');
      if (me.role !== 'admin') return redirect('/admin');
      const keyId = url.searchParams.get('keyId');
      const k = keyId ? twitchKeys.find(x => x.id === keyId) : twitchKeys[0];
      if (!k) return json(400, { error: 'No Twitch key available. Add one in the admin panel first.' });
      const state = crypto.randomBytes(16).toString('hex');
      res.writeHead(302, {
        Location: 'https://id.twitch.tv/oauth2/authorize?' + new URLSearchParams({
          client_id: k.clientId,
          redirect_uri: REDIRECT_URI,
          response_type: 'code',
          scope: 'moderator:read:followers',
          state
        }),
        'Set-Cookie': 'oauth_state=' + state + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=600; ' +
                      'oauth_key=' + k.id + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=600'
      });
      return res.end();
    }

    if (req.method === 'GET' && p === '/auth/callback') {
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const cookies = parseCookies(req);
      if (!code || !state || state !== cookies.oauth_state) return redirect('/admin?oauth=fail');
      const keyId = cookies.oauth_key;
      const k = twitchKeys.find(x => x.id === keyId);
      if (!k) return redirect('/admin?oauth=fail');
      const r = await fetch('https://id.twitch.tv/oauth2/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: k.clientId,
          client_secret: k.clientSecret,
          code,
          grant_type: 'authorization_code',
          redirect_uri: REDIRECT_URI
        })
      });
      const j = await r.json();
      if (!r.ok) { console.log('OAuth exchange failed:', j); return redirect('/admin?oauth=fail'); }
      oauthTokens = {
        access_token: j.access_token,
        refresh_token: j.refresh_token,
        expires_at: Date.now() + (j.expires_in - 60) * 1000,
        scope: j.scope,
        keyId: k.id
      };
      saveTokens();
      console.log('Twitch user token saved (key ' + k.name + ').');
      return redirect('/admin?oauth=ok');
    }

    if (!p.startsWith('/api/')) { res.writeHead(404); return res.end('Not found'); }

    if (req.method === 'POST' && !(req.headers['content-type'] || '').includes('application/json')) {
      return json(415, { error: 'JSON only' });
    }

    if (p === '/api/login' && req.method === 'POST') {
      const b = await readBody(req);
      const id = String(b.id || '').trim().toLowerCase();
      const pw = String(b.password || '');
      const key = req.socket.remoteAddress + '|' + id;
      const a = attempts.get(key) || { n: 0, until: 0 };
      if (a.until > Date.now()) return json(429, { error: 'Too many wrong tries. Wait 5 minutes.' });
      const u = users[id];
      const ok = u && !u.disabled && checkPw(u, pw);
      if (!ok) {
        a.n += 1;
        if (a.n >= 5) { a.until = Date.now() + 5 * 60 * 1000; a.n = 0; }
        attempts.set(key, a);
        return json(401, { error: 'Wrong ID or password.' });
      }
      attempts.delete(key);
      const sid = crypto.randomBytes(32).toString('hex');
      sessions.set(sid, { id, exp: Date.now() + SESSION_MS });
      return json(200, { ok: true, role: u.role }, {
        'Set-Cookie': 'sid=' + sid + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + (SESSION_MS / 1000)
      });
    }
    if (p === '/api/logout' && req.method === 'POST') {
      const t = parseCookies(req).sid;
      if (t) sessions.delete(t);
      return json(200, { ok: true }, { 'Set-Cookie': 'sid=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0' });
    }

    const ra = req.socket.remoteAddress || '';
    const fromThisComputer = ra === '127.0.0.1' || ra === '::1' || ra === '::ffff:127.0.0.1';
    if (p === '/api/setup-status') return json(200, { needsSetup: !hasAdmin() && fromThisComputer });
    if (p === '/api/setup' && req.method === 'POST') {
      if (hasAdmin()) return json(403, { error: 'Setup is already done.' });
      if (!fromThisComputer) return json(403, { error: 'The admin can only be created on the computer where the server runs.' });
      const b = await readBody(req);
      const id = String(b.id || '').trim().toLowerCase();
      const pw = String(b.password || '');
      if (!ID_RE.test(id)) return json(400, { error: 'ID must be 3-32 characters: letters, numbers, . _ -' });
      if (pw.length < 6) return json(400, { error: 'Password must be at least 6 characters.' });
      users[id] = { ...hashPw(pw), role: 'admin', disabled: false, created: Date.now() };
      saveUsers();
      console.log('Admin "' + id + '" created via setup.');
      const sid = crypto.randomBytes(32).toString('hex');
      sessions.set(sid, { id, exp: Date.now() + SESSION_MS });
      return json(200, { ok: true }, {
        'Set-Cookie': 'sid=' + sid + '; HttpOnly; SameSite=Strict; Path=/; Max-Age=' + (SESSION_MS / 1000)
      });
    }

    if (!me) return json(401, { error: 'Please log in.' });
    const isAdmin = me.role === 'admin';

    if (p === '/api/me') return json(200, { id: me.id, role: me.role, canCreate: me.canCreate });

    if (p === '/api/status') {
      return json(200, {
        keysCount: twitchKeys.length,
        keyConfigured: twitchKeys.length > 0,
        savedCount: seen.size,
        followersReady: !!(oauthTokens && activeOauthKey() &&
          (!oauthTokens.expires_at || Date.now() < oauthTokens.expires_at - 60000))
      });
    }
    if (p === '/api/saved') return json(200, { results: Object.values(saved) });

    if (p === '/api/search') {
      if (!twitchKeys.length) return json(400, { error: 'No Twitch keys configured. Ask admin to add one.' });
      const run = searching.then(() => search(Object.fromEntries(url.searchParams), me.id));
      searching = run.catch(() => {});
      try { return json(200, { results: await run }); }
      catch (e) { return json(400, { error: e.message }); }
    }

    if (p === '/api/keys' && req.method === 'GET') {
      if (!isAdmin) return json(403, { error: 'Admin only.' });
      const list = twitchKeys.map(k => ({
        id: k.id, name: k.name,
        clientIdPreview: k.clientId.slice(0, 6) + '...',
        clientSecretPreview: '****' + (k.clientSecret.slice(-4)),
        addedBy: k.addedBy, addedAt: k.addedAt,
        hasToken: !!(k.token && k.tokenExpiry && Date.now() < k.tokenExpiry)
      }));
      return json(200, {
        keys: list,
        oauth: oauthTokens ? {
          keyId: oauthTokens.keyId,
          scope: oauthTokens.scope,
          expires_at: oauthTokens.expires_at
        } : null
      });
    }

    if (p === '/api/keys' && req.method === 'POST') {
      if (!isAdmin) return json(403, { error: 'Admin only.' });
      const b = await readBody(req);
      const name = String(b.name || '').trim();
      const clientId = String(b.clientId || '').trim();
      const clientSecret = String(b.clientSecret || '').trim();
      if (!name || name.length > 60) return json(400, { error: 'Name required (max 60 chars).' });
      if (!clientId || clientId.length < 10) return json(400, { error: 'Client ID looks invalid.' });
      if (!clientSecret || clientSecret.length < 10) return json(400, { error: 'Client Secret looks invalid.' });
      try {
        const r = await fetch('https://id.twitch.tv/oauth2/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          body: new URLSearchParams({ client_id: clientId, client_secret: clientSecret, grant_type: 'client_credentials' })
        });
        const j = await r.json();
        if (!r.ok) return json(400, { error: 'Twitch rejected this key: ' + (j.message || r.status) });
      } catch (e) {
        return json(400, { error: 'Could not reach Twitch: ' + e.message });
      }
      const k = {
        id: crypto.randomBytes(8).toString('hex'),
        name, clientId, clientSecret,
        addedBy: me.id, addedAt: Date.now(),
        token: null, tokenExpiry: 0
      };
      twitchKeys.push(k);
      saveKeys();
      return json(200, { ok: true, id: k.id });
    }

    if (p === '/api/keys/delete' && req.method === 'POST') {
      if (!isAdmin) return json(403, { error: 'Admin only.' });
      const b = await readBody(req);
      const id = String(b.id || '');
      const i = twitchKeys.findIndex(k => k.id === id);
      if (i < 0) return json(404, { error: 'No such key.' });
      twitchKeys.splice(i, 1);
      saveKeys();
      if (oauthTokens && oauthTokens.keyId === id) { oauthTokens = null; saveTokens(); }
      return json(200, { ok: true });
    }

    if (p === '/api/auth/disconnect' && req.method === 'POST') {
      if (!isAdmin) return json(403, { error: 'Admin only.' });
      oauthTokens = null;
      saveTokens();
      followersCache.clear();
      return json(200, { ok: true });
    }

    if (p === '/api/reset') {
      if (!isAdmin) return json(403, { error: 'Admin only.' });
      if (req.method !== 'POST') return json(405, { error: 'POST only' });
      seen.clear(); saved = {}; persist();
      return json(200, { ok: true });
    }

    if (p === '/api/users' || p.startsWith('/api/users/')) {
      if (!me.canCreate) return json(403, { error: 'You are not allowed to manage IDs.' });
      const subsOf = id => Object.keys(users).filter(k => users[k].createdBy === id);
      const canManage = id => !!users[id] && (isAdmin ? true : users[id].createdBy === me.id);

      if (p === '/api/users' && req.method === 'GET') {
        const counts = {};
        Object.values(saved).forEach(s => { if (s.by) counts[s.by] = (counts[s.by] || 0) + 1; });
        const list = Object.entries(users)
          .filter(([id]) => isAdmin || users[id].createdBy === me.id)
          .map(([id, u]) => ({
            id, role: u.role, disabled: !!u.disabled, created: u.created,
            createdBy: u.createdBy || null,
            canCreate: u.role === 'admin' || !!u.canCreate,
            maxSub: u.maxSub == null ? DEFAULT_MAX_SUB : u.maxSub,
            subCount: subsOf(id).length,
            found: counts[id] || 0
          }));
        const mine = users[me.id];
        return json(200, {
          users: list,
          limit: isAdmin ? null : (mine.maxSub == null ? DEFAULT_MAX_SUB : mine.maxSub),
          used: subsOf(me.id).length
        });
      }

      if (p === '/api/users' && req.method === 'POST') {
        const b = await readBody(req);
        const id = String(b.id || '').trim().toLowerCase();
        const pw = String(b.password || '');
        if (!ID_RE.test(id)) return json(400, { error: 'ID must be 3-32 characters: letters, numbers, . _ -' });
        if (pw.length < 6) return json(400, { error: 'Password must be at least 6 characters.' });
        if (users[id]) return json(409, { error: 'This ID already exists.' });
        if (!isAdmin) {
          const limit = users[me.id].maxSub == null ? DEFAULT_MAX_SUB : users[me.id].maxSub;
          if (subsOf(me.id).length >= limit) return json(403, { error: 'Reached limit of ' + limit + ' IDs.' });
        }
        users[id] = { ...hashPw(pw), role: 'member', disabled: false, created: Date.now(), createdBy: me.id, canCreate: false, maxSub: DEFAULT_MAX_SUB };
        saveUsers();
        return json(200, { ok: true });
      }

      if (p === '/api/users/update' && req.method === 'POST') {
        const b = await readBody(req);
        const id = String(b.id || '').toLowerCase();
        if (!users[id]) return json(404, { error: 'No such user.' });
        if (!canManage(id) || (users[id].role === 'admin' && id !== me.id)) return json(403, { error: 'Not allowed.' });
        const u = users[id];
        if (typeof b.password === 'string') {
          if (b.password.length < 6) return json(400, { error: 'Password must be at least 6 characters.' });
          if (u.role === 'admin') return json(400, { error: 'Change admin password in .env.' });
          Object.assign(u, hashPw(b.password));
          dropSessionsOf(id);
        }
        if (typeof b.disabled === 'boolean') {
          if (id === me.id) return json(400, { error: 'You cannot disable yourself.' });
          u.disabled = b.disabled;
          if (b.disabled) dropSessionsOf(id);
        }
        if (typeof b.canCreate === 'boolean' || b.maxSub !== undefined) {
          if (!isAdmin) return json(403, { error: 'Only admin can change this.' });
          if (u.role === 'admin') return json(400, { error: 'Admin always can create.' });
          if (typeof b.canCreate === 'boolean') u.canCreate = b.canCreate;
          if (b.maxSub !== undefined) {
            const n = Math.floor(Number(b.maxSub));
            if (!(n >= 0 && n <= 1000)) return json(400, { error: 'Limit 0-1000.' });
            u.maxSub = n;
          }
        }
        saveUsers();
        return json(200, { ok: true });
      }

      if (p === '/api/users/delete' && req.method === 'POST') {
        const b = await readBody(req);
        const id = String(b.id || '').toLowerCase();
        if (!users[id]) return json(404, { error: 'No such user.' });
        if (id === me.id) return json(400, { error: 'You cannot delete yourself.' });
        if (users[id].role === 'admin') return json(400, { error: 'Admin cannot be deleted.' });
        if (!canManage(id)) return json(403, { error: 'Not allowed.' });
        const parent = users[id].createdBy || Object.keys(users).find(k => users[k].role === 'admin');
        subsOf(id).forEach(k => { users[k].createdBy = parent; });
        delete users[id];
        dropSessionsOf(id);
        saveUsers();
        return json(200, { ok: true });
      }
    }

    return json(404, { error: 'Not found' });
  } catch (e) {
    return json(500, { error: e.message });
