/*
  kyleatwood.com backend (one Vercel Function).

  Routes (all via /api/site?action=...):
    GET  list     public   - active + sold listings (cached ~60s at the edge)
    GET  session  public   - { ok: true|false } is this browser logged in?
    POST login    public   - checks ADMIN_PASSWORD, starts a signed session, locks out guessing
    POST logout   admin    - ends the session
    POST save     admin    - create or update a listing / closing
    POST delete   admin    - delete a listing / closing
    POST upload   admin    - upload one photo to Supabase Storage

  Environment variables (Vercel -> Project -> Settings -> Environment Variables):
    ADMIN_PASSWORD             the password you type to log in (you choose it)
    SESSION_SECRET             a long random string (24+ characters) used to sign sessions
    SUPABASE_URL               https://xxxx.supabase.co
    SUPABASE_SECRET_KEY        the Supabase SECRET key, "sb_secret_..." (NEVER put this in the page).
                               (Older projects: the legacy service_role key works here too, under either name.)
*/
const crypto = require('crypto');

const COOKIE = 'kyle_admin';
const SESSION_MS = 12 * 60 * 60 * 1000;      // stay logged in 12 hours
const MAX_FAILS = 5;                          // wrong passwords allowed...
const WINDOW_MS = 15 * 60 * 1000;             // ...per 15 minutes, per visitor
const BUCKET = 'listing-photos';
const TYPES = ['Residential', 'Commercial RE', 'Business for Sale', 'Land', 'Investment'];
const STATUSES = ['active', 'pending', 'sold'];

/* ---------- small helpers ---------- */
function getEnv() {
  const e = {
    pw: process.env.ADMIN_PASSWORD,
    secret: process.env.SESSION_SECRET,
    url: process.env.SUPABASE_URL,
    key: process.env.SUPABASE_SECRET_KEY || process.env.SUPABASE_SERVICE_ROLE_KEY,
  };
  const missing = [];
  if (!e.pw) missing.push('ADMIN_PASSWORD');
  if (!e.secret || e.secret.length < 24) missing.push('SESSION_SECRET (24+ chars)');
  if (!e.url) missing.push('SUPABASE_URL');
  if (!e.key) missing.push('SUPABASE_SECRET_KEY');
  e.ok = missing.length === 0;
  e.missing = missing;
  return e;
}
const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
function safeEqual(a, b) {
  const x = crypto.createHash('sha256').update(String(a)).digest();
  const y = crypto.createHash('sha256').update(String(b)).digest();
  return crypto.timingSafeEqual(x, y);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function send(res, status, obj, cache) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', cache || 'no-store');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.end(JSON.stringify(obj));
}

async function readBody(req) {
  if (req.body !== undefined && req.body !== null) {
    if (typeof req.body === 'string') { try { return JSON.parse(req.body); } catch (e) { return null; } }
    if (Buffer.isBuffer(req.body)) { try { return JSON.parse(req.body.toString('utf8')); } catch (e) { return null; } }
    return req.body;
  }
  const chunks = []; let size = 0;
  for await (const c of req) { size += c.length; if (size > 5 * 1024 * 1024) return null; chunks.push(c); }
  try { return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (e) { return null; }
}

/* ---------- sessions (signed cookie, no database needed) ---------- */
function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach((p) => {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
function signToken(env, payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', env.secret).update(body).digest('base64url');
  return body + '.' + sig;
}
function verifyToken(env, token) {
  if (!token || token.indexOf('.') < 1) return null;
  const [body, sig] = token.split('.');
  const want = crypto.createHmac('sha256', env.secret).update(body).digest('base64url');
  const a = Buffer.from(sig), b = Buffer.from(want);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
    return p && p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}
const isAuthed = (req, env) => !!verifyToken(env, parseCookies(req)[COOKIE]);
function setSession(req, res, token, maxAgeSec) {
  const secure = (req.headers['x-forwarded-proto'] === 'https' || process.env.VERCEL) ? '; Secure' : '';
  res.setHeader('Set-Cookie', `${COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAgeSec}${secure}`);
}

/* ---------- Supabase (server-side only) ---------- */
async function sb(env, path, opts) {
  opts = opts || {};
  // New-style keys (sb_secret_...) are NOT JWTs and must go in the apikey header only.
  // Legacy keys (long JWTs starting "eyJ") are also sent as the Bearer token.
  const base = { apikey: env.key };
  if (/^eyJ/.test(env.key)) base.Authorization = 'Bearer ' + env.key;
  const headers = Object.assign(base, opts.headers || {});
  let body = opts.body;
  if (body !== undefined && !opts.raw) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(body); }
  const r = await fetch(env.url.replace(/\/$/, '') + path, { method: opts.method || 'GET', headers, body });
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { data = text; }
  return { ok: r.ok, status: r.status, data };
}

/* ---------- validation (only these fields are ever stored) ---------- */
function str(v, max) { return String(v == null ? '' : v).trim().slice(0, max); }
function cleanListing(l, env) {
  if (!l || typeof l !== 'object') return { error: 'Invalid listing.' };
  const type = str(l.type, 40);
  if (TYPES.indexOf(type) < 0) return { error: 'Choose a valid type.' };
  const address = str(l.address, 160), price = str(l.price, 40);
  if (!address || !price) return { error: 'Address and price are required.' };
  const agent = str(l.agent, 80);
  if (!agent) return { error: 'Listing agent is required. It is credited on the listing.' };
  const is_sold = l.is_sold === true;
  let status = is_sold ? 'sold' : str(l.status, 20);
  if (STATUSES.indexOf(status) < 0) status = 'active';
  const sold_date = str(l.sold_date, 10);
  if (sold_date && !/^\d{4}-\d{2}-\d{2}$/.test(sold_date)) return { error: 'Sold date must be a valid date.' };
  const image = str(l.image, 600);
  const ownStorage = env.url.replace(/\/$/, '') + '/storage/v1/object/public/' + BUCKET + '/';
  if (image && !(image.indexOf(ownStorage) === 0 || /^https:\/\/[^\s"'<>]+$/.test(image)) || /[\s"'<>]/.test(image)) return { error: 'Photo must be an https link or an uploaded photo.' };
  return {
    row: {
      is_sold, status, type,
      subtype: str(l.subtype, 80) || type,
      agent,
      brokerage: str(l.brokerage, 100) || 'ERA Martin & Associates',
      address, city: str(l.city, 80) || 'Chillicothe', zip: str(l.zip, 10), price,
      sold_date: sold_date || null,
      sqft: str(l.sqft, 20), acres: str(l.acres, 20), beds: str(l.beds, 20), baths: str(l.baths, 20), cap: str(l.cap, 20),
      description: str(l.description, 1200),
      image,
    },
  };
}
const SAFE_ID = /^[A-Za-z0-9_-]{6,64}$/;

function sniffImage(buf) {
  if (buf.length > 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { mime: 'image/jpeg', ext: 'jpg' };
  if (buf.length > 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return { mime: 'image/png', ext: 'png' };
  if (buf.length > 12 && buf.slice(0, 4).toString() === 'RIFF' && buf.slice(8, 12).toString() === 'WEBP') return { mime: 'image/webp', ext: 'webp' };
  return null;
}

/* ---------- the handler ---------- */
module.exports = async function handler(req, res) {
  try {
    const env = getEnv();
    const url = new URL(req.url, 'http://x');
    const action = (req.query && req.query.action) || url.searchParams.get('action') || '';
    const method = req.method;

    // Not configured yet: say so (privately in the logs, generically to the browser).
    if (!env.ok) {
      console.error('Backend not configured. Missing: ' + env.missing.join(', '));
      if (action === 'list') return send(res, 200, { listings: [], configured: false });
      if (action === 'session') return send(res, 200, { ok: false, configured: false });
      return send(res, 503, { error: 'not_configured' });
    }

    /* ----- public ----- */
    if (action === 'list' && (method === 'GET' || method === 'HEAD')) {
      const fresh = url.searchParams.get('fresh');
      const r = await sb(env, '/rest/v1/listings?select=*&order=created_at.desc&limit=500');
      if (!r.ok) { console.error('list failed', r.status, r.data); return send(res, 502, { error: 'unavailable' }); }
      // Browsers always re-check (so visitors never see stale listings);
      // Vercel's edge cache holds it for 60s so the database is not hit on every view.
      if (!fresh) res.setHeader('Vercel-CDN-Cache-Control', 'max-age=60, stale-while-revalidate=300');
      return send(res, 200, { listings: r.data || [], configured: true },
        fresh ? 'no-store' : 'public, max-age=0, must-revalidate');
    }
    if (action === 'session' && (method === 'GET' || method === 'HEAD')) return send(res, 200, { ok: isAuthed(req, env) });

    if (method !== 'POST') return send(res, 405, { error: 'method' });

    // Every POST must come from our own pages (CSRF defence, on top of SameSite=Strict).
    if (req.headers['x-requested-with'] !== 'kyle-admin') return send(res, 403, { error: 'forbidden' });

    if (action === 'login') {
      const ip = String(req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || '').split(',')[0].trim();
      const ipHash = sha(ip + '|' + env.secret);
      const since = new Date(Date.now() - WINDOW_MS).toISOString();
      const q = await sb(env, `/rest/v1/login_attempts?select=at&ip_hash=eq.${ipHash}&at=gte.${encodeURIComponent(since)}`);
      if (!q.ok || !Array.isArray(q.data)) { console.error('attempt check failed', q.status, q.data); return send(res, 503, { error: 'unavailable' }); }
      if (q.data.length >= MAX_FAILS) return send(res, 429, { error: 'locked' });
      const body = await readBody(req);
      const pwd = String((body && body.password) || '');
      if (!pwd || !safeEqual(pwd, env.pw)) {
        await sb(env, '/rest/v1/login_attempts', { method: 'POST', body: { ip_hash: ipHash }, headers: { Prefer: 'return=minimal' } });
        await sleep(500);
        return send(res, 401, { error: 'invalid' });
      }
      setSession(req, res, signToken(env, { exp: Date.now() + SESSION_MS }), Math.floor(SESSION_MS / 1000));
      return send(res, 200, { ok: true });
    }

    /* ----- everything below needs a valid session ----- */
    if (!isAuthed(req, env)) return send(res, 401, { error: 'auth' });

    if (action === 'logout') { setSession(req, res, '', 0); return send(res, 200, { ok: true }); }

    if (action === 'save') {
      const body = await readBody(req);
      if (!body) return send(res, 400, { error: 'bad_request' });
      const c = cleanListing(body.listing, env);
      if (c.error) return send(res, 400, { error: 'invalid', message: c.error });
      if (body.id) {
        if (!SAFE_ID.test(String(body.id))) return send(res, 400, { error: 'bad_id' });
        const r = await sb(env, `/rest/v1/listings?id=eq.${encodeURIComponent(body.id)}`,
          { method: 'PATCH', body: Object.assign({ updated_at: new Date().toISOString() }, c.row), headers: { Prefer: 'return=representation' } });
        if (!r.ok) { console.error('update failed', r.status, r.data); return send(res, 502, { error: 'save_failed' }); }
        if (!r.data || !r.data.length) return send(res, 404, { error: 'not_found' });
        return send(res, 200, { ok: true, listing: r.data[0] });
      }
      const id = 'lst_' + Date.now().toString(36) + crypto.randomBytes(4).toString('hex');
      const r = await sb(env, '/rest/v1/listings', { method: 'POST', body: Object.assign({ id }, c.row), headers: { Prefer: 'return=representation' } });
      if (!r.ok) { console.error('insert failed', r.status, r.data); return send(res, 502, { error: 'save_failed' }); }
      return send(res, 200, { ok: true, listing: r.data[0] });
    }

    if (action === 'delete') {
      const body = await readBody(req);
      const id = body && String(body.id || '');
      if (!SAFE_ID.test(id)) return send(res, 400, { error: 'bad_id' });
      const r = await sb(env, `/rest/v1/listings?id=eq.${encodeURIComponent(id)}`, { method: 'DELETE', headers: { Prefer: 'return=minimal' } });
      if (!r.ok) { console.error('delete failed', r.status, r.data); return send(res, 502, { error: 'delete_failed' }); }
      return send(res, 200, { ok: true });
    }

    if (action === 'upload') {
      const body = await readBody(req);
      const m = body && typeof body.dataUrl === 'string' && /^data:image\/(?:jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$/.exec(body.dataUrl);
      if (!m) return send(res, 400, { error: 'bad_image' });
      const buf = Buffer.from(m[1], 'base64');
      if (buf.length > 3 * 1024 * 1024) return send(res, 413, { error: 'too_large' });
      const kind = sniffImage(buf);
      if (!kind) return send(res, 400, { error: 'bad_image' });
      const name = `${Date.now().toString(36)}-${crypto.randomBytes(5).toString('hex')}.${kind.ext}`;
      const r = await sb(env, `/storage/v1/object/${BUCKET}/${name}`, { method: 'POST', raw: true, body: buf, headers: { 'Content-Type': kind.mime, 'x-upsert': 'false' } });
      if (!r.ok) { console.error('upload failed', r.status, r.data); return send(res, 502, { error: 'upload_failed' }); }
      return send(res, 200, { ok: true, url: `${env.url.replace(/\/$/, '')}/storage/v1/object/public/${BUCKET}/${name}` });
    }

    return send(res, 404, { error: 'unknown_action' });
  } catch (err) {
    console.error('site handler error', err && err.stack || err);
    return send(res, 500, { error: 'server' });
  }
};
