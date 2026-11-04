// Splonk API — Cloudflare Pages Function.
// Every request must carry a valid Cloudflare Access sign-in token. Each person's
// data is stored in the D1 database tagged with their verified email address, and
// every query is filtered by that address, so nobody can read or change anyone else's data.
//
// Needs (Pages project → Settings):
//   D1 binding:  DB → your "splonk" D1 database
//   Then ONE of these ways to lock it:
//   - Single user:  secret APP_KEY → a long private key you enter once in the app
//   - Several users (Cloudflare Access): TEAM_DOMAIN → https://<team>.cloudflareaccess.com
//                                        POLICY_AUD  → the Access application's AUD tag

const MAX_DOC_BYTES = 400 * 1024;
const KEY_RE = /^(settings|active|[rcbv]_[A-Za-z0-9_.:@+~-]{1,100})$/;

const json = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra } });

/* ---------- Cloudflare Access token verification (RS256, no dependencies) ---------- */
let certCache = { at: 0, team: '', keys: null };
const b64uBytes = s => { s = s.replace(/-/g, '+').replace(/_/g, '/'); s += '='.repeat((4 - (s.length % 4)) % 4); const bin = atob(s); const out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; };
const b64uJson = s => JSON.parse(new TextDecoder().decode(b64uBytes(s)));

async function accessKeys(team, force) {
  if (!force && certCache.keys && certCache.team === team && Date.now() - certCache.at < 3600e3) return certCache.keys;
  const res = await fetch(`${team}/cdn-cgi/access/certs`);
  if (!res.ok) throw new Error('Could not fetch Access signing keys');
  const body = await res.json();
  certCache = { at: Date.now(), team, keys: body.keys || [] };
  return certCache.keys;
}

export async function verifyAccess(request, env) {
  const team = String(env.TEAM_DOMAIN || '').trim().replace(/\/+$/, '');
  const aud = String(env.POLICY_AUD || '').trim();
  if (!team || !aud) return { error: 'Server not set up yet: add TEAM_DOMAIN and POLICY_AUD in the Pages project settings.', status: 500 };
  let token = request.headers.get('Cf-Access-Jwt-Assertion');
  if (!token) { const m = (request.headers.get('Cookie') || '').match(/(?:^|;\s*)CF_Authorization=([^;]+)/); token = m && m[1]; }
  if (!token) return { error: 'Not signed in', status: 401 };
  const parts = token.split('.');
  if (parts.length !== 3) return { error: 'Invalid sign-in token', status: 401 };
  let header, payload;
  try { header = b64uJson(parts[0]); payload = b64uJson(parts[1]); } catch (e) { return { error: 'Invalid sign-in token', status: 401 }; }
  if (header.alg !== 'RS256') return { error: 'Invalid sign-in token', status: 401 };
  let keys = await accessKeys(team, false);
  let jwk = keys.find(k => k.kid === header.kid);
  if (!jwk) { keys = await accessKeys(team, true); jwk = keys.find(k => k.kid === header.kid); }
  if (!jwk) return { error: 'Unknown signing key', status: 401 };
  const key = await crypto.subtle.importKey('jwk', { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: 'RS256', ext: true }, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  const ok = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, b64uBytes(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
  if (!ok) return { error: 'Invalid sign-in token', status: 401 };
  const now = Date.now() / 1000;
  if (typeof payload.exp === 'number' && payload.exp < now - 30) return { error: 'Sign-in expired', status: 401 };
  if (typeof payload.nbf === 'number' && payload.nbf > now + 30) return { error: 'Sign-in not valid yet', status: 401 };
  if (payload.iss !== team) return { error: 'Wrong issuer', status: 401 };
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(aud)) return { error: 'Token is for a different app', status: 401 };
  const email = String(payload.email || '').trim().toLowerCase();
  if (!email) return { error: 'No email on sign-in', status: 401 };
  return { email };
}

/* ---------- Single-user private key ---------- */
function sameText(a, b) {
  const x = new TextEncoder().encode(a), y = new TextEncoder().encode(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < Math.max(x.length, y.length); i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}
async function whoIs(request, env) {
  const appKey = String(env.APP_KEY || '');
  if (appKey) {
    if (appKey.length < 16) return { error: 'APP_KEY is too short: use at least 16 characters.', status: 500 };
    const given = request.headers.get('X-Splonk-Key') || '';
    if (!given) return { error: 'Key required', code: 'key_required', status: 401 };
    if (!sameText(given, appKey)) return { error: 'Wrong key', code: 'key_wrong', status: 401 };
    return { email: 'owner' };
  }
  return verifyAccess(request, env);
}

/* ---------- API ---------- */
async function readBody(request) {
  const text = await request.text();
  if (text.length > 25 * 1024 * 1024) throw Object.assign(new Error('Request too large'), { status: 413 });
  try { return JSON.parse(text); } catch (e) { throw Object.assign(new Error('Invalid JSON'), { status: 400 }); }
}

export async function onRequest(context) {
  const { request, env, params } = context;
  try {
    const who = await whoIs(request, env);
    if (who.error) return json({ error: who.error, code: who.code }, who.status);
    const user = who.email;
    if (!env.DB) return json({ error: 'Server not set up yet: add the D1 binding named DB.' }, 500);
    const path = [].concat(params.path || []);
    const [res, key] = path;
    const method = request.method;
    const url = new URL(request.url);

    if (res === 'me' && method === 'GET') return json({ email: user });

    if (res === 'docs' && !key && method === 'GET') {
      const since = Math.max(0, Number(url.searchParams.get('since')) || 0);
      const { results } = await env.DB.prepare('SELECT key, data, updated_at, deleted FROM docs WHERE user = ?1 AND updated_at > ?2 ORDER BY updated_at')
        .bind(user, since).all();
      const docs = results.map(r => ({ key: r.key, updated_at: r.updated_at, deleted: !!r.deleted, data: r.deleted ? null : JSON.parse(r.data) }));
      const latest = docs.reduce((m, d) => Math.max(m, d.updated_at), since);
      return json({ docs, latest });
    }

    if (res === 'docs' && key) {
      if (!KEY_RE.test(key)) return json({ error: 'Invalid key' }, 400);
      const now = Date.now();
      if (method === 'PUT') {
        const body = await readBody(request);
        const data = body && body.data;
        if (!data || typeof data !== 'object' || Array.isArray(data)) return json({ error: 'data must be an object' }, 400);
        const text = JSON.stringify(data);
        if (text.length > MAX_DOC_BYTES) return json({ error: 'Item too large' }, 413);
        await env.DB.prepare('INSERT INTO docs (user, key, data, updated_at, deleted) VALUES (?1, ?2, ?3, ?4, 0) ON CONFLICT(user, key) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at, deleted = 0')
          .bind(user, key, text, now).run();
        return json({ key, updated_at: now });
      }
      if (method === 'DELETE') {
        await env.DB.prepare("INSERT INTO docs (user, key, data, updated_at, deleted) VALUES (?1, ?2, 'null', ?3, 1) ON CONFLICT(user, key) DO UPDATE SET data = 'null', updated_at = excluded.updated_at, deleted = 1")
          .bind(user, key, now).run();
        return json({ key, updated_at: now, deleted: true });
      }
    }

    // First sync from a phone: add anything the cloud doesn't have yet; never overwrites cloud data.
    if (res === 'import' && method === 'POST') {
      const body = await readBody(request);
      const docs = body && body.docs && typeof body.docs === 'object' ? body.docs : {};
      const now = Date.now();
      const stmts = [];
      for (const [k, v] of Object.entries(docs)) {
        if (!KEY_RE.test(k) || !v || typeof v !== 'object' || Array.isArray(v)) continue;
        const text = JSON.stringify(v);
        if (text.length > MAX_DOC_BYTES) continue;
        stmts.push(env.DB.prepare('INSERT OR IGNORE INTO docs (user, key, data, updated_at, deleted) VALUES (?1, ?2, ?3, ?4, 0)').bind(user, k, text, now));
      }
      for (let i = 0; i < stmts.length; i += 50) await env.DB.batch(stmts.slice(i, i + 50));
      return json({ imported: stmts.length, updated_at: now });
    }

    // Full backup download of this person's data.
    if (res === 'export' && method === 'GET') {
      const { results } = await env.DB.prepare('SELECT key, data FROM docs WHERE user = ?1 AND deleted = 0').bind(user).all();
      const out = {}; results.forEach(r => { out[r.key] = JSON.parse(r.data); });
      const day = new Date().toISOString().slice(0, 10);
      return json(out, 200, { 'content-disposition': `attachment; filename="splonk-backup-${day}.json"` });
    }

    return json({ error: 'Not found' }, 404);
  } catch (e) {
    return json({ error: e.message || 'Server error' }, e.status || 500);
  }
}
