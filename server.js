'use strict';
const path = require('path'), crypto = require('crypto');
const Fastify = require('fastify'), Redis = require('ioredis');

// Without REDIS_URL, fall back to an in-memory store (development only: single process, lost on restart).
let redis;
if (process.env.REDIS_URL) {
  redis = new Redis(process.env.REDIS_URL);
  let warned = false;
  redis.on('error', e => { if (!warned) { warned = true; console.error('Redis error:', e.message); } });
} else {
  redis = makeMemoryStore();
  console.log('REDIS_URL not set: using the in-memory store (development only).');
}

// Implements just the Redis commands this server uses.
function makeMemoryStore() {
  const m = new Map();
  const live = k => { const e = m.get(k); if (e && e.exp && e.exp <= Date.now()) { m.delete(k); return null; } return e || null; };
  const s = {
    defineCommand() {},
    async hset(k, o) { m.set(k, { f: Object.fromEntries(Object.entries(o).map(([a, b]) => [a, String(b)])), exp: 0 }); return 1; },
    async expire(k, sec) { const e = live(k); if (e) e.exp = Date.now() + sec * 1000; return e ? 1 : 0; },
    async ttl(k) { const e = live(k); return !e ? -2 : e.exp ? Math.ceil((e.exp - Date.now()) / 1000) : -1; },
    async hmget(k, ...fs) { const e = live(k); return fs.map(f => (e && f in e.f ? e.f[f] : null)); },
    async hget(k, f) { return (await s.hmget(k, f))[0]; },
    async hincrby(k, f, n) { const e = live(k); if (!e) return n; e.f[f] = String((+e.f[f] || 0) + n); return +e.f[f]; },
    async del(k) { return m.delete(k) ? 1 : 0; },
    async openDrop(k) { const e = live(k); if (!e) return null; if (e.f.burn === '1') m.delete(k); return e.f.blob; },
    multi() {
      const ops = [];
      const chain = new Proxy({}, { get: (_, name) => name === 'exec'
        ? async () => { const r = []; for (const [n, a] of ops) r.push([null, await s[n](...a)]); return r; }
        : (...a) => { ops.push([name, a]); return chain; } });
      return chain;
    }
  };
  setInterval(() => { for (const k of [...m.keys()]) live(k); }, 60000).unref();
  return s;
}
// No logger on purpose: we never record IPs, URLs or payloads.
const app = Fastify({ logger: false, bodyLimit: 16 * 1024 * 1024, trustProxy: process.env.TRUST_PROXY === '1' });

const TTLS = new Set([3600, 86400, 604800]), MAX_BLOB = 14500000, MAX_TRIES = 5;
const B64U = /^[A-Za-z0-9_-]+$/;
const sha = s => crypto.createHash('sha256').update(s).digest();
const rnd = n => crypto.randomBytes(n).toString('base64url');
const dropKey = id => 'drop:' + id;
const validId = id => typeof id === 'string' && id.length === 16 && B64U.test(id);
const validB64 = (s, len) => typeof s === 'string' && s.length === len && B64U.test(s);

// Atomic read: returns the blob and deletes the drop in the same step when burn is on,
// so two simultaneous requests can never both receive the secret.
redis.defineCommand('openDrop', {
  numberOfKeys: 1,
  lua: `local blob = redis.call('HGET', KEYS[1], 'blob')
        if not blob then return false end
        if redis.call('HGET', KEYS[1], 'burn') == '1' then redis.call('DEL', KEYS[1]) end
        return blob`
});

app.addHook('onSend', async (req, reply) => {
  reply.header('Referrer-Policy', 'no-referrer');
  reply.header('X-Content-Type-Options', 'nosniff');
  reply.header('Content-Security-Policy',
    "default-src 'none'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data:; " +
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'");
  if (req.url.startsWith('/api/')) reply.header('Cache-Control', 'no-store');
});

const gone = reply => reply.code(404).send({ error: 'Not found' });

(async () => {
  await app.register(require('@fastify/rate-limit'), { max: 120, timeWindow: '1 minute' });
  await app.register(require('@fastify/static'), { root: path.join(__dirname, 'public') });

  app.post('/api/drops', { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } }, async (req, reply) => {
    const b = req.body || {}, hasPass = b.hasPass === true;
    if (typeof b.blob !== 'string' || !b.blob || b.blob.length > MAX_BLOB || !B64U.test(b.blob) || !TTLS.has(b.ttl) ||
        (hasPass && !(validB64(b.salt, 22) && validB64(b.verifier, 43)))) {
      return reply.code(400).send({ error: 'Invalid request' });
    }
    const id = rnd(12), burnToken = rnd(16), k = dropKey(id);
    await redis.multi()
      .hset(k, {
        blob: b.blob, burn: b.burn === false ? '0' : '1', hasPass: hasPass ? '1' : '0',
        salt: hasPass ? b.salt : '', verifier: hasPass ? sha(b.verifier).toString('hex') : '',
        token: sha(burnToken).toString('hex'), tries: 0
      })
      .expire(k, b.ttl).exec();
    return { id, burnToken, expiresAt: Date.now() + b.ttl * 1000 };
  });

  // Metadata only. The blob is never returned here.
  app.get('/api/drops/:id', async (req, reply) => {
    if (!validId(req.params.id)) return gone(reply);
    const k = dropKey(req.params.id);
    const [[, f], [, ttl]] = await redis.multi().hmget(k, 'hasPass', 'salt', 'burn').ttl(k).exec();
    if (!f[0] || ttl < 0) return gone(reply);
    return { hasPass: f[0] === '1', salt: f[1], burn: f[2] === '1', expiresAt: Date.now() + ttl * 1000 };
  });

  app.post('/api/drops/:id/open', { config: { rateLimit: { max: 30, timeWindow: '1 minute' } } }, async (req, reply) => {
    if (!validId(req.params.id)) return gone(reply);
    const k = dropKey(req.params.id);
    const stored = await redis.hmget(k, 'hasPass', 'verifier');
    if (!stored[0]) return gone(reply);
    if (stored[0] === '1') {
      const tries = await redis.hincrby(k, 'tries', 1);
      const given = sha(typeof req.body?.verifier === 'string' ? req.body.verifier : '');
      const want = Buffer.from(stored[1], 'hex');
      if (want.length !== given.length || !crypto.timingSafeEqual(given, want)) {
        const left = Math.max(0, MAX_TRIES - tries);
        if (!left) await redis.del(k);
        return reply.code(403).send({ error: 'Wrong passphrase', attemptsLeft: left });
      }
    }
    const blob = await redis.openDrop(k);
    return blob ? { blob } : gone(reply);
  });

  app.delete('/api/drops/:id', async (req, reply) => {
    if (!validId(req.params.id)) return gone(reply);
    const k = dropKey(req.params.id), t = req.headers['x-burn-token'];
    const want = await redis.hget(k, 'token');
    if (!want) return gone(reply);
    const given = sha(typeof t === 'string' ? t : '');
    if (!crypto.timingSafeEqual(given, Buffer.from(want, 'hex'))) return reply.code(403).send({ error: 'Forbidden' });
    await redis.del(k);
    return { ok: true };
  });

  await app.listen({ port: +process.env.PORT || 3000, host: '0.0.0.0' });
})();