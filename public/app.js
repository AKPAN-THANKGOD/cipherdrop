'use strict';
/* ---------- API ----------
   The server only ever sees the encrypted blob, flags and a passphrase verifier. Never the key. */
const api = {
  async call(path, opts = {}) {
    const headers = { ...(opts.headers || {}) };
    if (opts.body) headers['content-type'] = 'application/json'; // a JSON content-type on a bodyless DELETE makes Fastify answer 400
    const r = await fetch('/api' + path, { ...opts, headers });
    let body = null; try { body = await r.json(); } catch {}
    return { ok: r.ok, status: r.status, body };
  },
  create: d => api.call('/drops', { method: 'POST', body: JSON.stringify(d) }),
  info: id => api.call('/drops/' + encodeURIComponent(id)),
  open: (id, verifier) => api.call('/drops/' + encodeURIComponent(id) + '/open', { method: 'POST', body: JSON.stringify({ verifier }) }),
  burn: (id, token) => api.call('/drops/' + encodeURIComponent(id), { method: 'DELETE', headers: { 'x-burn-token': token } })
};

/* Metadata about drops created in this browser (no keys, no links). */
const meta = {
  all() { try { return JSON.parse(localStorage.getItem('cd:meta') || '[]'); } catch { return []; } },
  save(list) { localStorage.setItem('cd:meta', JSON.stringify(list)); },
  add(m) { this.save([m, ...this.all()]); },
  remove(id) { this.save(this.all().filter(m => m.id !== id)); }
};

/* ---------- Crypto ---------- */
const enc = new TextEncoder(), dec = new TextDecoder();
const b64u = {
  to: b => { const u = new Uint8Array(b); let t = ''; for (let i = 0; i < u.length; i += 0x8000) t += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000)); return btoa(t).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); },
  from: s => { const bin = atob(s.replace(/-/g, '+').replace(/_/g, '/')), u = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; }
};
const rand = n => crypto.getRandomValues(new Uint8Array(n));
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };

async function seal(bytes, key) {
  const iv = rand(12);
  return concat(iv, new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, bytes)));
}
async function unseal(bytes, key) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, key, bytes.slice(12)));
}
/* One PBKDF2 run yields 64 bytes: the first 32 encrypt the inner layer, the last 32 are the
   verifier sent to the server. The verifier cannot be used to decrypt anything. */
async function passMaterial(pass, salt) {
  const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveBits']);
  const b = new Uint8Array(await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' }, base, 512));
  return { key: await crypto.subtle.importKey('raw', b.slice(0, 32), 'AES-GCM', false, ['encrypt', 'decrypt']), verifier: b64u.to(b.slice(32)) };
}
async function encryptSecret(bytes, pass) {
  const raw = rand(32);
  const key = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt']);
  let data = bytes, extra = {};
  if (pass) { const salt = rand(16), pm = await passMaterial(pass, salt); data = await seal(data, pm.key); extra = { salt: b64u.to(salt), verifier: pm.verifier }; }
  return { blob: b64u.to(await seal(data, key)), keyStr: b64u.to(raw), ...extra };
}
async function decryptSecret(blob, keyStr, innerKey) {
  const key = await crypto.subtle.importKey('raw', b64u.from(keyStr), 'AES-GCM', false, ['decrypt']);
  let data = await unseal(b64u.from(blob), key);
  if (innerKey) data = await unseal(data, innerKey);
  return data;
}
async function fingerprint(blob) {
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', b64u.from(blob)));
  return [...h].map(x => x.toString(16).padStart(2, '0')).join('').match(/.{4}/g).join(' ');
}

/* Everything inside the encryption is wrapped as [4-byte header length][JSON header][body],
   so the server never learns whether it holds text or a file, or the file's name. */
function pack(meta, body) {
  const h = enc.encode(JSON.stringify(meta)), len = new Uint8Array(4);
  new DataView(len.buffer).setUint32(0, h.length);
  return concat(len, h, body);
}
function unpack(b) {
  const n = new DataView(b.buffer, b.byteOffset, 4).getUint32(0);
  return { meta: JSON.parse(dec.decode(b.slice(4, 4 + n))), body: b.slice(4 + n) };
}

/* ---------- UI helpers ---------- */
const $ = id => document.getElementById(id);
const toast = msg => { const t = $('toast'); t.textContent = msg; t.classList.add('show'); setTimeout(() => t.classList.remove('show'), 1800); };
const copy = async (text, msg) => { try { await navigator.clipboard.writeText(text); toast(msg); } catch { toast('Copy failed. Select the text and copy it manually.'); } };
const fmtLeft = ms => { const m = Math.max(0, Math.round(ms / 60000)); return m >= 1440 ? Math.round(m / 1440) + ' d' : m >= 60 ? Math.round(m / 60) + ' h' : m + ' min'; };
const el = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); e.append(...kids); return e; };

/* A destructive button that needs a second click within 4 seconds. */
function twoStep(btn, armedText, action) {
  const idle = btn.textContent; let t;
  btn.onclick = async () => {
    if (!btn.dataset.arm) { btn.dataset.arm = '1'; btn.textContent = armedText; t = setTimeout(() => { delete btn.dataset.arm; btn.textContent = idle; }, 4000); return; }
    clearTimeout(t); delete btn.dataset.arm; btn.textContent = idle; await action();
  };
}

/* ---------- Create ---------- */
const MAX_FILE = 10 * 1024 * 1024, MAX_TEXT = 100 * 1024;
function setKind() {
  const isFile = document.querySelector('[name=kind]:checked').value === 'file';
  $('textField').hidden = isFile; $('fileField').hidden = !isFile; $('secret').required = !isFile;
}
document.querySelectorAll('[name=kind]').forEach(r => r.addEventListener('change', setKind));
$('file').addEventListener('change', e => {
  const f = e.target.files[0];
  $('fileInfo').textContent = f ? `${f.name} · ${(f.size / 1024).toFixed(1)} KB` : 'No file chosen';
});
$('secret').addEventListener('input', e => { $('bytes').textContent = enc.encode(e.target.value).length + ' bytes'; });
$('genPass').addEventListener('click', () => {
  const words = [...rand(18)].map(b => 'abcdefghjkmnpqrstuvwxyz23456789'[b % 31]).join('');
  $('pass').type = 'text'; $('pass').value = words.match(/.{6}/g).join('-');
});
$('createForm').addEventListener('submit', async e => {
  e.preventDefault();
  const btn = e.submitter, err = $('createError'); err.hidden = true;
  const isFile = document.querySelector('[name=kind]:checked').value === 'file';
  const pass = $('pass').value, file = $('file').files[0], text = $('secret').value;
  const bad = isFile
    ? (!file ? 'Choose a file first.' : file.size > MAX_FILE ? 'This file is larger than 10 MB.' : '')
    : (!text.trim() ? 'Enter a secret first.' : enc.encode(text).length > MAX_TEXT ? 'The text is longer than 100 KB. Share it as a file instead.' : '');
  if (bad) { err.textContent = bad; err.hidden = false; return; }
  btn.disabled = true; btn.textContent = 'Encrypting…';
  try {
    const ttl = +document.querySelector('[name=ttl]:checked').value;
    const payload = isFile
      ? pack({ kind: 'file', name: file.name, type: file.type }, new Uint8Array(await file.arrayBuffer()))
      : pack({ kind: 'text' }, enc.encode(text));
    const { blob, keyStr, salt, verifier } = await encryptSecret(payload, pass);
    const r = await api.create({ blob, burn: $('burn').checked, ttl: ttl / 1000, hasPass: !!pass, salt, verifier });
    if (!r.ok) throw new Error(r.status === 429 ? 'too many requests, wait a minute' : 'server error ' + r.status);
    const { id, burnToken, expiresAt } = r.body, rec = { id, burn: $('burn').checked, hasPass: !!pass, expiresAt };
    meta.add({ id, burnToken, burn: rec.burn, hasPass: rec.hasPass, createdAt: Date.now(), expiresAt });
    const prefix = `${location.origin}${location.pathname}#/d/${id}.`, link = prefix + keyStr;
    $('shareLink').replaceChildren(prefix, el('span', { className: 'frag', textContent: keyStr }));
    $('fingerprint').textContent = await fingerprint(blob);
    $('sumBurn').textContent = rec.burn ? 'Burns after first read' : 'Readable until expiry';
    $('sumExpiry').textContent = fmtLeft(expiresAt - Date.now());
    $('sumPass').textContent = pass ? 'Required' : 'None';
    $('sumSize').textContent = (blob.length * 0.75 / 1024).toFixed(1) + ' KB';
    $('selfOpenWarn').hidden = !rec.burn;
    $('copyLink').onclick = () => copy(link, 'Link copied');
    twoStep($('destroyNow'), 'Click again to destroy', async () => {
      const r = await api.burn(id, burnToken);
      toast(r.ok ? 'Secret destroyed' : 'Could not destroy it (error ' + r.status + ')');
      if (r.ok) location.hash = '#/drops';
    });
    $('createForm').reset(); $('bytes').textContent = '0 bytes'; $('pass').type = 'password'; $('fileInfo').textContent = 'No file chosen'; setKind();
    location.hash = '#/done';
  } catch (ex) {
    err.textContent = 'Encryption failed: ' + ex.message + '. Use a modern browser over HTTPS or localhost.'; err.hidden = false;
  } finally { btn.disabled = false; btn.textContent = 'Encrypt and create link'; }
});

/* ---------- Drops list ---------- */
async function renderDrops() {
  const list = $('dropList'); list.replaceChildren();
  const items = meta.all(); let live = 0;
  for (const m of items) {
    const active = (await api.info(m.id)).ok; if (active) live++;
    const pill = active ? el('span', { className: 'pill ' + (m.expiresAt - Date.now() < 36e5 ? 'warn' : 'ok') }, el('i'), 'Expires in ' + fmtLeft(m.expiresAt - Date.now()))
                        : el('span', { className: 'pill bad' }, el('i'), 'Gone');
    const burn = el('button', { className: 'danger', textContent: 'Burn now', disabled: !active });
    burn.onclick = async () => { const r = await api.burn(m.id, m.burnToken); toast(r.ok ? 'Drop burned' : 'Could not burn this drop (error ' + r.status + ')'); renderDrops(); };
    const rm = el('button', { className: 'ghost', textContent: 'Remove' });
    rm.onclick = () => { meta.remove(m.id); renderDrops(); };
    list.append(el('div', { className: 'item' },
      el('div', {}, el('span', { className: 'id', textContent: m.id }), el('small', { textContent: `${m.burn ? 'Burn after reading' : 'Multi-read'}${m.hasPass ? ' · passphrase' : ''}` })),
      pill, el('div', { className: 'inline' }, burn, active ? '' : rm)));
  }
  if (!items.length) list.append(el('p', { className: 'empty', textContent: 'No drops yet. Create a secret to see it here.' }));
  $('dropCount').textContent = live;
  $('dropStats').textContent = `${live} active · ${items.length - live} gone`;
  $('burnAll').disabled = !live;
}

/* ---------- Open ---------- */
async function renderOpen(hash) {
  const card = $('openCard'); card.replaceChildren();
  const [id, key] = hash.split('.');
  const info = id && key ? await api.info(id) : null;
  if (!info || !info.ok) {
    $('openTitle').textContent = 'Secret unavailable';
    card.append(el('p', {}, 'This secret does not exist, has expired or was already read. Ask the sender for a new link.')); return;
  }
  const rec = info.body;
  $('openTitle').textContent = 'Someone sent you a secret';
  const pass = el('input', { type: 'password', placeholder: 'Passphrase from the sender' });
  const err = el('p', { className: 'error', hidden: true });
  const go = el('button', { className: 'primary', textContent: 'Decrypt secret' });
  card.append(el('p', { className: 'meta', textContent: rec.burn ? 'It is deleted from the server the moment you decrypt it. Copy it before leaving this page.' : 'It can be opened again until it expires.' }));
  card.append(el('p', { className: 'meta', textContent: 'Drop ID: ' + id }));
  const show = el('button', { type: 'button', className: 'ghost', textContent: 'Show' });
  show.onclick = () => { const hidden = pass.type === 'password'; pass.type = hidden ? 'text' : 'password'; show.textContent = hidden ? 'Hide' : 'Show'; };
  if (rec.hasPass) card.append(el('label', { className: 'field' }, el('span', { className: 'label', textContent: 'Passphrase' }), el('span', { className: 'inline' }, pass, show)));
  card.append(err, go);
  const fail = msg => { err.textContent = msg; err.hidden = false; go.disabled = false; go.textContent = 'Decrypt secret'; };
  go.onclick = async () => {
    err.hidden = true; go.disabled = true; go.textContent = 'Decrypting…';
    try {
      let inner = null, verifier;
      if (rec.hasPass) { const pm = await passMaterial(pass.value, b64u.from(rec.salt)); inner = pm.key; verifier = pm.verifier; }
      const r = await api.open(id, verifier);
      if (r.status === 403) return fail(r.body.attemptsLeft ? `Wrong passphrase. ${r.body.attemptsLeft} attempts left.` : 'Too many wrong attempts. This secret was destroyed.');
      if (!r.ok) return fail('This secret is no longer available.');
      let item; try { item = unpack(await decryptSecret(r.body.blob, key, inner)); } catch { return fail('The link is damaged, so the secret could not be decrypted.'); }
      const status = el('span', { className: 'pill ok' }, el('i'), rec.burn ? 'Decrypted and destroyed' : 'Decrypted');
      if (item.meta.kind === 'file') {
        const dl = el('button', { className: 'primary', textContent: 'Download file' });
        dl.onclick = () => {
          const u = URL.createObjectURL(new Blob([item.body], { type: 'application/octet-stream' }));
          const a = el('a', { href: u, download: item.meta.name || 'download' }); document.body.append(a); a.click(); a.remove();
          setTimeout(() => URL.revokeObjectURL(u), 60000);
        };
        card.replaceChildren(status, el('div', { className: 'reveal mono', textContent: `${item.meta.name || 'file'} · ${(item.body.length / 1024).toFixed(1)} KB` }), dl);
      } else {
        const text = dec.decode(item.body);
        const cp = el('button', { className: 'secondary', textContent: 'Copy secret' }); cp.onclick = () => copy(text, 'Secret copied');
        card.replaceChildren(status, el('div', { className: 'reveal mono', textContent: text }), cp);
      }
    } catch (ex) { fail('Something went wrong: ' + ex.message); }
  };
}

/* ---------- Router ---------- */
async function route() {
  const h = location.hash.slice(1) || '/';
  const view = h === '/' ? 'create' : h === '/drops' ? 'drops' : h === '/done' && $('shareLink').textContent ? 'done' : h.startsWith('/d/') ? 'open' : 'create';
  document.querySelectorAll('.view').forEach(v => v.hidden = v.id !== 'view-' + view);
  document.querySelectorAll('[data-nav]').forEach(a => a.classList.toggle('on', a.dataset.nav === view));
  document.body.classList.toggle('recipient', view === 'open');
  document.querySelector('main').classList.toggle('wide', view === 'done' || view === 'drops');
  if (view === 'drops') await renderDrops(); else if (view === 'open') await renderOpen(h.slice(3));
  if (view !== 'drops') $('dropCount').textContent = meta.all().filter(m => m.expiresAt > Date.now()).length;
  window.scrollTo(0, 0);
}
twoStep($('burnAll'), 'Click again to burn all', async () => {
  for (const m of meta.all()) await api.burn(m.id, m.burnToken);
  await renderDrops(); toast('All drops burned');
});
addEventListener('hashchange', route);
if (location.hash === '#/done') location.hash = '#/';
route();