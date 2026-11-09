# CipherDrop

Share a secret or a file through a one-time link. Everything is encrypted in the sender's
browser, and the decryption key lives only in the link, so the server never sees it.

## How it works

- The browser encrypts the secret with AES-256-GCM using a random 256-bit key.
- The server stores only the encrypted blob. The key stays in the link's `#fragment`,
  which browsers never send to a server.
- Text or file, and a file's name and type, are encrypted inside the payload.
- An optional passphrase adds a second encryption layer (PBKDF2-SHA256, 600,000 rounds).
  The browser sends the server only a separate verifier, never the passphrase or key.
- Drops can burn after the first read and always expire (1 hour, 24 hours or 7 days).
- After 5 wrong passphrase attempts the drop is destroyed.

## Run it

Requires Node.js 20 or newer.

```
npm install
node server.js
```

Open http://localhost:3000. Without `REDIS_URL`, drops are kept in memory. That is for
development only: they are lost on restart and work for a single process.

### With Docker and Redis

```
docker compose up --build
```

Redis runs with persistence off, so nothing is written to disk.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | Port to listen on |
| `REDIS_URL` | unset | Redis connection string. Unset means the in-memory dev store |
| `TRUST_PROXY` | `0` | Set to `1` behind a reverse proxy so rate limits use real client IPs |

## Limits

- Files up to 10 MB, text up to 100 KB.
- Rate limits per IP on creating and opening drops.

## Project layout

```
server.js            API, security headers, rate limits, dev store
public/              index.html, styles.css, app.js (all encryption happens here)
Dockerfile, docker-compose.yml
```

## Known limitations

- Browsers need HTTPS (or localhost) for the Web Crypto API, so serve it behind HTTPS.
- A burn-after-reading drop is deleted when it is fetched, so a recipient who closes the
  page before saving the secret cannot get it back.
- The "Active drops" list is stored in the creator's browser only.
- Passphrases use PBKDF2, not Argon2id.
- There are no per-IP storage quotas yet.