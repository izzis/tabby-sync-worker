# tabby-sync-worker

Tabby sync-compatible config host on Cloudflare Workers + D1 (SQLite).
Used by the Android app as a self-hosted sync host replacing the Tabby server.

The API contract mirrors [Eugeny/tabby](https://github.com/Eugeny/tabby)
(`configSync.service`, `/api/1/*`); schema + token format mirror
[phil616/tabby-sync](https://github.com/phil616/tabby-sync) (MIT).

## Endpoints

Auth: `Authorization: Bearer <token>` on all `/api/1/*`.

- `GET /api/1/user` — connection check
- `GET /api/1/configs` — list configs
- `GET /api/1/configs/{id}` — single config
- `POST /api/1/configs` — body `{name}` (`{data:{name}}` variant accepted)
- `PATCH /api/1/configs/{id}` — body `{content, last_used_with_version}`
  (`{data:{...}}` variant accepted)
- `DELETE /api/1/configs/{id}`

The token rotate page lives at an obscure path (default `/rotate-token`,
configurable via `ROTATE_PATH`). **Sign in only, no registration.**
Sign in with your current sync token, press Rotate, the old token dies immediately.
Sessions are invalidated on rotate (HMAC is keyed to the token hash).

## Setup

```sh
npm install
npx wrangler d1 create tabby-sync      # copy database_id into wrangler.jsonc
npx wrangler d1 execute tabby-sync --local --file=migrations/0001_init.sql
npm run dev                            # http://localhost:8787
```

Create the first user (the token is shown only once here — store it safely):

```sh
TOKEN="tcs_$(openssl rand -hex 32)"; echo "$TOKEN"
echo -n "$TOKEN" | sha256sum
npx wrangler d1 execute tabby-sync --local --command \
  "INSERT INTO users (name, token_sha256, created_at) VALUES ('al', '<sha256-from-above>', '$(date -u +%FT%TZ)')"
```

Deploy:

```sh
npx wrangler d1 execute tabby-sync --remote --file=migrations/0001_init.sql
npx wrangler deploy
# custom domain (optional): dashboard Workers -> <your-worker> -> Settings -> Domains
```

`wrangler.jsonc` in this repo is a template with placeholder values.
To deploy with real values without committing them, copy it to the
gitignored `wrangler.local.jsonc`, fill in the real `database_id` /
`ROTATE_PATH` there, and deploy with:

```sh
npx wrangler deploy --config wrangler.local.jsonc
```

Live: `https://<your-worker>.<your-account>.workers.dev`

In the app: Settings → Config sync → host `https://<your-worker>.<your-account>.workers.dev` + token.

## Backup

```sh
npx wrangler d1 export tabby-sync --output=backup-$(date +%F).sql
```

## Security notes

- Sync tokens are never stored in plaintext, only SHA-256.
- Rotate-page sign-in is throttled to 10 failures per 10 minutes per IP (best-effort).
- The obscure rotate path is only a second layer; the token remains the only real key.
- The sign-in page uses `noindex,nofollow`.
- Disable a user: `UPDATE users SET disabled = 1 WHERE name = '…'` via wrangler.
