import type { Context } from "hono";
import {
  escapeHtml,
  hmacHex,
  newToken,
  parseCookies,
  safeEqual,
  sha256Hex,
} from "./crypto";
import type { Env } from "./index";

const SESSION_COOKIE = "s_tcs";
const SESSION_TTL_SECONDS = 30 * 60;
const LOGIN_LIMIT = 10;
const LOGIN_WINDOW_MS = 10 * 60 * 1000;

type Session = { uid: number };

type DbUser = { id: number; name: string; created_at: string };

// Best-effort login throttle (per isolate, resets on deploy — enough to
// slow down token guessing; the token itself is 256 bit).
const attempts = new Map<string, { n: number; until: number }>();

function clientIp(c: Context<{ Bindings: Env }>): string {
  return (
    c.req.header("CF-Connecting-IP") ||
    c.req.header("X-Forwarded-For")?.split(",")[0]?.trim() ||
    "unknown"
  );
}

function loginBlocked(ip: string): boolean {
  const a = attempts.get(ip);
  if (!a) return false;
  if (Date.now() > a.until) {
    attempts.delete(ip);
    return false;
  }
  return a.n >= LOGIN_LIMIT;
}

function loginFailed(ip: string): void {
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a || now > a.until) attempts.set(ip, { n: 1, until: now + LOGIN_WINDOW_MS });
  else a.n += 1;
}

function sessionValue(uid: number, exp: number, sig: string): string {
  return `${uid}.${exp}.${sig}`;
}

async function signSession(tokenSha256: string, uid: number, exp: number): Promise<string> {
  return hmacHex(tokenSha256, `tabby-sync:${uid}:${exp}`);
}

async function readSession(
  c: Context<{ Bindings: Env }>,
): Promise<Session | null> {
  const raw = parseCookies(c.req.header("Cookie") ?? null)[SESSION_COOKIE];
  if (!raw) return null;
  const m = /^(\d+)\.(\d+)\.([0-9a-f]{64})$/.exec(raw);
  if (!m) return null;
  const uid = Number(m[1]);
  const exp = Number(m[2]);
  const sig = m[3] ?? "";
  if (!Number.isSafeInteger(uid) || !Number.isSafeInteger(exp)) return null;
  if (exp * 1000 < Date.now()) return null;
  const row = await c.env.DB.prepare(
    "SELECT token_sha256 FROM users WHERE id = ?1 AND disabled = 0",
  )
    .bind(uid)
    .first<{ token_sha256: string }>();
  if (!row) return null;
  const expect = await signSession(row.token_sha256, uid, exp);
  return safeEqual(sig, expect) ? { uid } : null;
}

function setSessionCookie(uid: number, exp: number, sig: string, base: string): string {
  return (
    `${SESSION_COOKIE}=${sessionValue(uid, exp, sig)}; Path=${base}; ` +
    `Max-Age=${SESSION_TTL_SECONDS}; HttpOnly; Secure; SameSite=Lax`
  );
}

function clearSessionCookie(base: string): string {
  return `${SESSION_COOKIE}=; Path=${base}; Max-Age=0; HttpOnly; Secure; SameSite=Lax`;
}

function shell(title: string, body: string): string {
  return (
    `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">` +
    `<meta name="viewport" content="width=device-width,initial-scale=1">` +
    `<meta name="robots" content="noindex,nofollow">` +
    `<title>${escapeHtml(title)}</title>` +
    `<style>:root{color-scheme:light dark}` +
    `body{font-family:system-ui,-apple-system,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;line-height:1.5}` +
    `.card{border:1px solid #8884;border-radius:.75rem;padding:1.5rem}` +
    `h1{margin-top:0;font-size:1.4rem}` +
    `input{width:100%;box-sizing:border-box;font-size:1rem;padding:.6rem;border:1px solid #8886;border-radius:.5rem}` +
    `button{font-size:1rem;padding:.55rem 1.1rem;border:0;border-radius:.5rem;background:#2563eb;color:#fff;cursor:pointer}` +
    `button:hover{background:#1d4ed8}button.secondary{background:#6662;color:#fff}` +
    `.err{color:#dc2626}` +
    `.tokbox{display:flex;gap:.5rem;align-items:stretch;background:#8882;border-radius:.5rem;padding:.75rem}` +
    `.tok{flex:1;font-family:ui-monospace,monospace;font-size:.95rem;word-break:break-all;margin:0}` +
    `.warn{background:#fff3cd;color:#664d03;padding:.75rem;border-radius:.5rem}` +
    `@media(prefers-color-scheme:dark){.warn{background:#443a12;color:#ffe58a}}</style></head>` +
    `<body><div class="card">${body}</div></body></html>`
  );
}

function loginPage(base: string, error: string | null): string {
  const err = error ? `<p class="err">${escapeHtml(error)}</p>` : "";
  return shell(
    "Sign in",
    `<h1>Sign in</h1>${err}` +
      `<p>Paste your <b>current sync token</b> to sign in and rotate it.</p>` +
      `<form method="post" action="${base}/login">` +
      `<input type="password" name="token" autocomplete="off" placeholder="tcs_…" required>` +
      `<p><button type="submit">Sign in</button></p></form>`,
  );
}

async function panelPage(
  c: Context<{ Bindings: Env }>,
  base: string,
  uid: number,
  notice: string | null,
): Promise<string> {
  const user = await c.env.DB.prepare(
    "SELECT id, name, created_at FROM users WHERE id = ?1",
  )
    .bind(uid)
    .first<DbUser>();
  if (!user) throw new Error("user gone");
  const n = await c.env.DB.prepare(
    "SELECT COUNT(*) AS n FROM configs WHERE user_id = ?1",
  )
    .bind(uid)
    .first<{ n: number }>();
  const note = notice ? `<p>${notice}</p>` : "";
  return shell(
    "Manage token",
    `<h1>Manage token</h1>${note}` +
      `<p>Signed in as <b>${escapeHtml(user.name)}</b> · ` +
      `${n?.n ?? 0} configs stored.</p>` +
      `<form method="post" action="${base}/rotate" ` +
      `onsubmit="return confirm('Rotate token? The old token stops working on all devices immediately.')">` +
      `<button type="submit">Rotate token now</button></form>` +
      `<form method="post" action="${base}/logout"><p>` +
      `<button type="submit">Sign out</button></p></form>`,
  );
}

function rotatedPage(base: string, token: string): string {
  return shell(
    "New token",
    `<h1>New token</h1>` +
      `<p class="warn">The old token is dead. Replace the token on all ` +
      `devices now — this new token is shown only once.</p>` +
      `<div class="tokbox"><p class="tok"><code id="newtok">${escapeHtml(token)}</code></p>` +
      `<button type="button" id="copybtn" onclick="copyTok()">Copy</button></div>` +
      `<p><a href="${base}">Back</a></p>` +
      `<script>function copyTok(){var t=document.getElementById('newtok').textContent;` +
      `function done(){var b=document.getElementById('copybtn');b.textContent='Copied';` +
      `setTimeout(function(){b.textContent='Copy'},2000)}` +
      `if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,done)}` +
      `else{var ta=document.createElement('textarea');ta.value=t;document.body.appendChild(ta);` +
      `ta.select();try{document.execCommand('copy')}catch(e){}document.body.removeChild(ta);done()}}</script>`,
  );
}

export async function rotateHandler(
  c: Context<{ Bindings: Env }>,
  base: string,
): Promise<Response> {
  const url = new URL(c.req.url);
  const sub = url.pathname.slice(base.length) || "/";
  const method = c.req.method.toUpperCase();

  if (method === "GET" && (sub === "/" || sub === "")) {
    const s = await readSession(c);
    if (!s) return c.html(loginPage(base, null));
    return c.html(await panelPage(c, base, s.uid, null));
  }

  if (method === "POST" && sub === "/login") {
    const ip = clientIp(c);
    if (loginBlocked(ip)) {
      return c.html(loginPage(base, "Too many attempts. Try again later."), 429);
    }
    let token = "";
    try {
      const form = await c.req.formData();
      token = String(form.get("token") ?? "").trim();
    } catch {
      token = "";
    }
    const row = token
      ? await c.env.DB.prepare(
          "SELECT id FROM users WHERE token_sha256 = ?1 AND disabled = 0",
        )
          .bind(await sha256Hex(token))
          .first<{ id: number }>()
      : null;
    if (!row) {
      loginFailed(ip);
      return c.html(loginPage(base, "Invalid token."), 401);
    }
    attempts.delete(ip);
    const exp = Math.floor(Date.now() / 1000) + SESSION_TTL_SECONDS;
    const user = await c.env.DB.prepare("SELECT token_sha256 FROM users WHERE id = ?1")
      .bind(row.id)
      .first<{ token_sha256: string }>();
    if (!user) return c.html(loginPage(base, "Invalid token."), 401);
    const sig = await signSession(user.token_sha256, row.id, exp);
    c.header("Set-Cookie", setSessionCookie(row.id, exp, sig, base));
    return c.redirect(base, 303);
  }

  if (method === "POST" && sub === "/logout") {
    c.header("Set-Cookie", clearSessionCookie(base));
    return c.redirect(base, 303);
  }

  if (method === "POST" && sub === "/rotate") {
    const s = await readSession(c);
    if (!s) return c.redirect(base, 303);
    const token = newToken();
    const now = new Date().toISOString();
    await c.env.DB.prepare(
      "UPDATE users SET token_sha256 = ?1 WHERE id = ?2 AND disabled = 0",
    )
      .bind(await sha256Hex(token), s.uid)
      .run();
    // Old sessions die too: the HMAC is keyed to the previous token hash.
    c.header("Set-Cookie", clearSessionCookie(base));
    return c.html(rotatedPage(base, token));
  }

  return c.text("not found", 404);
}
