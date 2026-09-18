import { Hono, type Context } from "hono";
import { rotateHandler } from "./rotate";
import { sha256Hex } from "./crypto";

export type Env = {
  DB: D1Database;
  ROTATE_PATH?: string;
};

const DEFAULT_ROTATE_PATH = "/rotate-token";
const MAX_BODY_BYTES = 8 * 1024 * 1024;

type ApiUser = { id: number; name: string };

type ConfigRow = {
  id: number;
  name: string;
  content: string;
  last_used_with_version: string | null;
  created_at: string;
  modified_at: string;
};

const app = new Hono<{ Bindings: Env }>();

function rotateBase(c: { env: Env }): string {
  const p = (c.env.ROTATE_PATH || DEFAULT_ROTATE_PATH).trim() || DEFAULT_ROTATE_PATH;
  return p.startsWith("/") ? p : "/" + p;
}

// Sign-in/rotate page: obscure path. Second layer only —
// unreachable without a valid sync token.
app.use("*", async (c, next) => {
  const base = rotateBase(c);
  const path = new URL(c.req.url).pathname;
  if (path === base || path.startsWith(base + "/")) {
    return rotateHandler(c, base);
  }
  return next();
});

async function apiUser(c: Context<{ Bindings: Env }>): Promise<ApiUser | null> {
  const m = /^Bearer (.+)$/.exec(c.req.header("Authorization") || "");
  if (!m) return null;
  return c.env.DB.prepare(
    "SELECT id, name FROM users WHERE token_sha256 = ?1 AND disabled = 0",
  )
    .bind(await sha256Hex(m[1] ?? ""))
    .first<ApiUser>();
}

function needAuth(c: Context<{ Bindings: Env }>, user: ApiUser | null) {
  if (!user) return c.json({ error: "unauthorized" }, 401);
  return null;
}

/** Accept the official flat shape and the legacy {data:{...}}-wrapped variant. */
function unwrap(body: unknown): Record<string, unknown> {
  if (body !== null && typeof body === "object") {
    const b = body as Record<string, unknown>;
    const d = b["data"];
    if (d !== null && typeof d === "object") return d as Record<string, unknown>;
    return b;
  }
  return {};
}

async function readJson(c: Context<{ Bindings: Env }>): Promise<{ ok: true; body: unknown } | { ok: false; res: Response }> {
  const len = Number(c.req.header("Content-Length") || "0");
  if (Number.isFinite(len) && len > MAX_BODY_BYTES) {
    return { ok: false, res: c.json({ error: "body too large" }, 413) };
  }
  try {
    return { ok: true, body: await c.req.json() };
  } catch {
    return { ok: false, res: c.json({ error: "invalid json" }, 400) };
  }
}

app.get("/", (c) => c.text("", 200));

app.get("/api/1/user", async (c) => {
  const user = await apiUser(c);
  const deny = needAuth(c, user);
  if (deny) return deny;
  return c.json({ id: user!.id, name: user!.name });
});

app.get("/api/1/configs", async (c) => {
  const user = await apiUser(c);
  const deny = needAuth(c, user);
  if (deny) return deny;
  const rows = await c.env.DB.prepare(
    "SELECT id, name, content, last_used_with_version, created_at, modified_at " +
      "FROM configs WHERE user_id = ?1 ORDER BY id",
  )
    .bind(user!.id)
    .all<ConfigRow>();
  return c.json(rows.results ?? []);
});

app.get("/api/1/configs/:id", async (c) => {
  const user = await apiUser(c);
  const deny = needAuth(c, user);
  if (deny) return deny;
  const row = await c.env.DB.prepare(
    "SELECT id, name, content, last_used_with_version, created_at, modified_at " +
      "FROM configs WHERE id = ?1 AND user_id = ?2",
  )
    .bind(Number(c.req.param("id")), user!.id)
    .first<ConfigRow>();
  if (!row) return c.json({ error: "not found" }, 404);
  return c.json(row);
});

app.post("/api/1/configs", async (c) => {
  const user = await apiUser(c);
  const deny = needAuth(c, user);
  if (deny) return deny;
  const parsed = await readJson(c);
  if (!parsed.ok) return parsed.res;
  const b = unwrap(parsed.body);
  const name = typeof b["name"] === "string" ? (b["name"] as string) : "";
  if (!name) return c.json({ error: "name required" }, 400);
  const now = new Date().toISOString();
  const r = await c.env.DB.prepare(
    "INSERT INTO configs (user_id, name, content, created_at, modified_at) " +
      "VALUES (?1, ?2, '', ?3, ?3)",
  )
    .bind(user!.id, name, now)
    .run();
  const row = await c.env.DB.prepare(
    "SELECT id, name, content, last_used_with_version, created_at, modified_at " +
      "FROM configs WHERE id = ?1",
  )
    .bind(r.meta.last_row_id)
    .first<ConfigRow>();
  return c.json(row, 201);
});

app.patch("/api/1/configs/:id", async (c) => {
  const user = await apiUser(c);
  const deny = needAuth(c, user);
  if (deny) return deny;
  const id = Number(c.req.param("id"));
  const exists = await c.env.DB.prepare(
    "SELECT id FROM configs WHERE id = ?1 AND user_id = ?2",
  )
    .bind(id, user!.id)
    .first<{ id: number }>();
  if (!exists) return c.json({ error: "not found" }, 404);
  const parsed = await readJson(c);
  if (!parsed.ok) return parsed.res;
  const b = unwrap(parsed.body);
  if (typeof b["content"] !== "string") {
    return c.json({ error: "content required" }, 400);
  }
  const version =
    typeof b["last_used_with_version"] === "string"
      ? (b["last_used_with_version"] as string)
      : null;
  const now = new Date().toISOString();
  await c.env.DB.prepare(
    "UPDATE configs SET content = ?1, last_used_with_version = ?2, modified_at = ?3 " +
      "WHERE id = ?4 AND user_id = ?5",
  )
    .bind(b["content"], version, now, id, user!.id)
    .run();
  const row = await c.env.DB.prepare(
    "SELECT id, name, content, last_used_with_version, created_at, modified_at " +
      "FROM configs WHERE id = ?1",
  )
    .bind(id)
    .first<ConfigRow>();
  return c.json(row);
});

app.delete("/api/1/configs/:id", async (c) => {
  const user = await apiUser(c);
  const deny = needAuth(c, user);
  if (deny) return deny;
  const r = await c.env.DB.prepare(
    "DELETE FROM configs WHERE id = ?1 AND user_id = ?2",
  )
    .bind(Number(c.req.param("id")), user!.id)
    .run();
  if ((r.meta.changes ?? 0) === 0) return c.json({ error: "not found" }, 404);
  return new Response(null, { status: 204 });
});

app.notFound((c) => c.text("not found", 404));

export default app;
