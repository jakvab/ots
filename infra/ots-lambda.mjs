/* ============================================================
   ots-api — One-Time Secret backend (Node.js 20)
   Zero-knowledge: stores only the ciphertext blob, never the key.
   Routes (API Gateway HTTP API, $default):
     POST /api/secrets              -> create   { ct, ttlSeconds, maxViews, turnstileToken }
     POST /api/secrets/{id}/reveal  -> atomic one-time read (burns)
     GET  /api/secrets/{id}/meta    -> exists? (no count, no burn)

   Env: TABLE, TURNSTILE_SECRET, ALLOW_ORIGIN
   ============================================================ */
import { randomBytes } from "node:crypto";
import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import {
  DynamoDBDocumentClient, PutCommand, GetCommand, UpdateCommand, DeleteCommand,
} from "@aws-sdk/lib-dynamodb";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const TABLE = process.env.TABLE || "ots-secrets";
// Exact-match allowlist only (no wildcard) — locked to ots.jakvab.se.
const ALLOWED = (process.env.ALLOW_ORIGIN || "https://ots.jakvab.se")
  .split(",").map((s) => s.trim()).filter(Boolean);

const TTL_ALLOWED = new Set([3600, 86400, 604800]); // 1h, 1d, 7d
const MAX_VIEWS = 5;
const MAX_CT = 90000; // base64 chars (~64 KB plaintext)

function cors(origin) {
  const allow = ALLOWED.indexOf(origin) !== -1 ? origin : ALLOWED[0];
  return {
    "Content-Type": "application/json",
    "Access-Control-Allow-Origin": allow,
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Vary": "Origin",
  };
}
const now = () => Math.floor(Date.now() / 1000);

function clientIp(h, event) {
  const xff = (h["x-forwarded-for"] || "").split(",")[0].trim();
  return xff || event?.requestContext?.http?.sourceIp || "";
}

// Per-IP rate limit using the same table (TTL-cleaned). Fails open on error.
async function rateLimit(ip, bucket, limit, windowSec) {
  if (!ip) return true;
  const win = Math.floor(Date.now() / 1000 / windowSec);
  const id = `rl#${bucket}#${ip}#${win}`;
  try {
    const res = await ddb.send(new UpdateCommand({
      TableName: TABLE,
      Key: { id },
      UpdateExpression: "ADD #c :one SET #t = if_not_exists(#t, :ttl)",
      ExpressionAttributeNames: { "#c": "count", "#t": "ttl" },
      ExpressionAttributeValues: { ":one": 1, ":ttl": now() + windowSec * 2 },
      ReturnValues: "UPDATED_NEW",
    }));
    return (res.Attributes.count || 0) <= limit;
  } catch (e) {
    console.error("ratelimit error", e);
    return true;
  }
}

async function verifyTurnstile(token, ip) {
  const SECRET = process.env.TURNSTILE_SECRET;
  // Fail CLOSED if not configured — never silently allow creation in prod.
  if (!SECRET) { console.error("TURNSTILE_SECRET missing — denying"); return false; }
  if (!token) return false;
  try {
    const body = new URLSearchParams({ secret: SECRET, response: token });
    if (ip) body.set("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    });
    const out = await r.json().catch(() => ({ success: false }));
    return !!out.success;
  } catch {
    return false;
  }
}

export const handler = async (event) => {
  const h = event?.headers || {};
  const origin = h.origin || h.Origin || "";
  const headers = cors(origin);
  const reply = (code, obj) => ({ statusCode: code, headers, body: JSON.stringify(obj) });

  const method = event?.requestContext?.http?.method || event?.httpMethod;
  const path = event?.rawPath || event?.requestContext?.http?.path || "";
  const ip = clientIp(h, event);

  if (method === "OPTIONS") return reply(204, {});

  // POST /api/secrets
  if (method === "POST" && /^\/api\/secrets\/?$/.test(path)) {
    if (!(await rateLimit(ip, "create", 30, 600))) return reply(429, { error: "rate limited" });

    let data;
    try { data = JSON.parse(event.body || "{}"); } catch { return reply(400, { error: "invalid json" }); }

    if (!(await verifyTurnstile(String(data.turnstileToken || ""), ip))) {
      return reply(403, { error: "captcha failed" });
    }

    const ct = String(data.ct || "");
    if (!ct || ct.length > MAX_CT) return reply(400, { error: "bad ciphertext" });

    const ttlSeconds = Number(data.ttlSeconds);
    if (!TTL_ALLOWED.has(ttlSeconds)) return reply(400, { error: "bad ttl" });

    let maxViews = parseInt(data.maxViews, 10);
    if (!Number.isInteger(maxViews) || maxViews < 1) maxViews = 1;
    if (maxViews > MAX_VIEWS) maxViews = MAX_VIEWS;

    const id = randomBytes(16).toString("base64url");
    await ddb.send(new PutCommand({
      TableName: TABLE,
      Item: { id, ct, createdAt: now(), ttl: now() + ttlSeconds, views: maxViews },
    }));
    return reply(201, { id });
  }

  // POST /api/secrets/{id}/reveal  — atomic one-time read
  let m = path.match(/^\/api\/secrets\/([^/]+)\/reveal\/?$/);
  if (m && method === "POST") {
    if (!(await rateLimit(ip, "read", 60, 60))) return reply(429, { error: "rate limited" });
    const id = decodeURIComponent(m[1]);
    try {
      const res = await ddb.send(new UpdateCommand({
        TableName: TABLE,
        Key: { id },
        UpdateExpression: "SET #v = #v - :one",
        ConditionExpression: "attribute_exists(id) AND #v > :zero AND #t > :now",
        ExpressionAttributeNames: { "#v": "views", "#t": "ttl" },
        ExpressionAttributeValues: { ":one": 1, ":zero": 0, ":now": now() },
        ReturnValues: "ALL_OLD",
      }));
      const old = res.Attributes;
      const viewsLeft = (old.views || 1) - 1;
      if (viewsLeft <= 0) {
        await ddb.send(new DeleteCommand({ TableName: TABLE, Key: { id } }));
      }
      return reply(200, { ct: old.ct, viewsLeft });
    } catch (err) {
      if (err.name === "ConditionalCheckFailedException") return reply(404, { error: "gone" });
      console.error("reveal error", err);
      return reply(500, { error: "server error" });
    }
  }

  // GET /api/secrets/{id}/meta — existence only (no count), no burn
  m = path.match(/^\/api\/secrets\/([^/]+)\/meta\/?$/);
  if (m && method === "GET") {
    if (!(await rateLimit(ip, "read", 60, 60))) return reply(429, { error: "rate limited" });
    const id = decodeURIComponent(m[1]);
    const res = await ddb.send(new GetCommand({ TableName: TABLE, Key: { id } }));
    const item = res.Item;
    if (!item || item.ttl <= now() || item.views <= 0) return reply(404, { error: "gone" });
    return reply(200, { ok: true });
  }

  return reply(404, { error: "not found" });
};
