#!/usr/bin/env node
import http from "node:http"
import fs from "node:fs"
import path from "node:path"
import os from "node:os"
import { execFileSync } from "node:child_process"
import { randomBytes } from "node:crypto"
import { fileURLToPath } from "node:url"

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const isMain = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)
const CONFIG_PATH = process.env.ZEN_PROXY_CONFIG || path.join(__dirname, "zen-proxy.json")
const UI_PATH = path.join(__dirname, "public", "index.html")
const ENV = process.env

const DEFAULT_CONFIG = {
  host: ENV.HOST ?? "127.0.0.1",
  port: Number(ENV.PORT ?? 8787),
  upstream: (ENV.ZEN_URL ?? "https://opencode.ai/zen/v1").replace(/\/+$/, ""),
  // opencode 2.x official client sends `opencode/<channel>/<version>/<client>`
  // e.g. `opencode/latest/2.0.9/cli`. The free tier checks this.
  ua: ENV.ZEN_UA ?? "opencode/latest/2.0.9/cli",
  autoUA: ENV.AUTO_UA !== "0",
  uaRefreshMs: Number(ENV.UA_REFRESH_MS ?? 6 * 3600_000),
  injectSession: ENV.INJECT_SESSION !== "0",
  // "" = auto: at request time the first *healthy* free model becomes the default
  // (see effectiveDefault), so a vanished model like deepseek-v4-flash-free never
  // bricks new installs. Set an explicit model here to pin it.
  defaultModel: ENV.DEFAULT_MODEL ?? "",
  fallbackModels: JSON.parse(
    ENV.FALLBACK_MODELS ??
      JSON.stringify([
        "mimo-v2.5-free",
        "big-pickle",
        "ling-3.0-flash-fin-free",
        "deepseek-v4-flash-free",
        "nemotron-3.5-lightning-free",
        "nemotron-3-ultra-free",
        "muse-spark-1.3-contributor-free",
        "muse-spark-1.2-contributor-free",
        "jev-1.13-free",
      ]),
  ),
  modelAliases: JSON.parse(ENV.MODEL_ALIASES ?? "{}"),
  proxyKey: ENV.PROXY_KEY ?? "",
  defaultZenKey: ENV.ZEN_KEY ?? "",
  trustForwarded: ENV.TRUST_FORWARDED === "1",
  timeoutMs: Number(ENV.TIMEOUT_MS ?? 120000),
  cacheMs: Number(ENV.CACHE_MS ?? 30000),
  autoSync: ENV.AUTO_SYNC !== "0",
  autoSyncIntervalMs: Number(ENV.AUTO_SYNC_MS ?? 3600000),
}

function loadConfig() {
  try {
    const raw = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf8"))
    return { ...DEFAULT_CONFIG, ...raw }
  } catch {
    return { ...DEFAULT_CONFIG }
  }
}

let config = loadConfig()
let uiHtml = ""
try {
  uiHtml = fs.readFileSync(UI_PATH, "utf8")
} catch {}

let reloading = false
if (isMain) {
  try {
    const CONFIG_NAME = path.basename(CONFIG_PATH)
    fs.watch(path.dirname(CONFIG_PATH), (_event, filename) => {
      if (reloading) return
      if (filename && filename !== CONFIG_NAME && filename !== CONFIG_NAME + ".tmp") return
      reloading = true
      setTimeout(() => {
        config = loadConfig()
        reloading = false
        scheduleSync()
        scheduleUA()
        log("config reloaded")
      }, 150)
    })
  } catch {}
}

function saveConfig(next) {
  const merged = { ...config, ...next }
  fs.writeFileSync(CONFIG_PATH + ".tmp", JSON.stringify(merged, null, 2))
  fs.renameSync(CONFIG_PATH + ".tmp", CONFIG_PATH)
  config = merged
  return merged
}

function maskKey(k) {
  if (!k) return ""
  if (k.length <= 12) return "••••••••"
  return k.slice(0, 6) + "••••••" + k.slice(-4)
}

function sanitize(cfg) {
  const out = { ...cfg }
  if (out.proxyKey) out.proxyKey = "••••••••"
  if (out.defaultZenKey) out.defaultZenKey = maskKey(out.defaultZenKey)
  return out
}

const ALLOWED = () => new Set([...config.fallbackModels, ...Object.values(config.modelAliases)])
const requestStats = { total: 0, errors: 0, recent: [], perMinute: new Map(), window60: [] }
const VALID_MODEL_ID = /^[A-Za-z0-9._:@+/%-]+$/
const MAX_BODY = 1024 * 1024

// ---- opencode official client emulation (zen free tier, opencode 2.x) ----
// Upstream `Console` rejects free requests that don't look like opencode:
//   `403 FreeTierError: OpenCode's free tier can only be used from within OpenCode`
// Real requirements (verified by replaying the official binary):
//   - Authorization must be a real auto-provisioned `sk-...` (not `public`)
//   - User-Agent `opencode/<channel>/<version>/<client>` e.g. `opencode/latest/2.0.9/cli`
//   - x-opencode-session must be a valid descending ID (timestamp prefix), random hex fails
//   - x-opencode-client / x-opencode-project / x-session-affinity / x-session-id required
//   - body must have stream:true + >=6 real opencode tools (or full title prompt)
const OFFICIAL_TOOLS = ["edit", "glob", "grep", "question", "read", "shell",
  "skill", "subagent", "webfetch", "websearch", "write", "execute"]
const MIN_OFFICIAL_TOOLS = ["edit", "glob", "grep", "question", "read", "shell"]

function isFreeModel(id) {
  const m = String(id ?? "").split("/").pop()
  return m === "big-pickle" || m.endsWith("-free")
}

function isResponsesModel(id) {
  const m = String(id ?? "").split("/").pop()
  // mirrors docs/zen.mdx: only muse-spark contributor free uses /responses
  return m.startsWith("muse-spark") && m.endsWith("-free")
}

function mkOfficialTools(names) {
  const list = names ?? MIN_OFFICIAL_TOOLS
  return list.map((n) => ({
    type: "function",
    function: { name: n, description: `opencode tool ${n}`, parameters: { type: "object", properties: {} } },
  }))
}

function hasEnoughOfficialTools(tools) {
  if (!Array.isArray(tools)) return false
  const names = new Set(tools.map((t) => t?.function?.name ?? t?.name).filter(Boolean))
  let hits = 0
  for (const n of OFFICIAL_TOOLS) if (names.has(n)) hits++
  return hits >= 6
}

// Replicates opencode/src/id/id.ts `create(prefix, descending)`.
// Session IDs are `ses_<12hex timestamp><14 base62>` where the hex part is the
// low 48 bits of `~(Date.now()*0x1000 + counter)`. Pure random `ses_` fails.
let _idLastTs = 0
let _idCounter = 0
function genOfficialId(prefix = "ses") {
  const cur = Date.now()
  if (cur !== _idLastTs) {
    _idLastTs = cur
    _idCounter = 0
  }
  _idCounter++
  let now = BigInt(cur) * BigInt(0x1000) + BigInt(_idCounter)
  now = ~now
  const mask = (1n << 48n) - 1n
  const low = now & mask
  const hexpart = low.toString(16).padStart(12, "0")
  const chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
  const bytes = randomBytes(14)
  let rand = ""
  for (let i = 0; i < 14; i++) rand += chars[bytes[i] % 62]
  return `${prefix}_${hexpart}${rand}`
}

function genProjectId() {
  return randomBytes(20).toString("hex")
}

// opencode's free tier requires every request to carry an `x-opencode-session`
// header (upstream returns 400 `MissingSessionID` otherwise). Generic agents
// never send one, so we mint stable per-client session IDs and inject them.
const sessionPool = new Map()
function genSessionId() {
  return genOfficialId("ses")
}
function isValidOfficialSession(v) {
  return typeof v === "string" && /^ses_[0-9a-f]{12}[0-9A-Za-z]{14}$/.test(v.trim())
}
function sessionFor(req) {
  const incoming = req?.headers?.["x-opencode-session"]
  if (isValidOfficialSession(incoming)) return { value: incoming.trim(), injected: false }
  // Invalid/random incoming would 403 as non-official; replace with a valid one.
  // If injectSession is disabled and incoming is invalid, still return incoming
  // so behavior is explicit (will fail upstream, as requested).
  if (typeof incoming === "string" && incoming.trim() && !config.injectSession) {
    return { value: incoming.trim(), injected: false }
  }
  const key = req ? (ipOmit(clientIp(req)) ? "local" : clientIp(req)) : "server"
  let id = sessionPool.get(key)
  if (!id || !isValidOfficialSession(id)) {
    id = genSessionId()
    sessionPool.set(key, id)
  }
  return { value: id, injected: true }
}
function sessionHeader(req) {
  if (!config.injectSession) return undefined
  return sessionFor(req).value
}

function parseRetryAfter(v) {
  if (v == null) return 0
  const n = Number(v)
  if (Number.isFinite(n)) return Math.max(0, n)
  const t = Date.parse(v)
  if (Number.isFinite(t)) return Math.max(0, (t - Date.now()) / 1000)
  return 0
}

const RETRYABLE_ERROR_TYPES = new Set([
  "server_error",
  "api_error",
  "upstream_error",
  "ProviderError",
  "ModelError",
  "MissingSessionID",
  "RegionError",
  "model_not_found",
])
// Free-tier backends fail with 4xx errors that are really per-model / per-provider
// conditions (console says "Model is unavailable", "not supported", geo blocks…).
// Those are not client bugs — the proxy should roll to the next candidate instead
// of surfacing a hard 4xx. Real request errors (bad JSON, auth, context length…)
// still break out immediately.
function retryableUpstream(status, body) {
  if (status === 429 || status >= 500) return true
  if (status < 400 || status > 499) return false
  const t = body?.error?.type ?? body?.type ?? ""
  const msg = String(body?.error?.message ?? body?.message ?? "")
  if (RETRYABLE_ERROR_TYPES.has(t)) return true
  return /model is unavailable|not supported|only be used in opencode|no such model|does not exist|overloaded|temporarily.*limit|upstream request failed/i.test(msg)
}

function toBool(v, dflt) {
  if (v === undefined || v === null) return dflt
  if (v === false || v === 0 || v === "0" || v === "false") return false
  return true
}

function num(v, dflt) {
  const n = Number(v)
  return Number.isFinite(n) ? n : dflt
}
const syncState = { at: 0, ok: false, running: false, working: [], rateLimited: [], flaky: [], dead: [], error: "", ms: 0 }
const modelHealth = new Map()
const MAX_LOG = 500
const logLines = []
function log(message) {
  const line = { at: new Date().toISOString(), msg: message }
  logLines.push(line)
  if (logLines.length > MAX_LOG) logLines.shift()
  console.log(line.msg)
}

function recordReq(req, model, ms, status, at = Date.now()) {
  const entry = { at, ip: clientIp(req), model, status, ms }
  const key = `${entry.at}|${entry.model}|${entry.status}`
  if (!requestStats.recent.length || requestStats.recent[requestStats.recent.length - 1][0] !== key) {
    requestStats.recent.push([key, 1, ms])
    if (requestStats.recent.length > 200) requestStats.recent.shift()
  } else {
    requestStats.recent[requestStats.recent.length - 1][1]++
    requestStats.recent[requestStats.recent.length - 1][2] = ms
  }
  requestStats.total++
  if (status >= 400) requestStats.errors++
  const minute = Math.floor(entry.at / 60000)
  requestStats.perMinute.set(minute, (requestStats.perMinute.get(minute) ?? 0) + 1)
  const cutoff = entry.at - 60_000
  while (requestStats.window60.length && requestStats.window60[0] < cutoff) requestStats.window60.shift()
  requestStats.window60.push(entry.at)
  const minCutoff = minute - 60
  for (const m of [...requestStats.perMinute.keys()]) {
    if (m < minCutoff) requestStats.perMinute.delete(m)
  }
}

// Effective default model: an explicit config.defaultModel always wins; when it's
// empty (auto), prefer the first fallback model the last auto-sync saw as healthy
// so a dead hardcoded default never stalls requests.
function effectiveDefault() {
  if (config.defaultModel) return config.defaultModel
  const synced = new Set([...(syncState.working ?? []), ...(syncState.rateLimited ?? [])])
  for (const m of config.fallbackModels) if (synced.has(m)) return m
  return config.fallbackModels[0] ?? ""
}

function resolveModel(requested) {
  const dflt = effectiveDefault()
  const id = String(requested ?? "").split("/").pop()
  const target = config.modelAliases[id] || (ALLOWED().has(id) ? id : "") || dflt
  const rest = config.fallbackModels.filter((m) => m !== target)
  return { requested: id || dflt, candidates: [target, ...rest] }
}

function clientIp(req) {
  if (config.trustForwarded) {
    const xff = req.headers["x-forwarded-for"]
    if (typeof xff === "string" && xff.trim()) return xff.split(",")[0].trim()
    const xri = req.headers["x-real-ip"]
    if (typeof xri === "string" && xri.trim()) return xri.trim()
  }
  return req.socket.remoteAddress ?? ""
}

function ipOmit(ip) {
  if (!ip) return true
  const v = ip.replace(/^::ffff:/, "").toLowerCase()
  if (v === "::1" || v === "localhost" || v === "127.0.0.1" || /^127\./.test(v)) return true
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v)) return true
  if (/^fe80:/.test(v) || /^fc/.test(v) || /^fd/.test(v)) return true
  return false
}

function zenHeaders(req, auth, opts = {}) {
  // Official 2.x headers: UA + session + client + project + affinity.
  // Missing/invalid ones are minted so generic agents look like opencode.
  const headers = {
    "content-type": "application/json",
    accept: "application/json, text/event-stream",
    authorization: auth,
    "user-agent": config.ua,
  }
  if (config.injectSession === false) {
    // Explicit opt-out: forward whatever the client sent, mint nothing.
    for (const h of ["x-opencode-session", "x-opencode-client", "x-opencode-project", "x-session-affinity", "x-session-id", "x-opencode-request"]) {
      const v = req.headers[h]
      if (typeof v === "string" && v) headers[h] = v
    }
    const ip = clientIp(req)
    if (!ipOmit(ip)) headers["x-real-ip"] = ip
    return { headers, session: headers["x-opencode-session"] }
  }
  const sess = sessionFor(req)
  const session = sess.value
  headers["x-opencode-session"] = session
  headers["x-session-affinity"] = session
  headers["x-session-id"] = session
  const incomingClient = req.headers["x-opencode-client"]
  headers["x-opencode-client"] =
    typeof incomingClient === "string" && incomingClient ? incomingClient : "cli"
  const incomingProject = req.headers["x-opencode-project"]
  headers["x-opencode-project"] =
    typeof incomingProject === "string" && incomingProject ? incomingProject : (opts.project ?? genProjectId())
  // legacy passthrough (harmless)
  const legacy = req.headers["x-opencode-request"]
  if (typeof legacy === "string" && legacy) headers["x-opencode-request"] = legacy
  const ip = clientIp(req)
  if (!ipOmit(ip)) headers["x-real-ip"] = ip
  return { headers, session }
}

function bearer(req) {
  const v = req.headers["authorization"]
  return typeof v === "string" && v.startsWith("Bearer ") ? v.slice(7).trim() : ""
}

// Auto-load the anonymous `sk-...` that official opencode provisions on first
// run (`~/.local/share/opencode/opencode.db` credential integration `opencode`).
// `Bearer public` only works for GET /models; inference needs the real key.
let _localZenKey = null
let _localZenKeyAt = 0
function loadLocalZenKey() {
  const now = Date.now()
  if (_localZenKey && now - _localZenKeyAt < 60_000) return _localZenKey
  try {
    // If OPENCODE_DB is explicitly set (e.g. tests), only use that path
    // so tests can isolate from the developer's real key.
    const explicit = process.env.OPENCODE_DB
    const candidates = explicit
      ? [explicit]
      : (() => {
          const home = os.homedir() || process.env.HOME || process.env.USERPROFILE || ""
          return home ? [`${home}/.local/share/opencode/opencode.db`] : []
        })()
    for (const dbPath of candidates) {
      try {
        if (!dbPath || !fs.existsSync(dbPath)) continue
        const out = tryReadCredentialViaCli(dbPath)
        if (out) {
          _localZenKey = out
          _localZenKeyAt = now
          return out
        }
      } catch {}
    }
  } catch {}
  return _localZenKey
}

function tryReadCredentialViaCli(dbPath) {
  try {
    const sql = "SELECT value FROM credential WHERE integration_id='opencode' LIMIT 1"
    const raw = execFileSync("sqlite3", [dbPath, sql], { encoding: "utf8", timeout: 3000 })
    const txt = String(raw ?? "").trim()
    if (!txt) return null
    try {
      const j = JSON.parse(txt)
      if (j?.key) return j.key
    } catch {}
    // sqlite3 may output the JSON string directly
    const m = txt.match(/"key"\s*:\s*"([^"]+)"/)
    if (m) return m[1]
    return null
  } catch {
    return null
  }
}

function resolveZenKey() {
  if (config.defaultZenKey) return config.defaultZenKey
  const local = loadLocalZenKey()
  if (local) return local
  return ""
}

function authForUpstream(req) {
  const incoming = bearer(req)
  if (config.proxyKey) {
    if (incoming !== config.proxyKey) return null
    const zen = req.headers["x-zen-key"]
    if (typeof zen === "string" && zen && zen !== "public") return `Bearer ${zen}`
    const resolved = resolveZenKey()
    if (resolved) return `Bearer ${resolved}`
    return "Bearer public"
  }
  if (incoming && incoming !== "public") return `Bearer ${incoming}`
  const zenHeader = req.headers["x-zen-key"]
  if (typeof zenHeader === "string" && zenHeader && zenHeader !== "public") return `Bearer ${zenHeader}`
  const resolved = resolveZenKey()
  if (resolved) return `Bearer ${resolved}`
  if (config.defaultZenKey) return `Bearer ${config.defaultZenKey}`
  return "Bearer public"
}

async function readBody(req) {
  let raw = ""
  for await (const chunk of req) raw += chunk
  return raw
}

function json(res, status, data) {
  res.writeHead(status, { "content-type": "application/json" })
  res.end(JSON.stringify(data))
}

function ensureChatFreeTier(body) {
  // Returns { payload, clientStream } where payload is upstream-ready.
  // Free tier needs stream:true + >=6 real tools; non-stream clients are
  // served by upstream-streaming + destreaming (see collectChatSSE).
  const clientStream = !!body.stream
  const payload = { ...body }
  if (!hasEnoughOfficialTools(payload.tools)) {
    payload.tools = mkOfficialTools()
  }
  payload.stream = true
  if (payload.stream_options == null) payload.stream_options = { include_usage: true }
  return { payload, clientStream }
}

function ensureResponsesFreeTier(body, session) {
  const clientStream = body.stream !== false
  const payload = { ...body }
  // responses tools are flat: {type:"function", name, ...}
  const names = new Set(
    (Array.isArray(payload.tools) ? payload.tools : [])
      .map((t) => t?.name ?? t?.function?.name)
      .filter(Boolean),
  )
  let hits = 0
  for (const n of OFFICIAL_TOOLS) if (names.has(n)) hits++
  if (hits < 6) {
    payload.tools = MIN_OFFICIAL_TOOLS.map((n) => ({
      type: "function",
      name: n,
      description: `opencode tool ${n}`,
      parameters: { type: "object", properties: {} },
    }))
  }
  if (payload.store == null) payload.store = false
  if (payload.prompt_cache_key == null) payload.prompt_cache_key = session
  if (payload.include == null) payload.include = ["reasoning.encrypted_content"]
  payload.stream = true
  return { payload, clientStream }
}

async function collectChatSSE(upstreamRes) {
  const text = await upstreamRes.text()
  let content = ""
  let model = ""
  let id = `chatcmpl-${Date.now().toString(36)}`
  for (const line of text.split("\n")) {
    const t = line.trim()
    if (!t.startsWith("data:")) continue
    const payload = t.slice(5).trim()
    if (!payload || payload === "[DONE]") continue
    try {
      const j = JSON.parse(payload)
      if (typeof j.id === "string") id = j.id
      if (typeof j.model === "string") model = j.model
      const delta = j.choices?.[0]?.delta
      if (delta && typeof delta.content === "string") content += delta.content
      // some providers put final content in message instead of delta
      const msg = j.choices?.[0]?.message
      if (msg && typeof msg.content === "string" && !content) content = msg.content
    } catch {}
  }
  return { content, model, id }
}

async function collectResponsesSSE(upstreamRes) {
  const text = await upstreamRes.text()
  const deltas = []
  const completed = []
  for (const chunk of text.split("\n\n")) {
    const c = chunk.trim()
    if (!c || !c.includes("data:")) continue
    for (const line of c.split("\n")) {
      const t = line.trim()
      if (!t.startsWith("data:")) continue
      try {
        const j = JSON.parse(t.slice(5).trim())
        if (typeof j.delta === "string") deltas.push(j.delta)
        else if (j.delta && typeof j.delta.text === "string") deltas.push(j.delta.text)
        const out = j.response?.output
        if (Array.isArray(out)) {
          for (const item of out) {
            for (const p of item.content ?? []) {
              if (p?.type === "output_text" && typeof p.text === "string") completed.push(p.text)
            }
          }
        }
      } catch {}
    }
  }
  const full = completed.length ? completed.sort((a, b) => b.length - a.length)[0] : deltas.join("")
  return full
}

async function handleChat(req, res) {
  const start = Date.now()
  let body
  try {
    const raw = await readBody(req)
    if (raw.length > MAX_BODY) {
      return json(res, 413, { error: { type: "invalid_request_error", message: "request body too large" } })
    }
    body = JSON.parse(raw)
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return json(res, 400, { error: { type: "invalid_request_error", message: "body must be a JSON object" } })
    }
  } catch {
    return json(res, 400, { error: { type: "invalid_request_error", message: "invalid JSON body" } })
  }

  const { requested, candidates } = resolveModel(body.model)
  const clientStream = !!body.stream
  const auth = authForUpstream(req)
  if (!auth) {
    recordReq(req, requested, Date.now() - start, 401)
    return json(res, 401, { error: { type: "invalid_request_error", message: "invalid proxy key" } })
  }

  let lastErr = null
  let lastStatus = 502
  let used = requested
  for (const model of candidates) {
    used = model
    // Free-tier body hardening: inject official tools + force upstream stream.
    // Non-stream clients are served via destreaming below.
    let payload = { ...body, model }
    let wantStream = clientStream
    if (isFreeModel(model)) {
      const fixed = ensureChatFreeTier(payload)
      payload = fixed.payload
      // upstream always streams for free; client non-stream gets converted
      wantStream = true
    }
    const { headers: upHeaders } = zenHeaders(req, auth)
    let upstreamRes
    try {
      upstreamRes = await fetch(`${config.upstream}/chat/completions`, {
        method: "POST",
        headers: upHeaders,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(config.timeoutMs),
      })
    } catch (err) {
      lastErr = { error: { type: "upstream_error", message: err.message } }
      lastStatus = 502
      continue
    }

    if (upstreamRes.ok) {
      if (clientStream) {
        const contentType = upstreamRes.headers.get("content-type") ?? "text/event-stream"
        // Upstream is SSE; relay with model rewritten.
        relayStream(req, res, upstreamRes, requested)
        res.on("finish", () => recordReq(req, `${requested}→${model}`, Date.now() - start, 200))
        return
      }
      // Client asked non-stream but upstream streamed (free-tier requirement):
      // collect SSE and return a standard chat.completion JSON.
      try {
        const { content, model: upModel, id } = await collectChatSSE(upstreamRes)
        const out = {
          id: id || `chatcmpl-${Date.now().toString(36)}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: requested,
          choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }],
        }
        recordReq(req, `${requested}→${model}`, Date.now() - start, 200)
        return json(res, 200, out)
      } catch {
        recordReq(req, requested, Date.now() - start, 502)
        return json(res, 502, { error: { type: "upstream_error", message: "bad upstream response" } })
      }
    }

    try {
      lastErr = await upstreamRes.json()
    } catch {
      // Upstream SSE error (stream:true always) may not be JSON; read text.
      try {
        const t = await upstreamRes.text()
        lastErr = { error: { type: "upstream_error", message: t.slice(0, 500) } }
      } catch {
        lastErr = { error: { type: "upstream_error", message: `upstream returned ${upstreamRes.status}` } }
      }
    }
    lastStatus = upstreamRes.status
    // Try the next candidate not only on 429/5xx but also when the upstream
    // reports a model/environment-level failure (e.g. a provider that is
    // temporarily "unavailable", a geo-blocked free model, or a stale model id)
    // so one dead model doesn't brick the whole request.
    if (retryableUpstream(upstreamRes.status, lastErr)) {
      const wait = Math.min(parseRetryAfter(upstreamRes.headers.get("retry-after")) * 1000, 3000)
      if (wait > 0) await new Promise((r) => setTimeout(r, wait))
      continue
    }
    break
  }

  recordReq(req, `${requested}→${used}`, Date.now() - start, lastStatus)
  res.writeHead(lastStatus, { "content-type": "application/json" })
  res.end(
    JSON.stringify(lastErr ?? { error: { type: "free_usage_limit_error", message: "all free models are rate-limited" } }),
  )
}

async function handleResponses(req, res) {
  const start = Date.now()
  let body
  try {
    const raw = await readBody(req)
    if (raw.length > MAX_BODY) {
      return json(res, 413, { error: { type: "invalid_request_error", message: "request body too large" } })
    }
    body = JSON.parse(raw)
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      return json(res, 400, { error: { type: "invalid_request_error", message: "body must be a JSON object" } })
    }
  } catch {
    return json(res, 400, { error: { type: "invalid_request_error", message: "invalid JSON body" } })
  }

  const { requested, candidates } = resolveModel(body.model)
  const clientStream = body.stream !== false
  const auth = authForUpstream(req)
  if (!auth) {
    recordReq(req, requested, Date.now() - start, 401)
    return json(res, 401, { error: { type: "invalid_request_error", message: "invalid proxy key" } })
  }

  let lastErr = null
  let lastStatus = 502
  let used = requested
  for (const model of candidates) {
    used = model
    let payload = { ...body, model }
    if (isFreeModel(model)) {
      // Responses free also needs tools + stream; reuse session for cache key.
      const { headers: tmp } = zenHeaders(req, auth)
      const sess = tmp["x-opencode-session"]
      const fixed = ensureResponsesFreeTier(payload, sess)
      payload = fixed.payload
    }
    const { headers: upHeaders } = zenHeaders(req, auth)
    let upstreamRes
    try {
      upstreamRes = await fetch(`${config.upstream}/responses`, {
        method: "POST",
        headers: upHeaders,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(config.timeoutMs),
      })
    } catch (err) {
      lastErr = { error: { type: "upstream_error", message: err.message } }
      lastStatus = 502
      continue
    }

    if (upstreamRes.ok) {
      if (clientStream) {
        relayResponsesStream(req, res, upstreamRes, requested)
        res.on("finish", () => recordReq(req, `${requested}→${model}`, Date.now() - start, 200))
        return
      }
      try {
        const full = await collectResponsesSSE(upstreamRes)
        const out = {
          id: `resp_${Date.now().toString(36)}`,
          object: "response",
          model: requested,
          output: [{
            type: "message",
            role: "assistant",
            content: [{ type: "output_text", text: full }],
          }],
        }
        recordReq(req, `${requested}→${model}`, Date.now() - start, 200)
        return json(res, 200, out)
      } catch {
        recordReq(req, requested, Date.now() - start, 502)
        return json(res, 502, { error: { type: "upstream_error", message: "bad upstream response" } })
      }
    }

    try {
      lastErr = await upstreamRes.json()
    } catch {
      try {
        const t = await upstreamRes.text()
        lastErr = { error: { type: "upstream_error", message: t.slice(0, 500) } }
      } catch {
        lastErr = { error: { type: "upstream_error", message: `upstream returned ${upstreamRes.status}` } }
      }
    }
    lastStatus = upstreamRes.status
    if (retryableUpstream(upstreamRes.status, lastErr)) {
      const wait = Math.min(parseRetryAfter(upstreamRes.headers.get("retry-after")) * 1000, 3000)
      if (wait > 0) await new Promise((r) => setTimeout(r, wait))
      continue
    }
    break
  }

  recordReq(req, `${requested}→${used}`, Date.now() - start, lastStatus)
  res.writeHead(lastStatus, { "content-type": "application/json" })
  res.end(
    JSON.stringify(lastErr ?? { error: { type: "free_usage_limit_error", message: "all free models are rate-limited" } }),
  )
}

function relayResponsesStream(req, res, upstreamRes, requested) {
  // Responses SSE is `event: ...\ndata: {...}\n\n`; rewrite embedded model fields.
  res.writeHead(200, {
    "content-type": upstreamRes.headers.get("content-type") ?? "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  })
  const reader = upstreamRes.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ""
  const ctrl = new AbortController()
  const onAbort = () => ctrl.abort()
  if (req.signal?.addEventListener) req.signal.addEventListener("abort", onAbort)
  const timer = setTimeout(() => ctrl.abort(), config.timeoutMs)
  ctrl.signal.addEventListener("abort", () => {
    reader.cancel().catch(() => {})
  })
  const cleanup = () => {
    clearTimeout(timer)
    if (req.signal?.removeEventListener) req.signal.removeEventListener("abort", onAbort)
  }
  const pump = async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) {
          if (buffer.trim()) res.write(buffer)
          res.end()
          return
        }
        buffer += decoder.decode(value, { stream: true })
        let idx
        while ((idx = buffer.indexOf("\n\n")) !== -1) {
          const block = buffer.slice(0, idx)
          buffer = buffer.slice(idx + 2)
          if (!block.trim()) continue
          // rewrite model inside data payloads
          const lines = block.split("\n")
          const out = []
          for (const line of lines) {
            if (line.startsWith("data: ")) {
              const payload = line.slice(6)
              try {
                const j = JSON.parse(payload)
                if (j?.response?.model) j.response.model = requested
                if (j?.model) j.model = requested
                out.push(`data: ${JSON.stringify(j)}`)
              } catch {
                out.push(line)
              }
            } else {
              out.push(line)
            }
          }
          res.write(out.join("\n") + "\n\n")
        }
      }
    } catch {
      res.end()
    } finally {
      cleanup()
    }
  }
  return pump()
}

function relayStream(req, res, upstreamRes, requested) {
  res.writeHead(200, {
    "content-type": upstreamRes.headers.get("content-type") ?? "text/event-stream",
    "cache-control": "no-cache",
    connection: "keep-alive",
  })
  const reader = upstreamRes.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ""
  const ctrl = new AbortController()
  const onAbort = () => ctrl.abort()
  if (req.signal?.addEventListener) req.signal.addEventListener("abort", onAbort)
  const timer = setTimeout(() => ctrl.abort(), config.timeoutMs)
  ctrl.signal.addEventListener("abort", () => {
    reader.cancel().catch(() => {})
  })
  const cleanup = () => {
    clearTimeout(timer)
    if (req.signal?.removeEventListener) req.signal.removeEventListener("abort", onAbort)
  }
  const pump = async () => {
    try {
      for (;;) {
        const { done, value } = await reader.read()
        if (done) {
          if (buffer.trim()) res.write(buffer)
          res.end()
          return
        }
        buffer += decoder.decode(value, { stream: true })
        let idx
        while ((idx = buffer.indexOf("\n\n")) !== -1) {
          const block = buffer.slice(0, idx)
          buffer = buffer.slice(idx + 2)
          const out = rewriteSSE(block, requested)
          if (out) res.write(out)
        }
      }
    } catch {
      res.end()
    } finally {
      cleanup()
    }
  }
  return pump()
}

function rewriteSSE(block, requested) {
  if (!block.trim()) return null
  const lines = block.split("\n")
  const out = []
  for (const line of lines) {
    if (line.startsWith("data: ")) {
      const payload = line.slice(6)
      if (payload === "[DONE]") {
        out.push(line)
        continue
      }
      try {
        const parsed = JSON.parse(payload)
        if (parsed && typeof parsed === "object" && "model" in parsed) parsed.model = requested
        out.push(`data: ${JSON.stringify(parsed)}`)
      } catch {
        out.push(line)
      }
    } else {
      out.push(line)
    }
  }
  return out.join("\n") + "\n\n"
}

let modelsCache = { at: 0, data: [], ok: false }
let modelsFetching = null
async function fetchModels() {
  if (modelsCache.at && Date.now() - modelsCache.at < config.cacheMs) return modelsCache
  if (modelsFetching) return modelsFetching
  modelsFetching = (async () => {
    try {
      const res = await fetch(`${config.upstream}/models`, {
        headers: { "user-agent": config.ua },
        signal: AbortSignal.timeout(15_000),
      })
      if (res.ok) {
        const parsed = await res.json()
        const upstreamModels = parsed.data ?? []
        const allowed = ALLOWED()
        const dead = new Set(syncState.dead)
        let free
        if (syncState.ok && syncState.at) {
          const live = new Set([...syncState.working, ...syncState.rateLimited])
          free = upstreamModels.filter((m) => (live.has(m.id) || allowed.has(m.id)) && !dead.has(m.id))
        } else {
          free = upstreamModels.filter((m) => (m.id.endsWith("-free") || m.id === "big-pickle" || allowed.has(m.id)) && !dead.has(m.id))
        }
        modelsCache = { at: Date.now(), data: free, ok: true }
      } else {
        modelsCache = { at: Date.now(), data: modelsCache.data, ok: false }
      }
    } catch {
      modelsCache = { at: Date.now(), data: modelsCache.data, ok: false }
    }
    return modelsCache
  })()
  try {
    return await modelsFetching
  } finally {
    modelsFetching = null
  }
}

async function syncModels() {
  if (syncState.running) return syncState
  syncState.running = true
  syncState.at = Date.now()
  const start = Date.now()
  try {
    const res = await fetch(`${config.upstream}/models`, {
      headers: { "user-agent": config.ua },
      signal: AbortSignal.timeout(15_000),
    })
    if (!res.ok) throw new Error(`upstream /models → ${res.status}`)
    const parsed = await res.json()
    const upstreamIds = new Set((parsed.data ?? []).map((m) => m.id))
    const current = [...config.fallbackModels].filter((id) => VALID_MODEL_ID.test(id))
    const candidates = [...new Set([...current, ...[...upstreamIds].filter((id) => (id.endsWith("-free") || id === "big-pickle") && VALID_MODEL_ID.test(id))])]
    const working = []
    const rateLimited = []
    const dead = []
    const flaky = []
    const removeFromCurrent = new Set()
    const auth = (() => {
      if (config.defaultZenKey) return `Bearer ${config.defaultZenKey}`
      const local = loadLocalZenKey()
      if (local) return `Bearer ${local}`
      return "Bearer public"
    })()
    let idx = 0
    const probe = async () => {
      while (idx < candidates.length) {
        const id = candidates[idx++]
        try {
          const isResp = isResponsesModel(id)
          const sess = genOfficialId("ses")
          const proj = genProjectId()
          const url = isResp ? `${config.upstream}/responses` : `${config.upstream}/chat/completions`
          // Free-tier probe must look like opencode: valid session + UA + tools + stream.
          // Minimal ping bodies without tools always 403 FreeTierError.
          const headers = {
            "content-type": "application/json",
            accept: "application/json, text/event-stream",
            authorization: auth,
            "user-agent": config.ua,
            "x-opencode-session": sess,
            "x-opencode-client": "cli",
            "x-opencode-project": proj,
            "x-session-affinity": sess,
            "x-session-id": sess,
          }
          const probeBody = isResp
            ? {
                model: id,
                input: [{ role: "user", content: [{ type: "input_text", text: "ping" }] }],
                tools: MIN_OFFICIAL_TOOLS.map((n) => ({
                  type: "function", name: n,
                  description: `opencode tool ${n}`,
                  parameters: { type: "object", properties: {} },
                })),
                store: false,
                prompt_cache_key: sess,
                include: ["reasoning.encrypted_content"],
                stream: true,
              }
            : {
                model: id,
                messages: [{ role: "user", content: "ping" }],
                tools: mkOfficialTools(),
                stream: true,
                stream_options: { include_usage: true },
              }
          const r = await fetch(url, {
            method: "POST",
            headers,
            body: JSON.stringify(probeBody),
            signal: AbortSignal.timeout(Math.min(config.timeoutMs, 30_000)),
          })
          let bodyErr = ""
          try {
            const j = await r.json()
            if (j && (j.error || j.type === "error")) {
              const e = j.error ?? j
              bodyErr = (e.type || "") + " " + (e.message || "")
            }
          } catch {}
          if (r.ok && !bodyErr) { working.push(id); modelHealth.set(id, 0) }
          else if (r.status === 429 && !bodyErr) { rateLimited.push(id); modelHealth.set(id, 0) }
          else {
            // Model gone / not supported upstream ("Model hy3-free is not supported",
            // "does not exist", 404…) → remove immediately, no grace period needed.
            const notSupported =
              r.status === 404 ||
              /model_not_found|no such model|does not exist|not supported/i.test(bodyErr)
            // Key/auth problems are not model problems — never punish a healthy
            // model because the configured key is bad.
            const authErr = /AuthError|invalid api key|missing api key/i.test(bodyErr)
            const fails = (modelHealth.get(id) ?? 0) + 1
            if (notSupported) { dead.push(id); removeFromCurrent.add(id) }
            else if (authErr) { flaky.push(id) }
            else {
              modelHealth.set(id, fails)
              if (fails >= 2) { dead.push(id); removeFromCurrent.add(id) }
              else { flaky.push(id) }
            }
          }
        } catch {
          const fails = (modelHealth.get(id) ?? 0) + 1
          modelHealth.set(id, fails)
          if (fails >= 2) { dead.push(id); removeFromCurrent.add(id) }
          else flaky.push(id)
        }
      }
    }
    await Promise.all([probe(), probe(), probe()])
    const newList = current.filter((id) => !removeFromCurrent.has(id))
    for (const id of working) if (!newList.includes(id)) newList.push(id)
    const changed = newList.join(",") !== current.join(",")
    if (changed && newList.length) {
      config.fallbackModels = newList
      try { saveConfig({ fallbackModels: newList }) } catch {}
      log(`auto-sync: updated model list (${working.length} ok, ${rateLimited.length} rate-limited, ${flaky.length} flaky, ${dead.length} dead)`)
    } else {
      log(`auto-sync: list unchanged (${working.length} ok, ${rateLimited.length} rate-limited, ${flaky.length} flaky, ${dead.length} dead)`)
    }
    syncState.working = working
    syncState.rateLimited = rateLimited
    syncState.flaky = flaky
    syncState.dead = dead
    syncState.error = ""
    syncState.ok = true
    modelsCache = { at: 0, data: [], ok: true }
  } catch (err) {
    syncState.ok = false
    syncState.error = err.message
    log(`auto-sync failed: ${err.message}`)
  }
  syncState.ms = Date.now() - start
  syncState.running = false
  return syncState
}

let syncTimer = null
function scheduleSync() {
  if (syncTimer) clearTimeout(syncTimer)
  if (!config.autoSync || config.autoSyncIntervalMs <= 0) return
  syncTimer = setTimeout(async () => {
    await syncModels()
    scheduleSync()
  }, config.autoSyncIntervalMs)
  if (syncTimer.unref) syncTimer.unref()
}

// Auto-UA: opencode ships new versions regularly; keeping the injected
// `opencode/<version>` User-Agent current future-proofs the free-tier unlock.
const uaAutoState = { at: 0, version: "" }
async function refreshUA(force = false) {
  if (!config.autoUA) return ""
  const now = Date.now()
  if (!force && uaAutoState.at && now - uaAutoState.at < config.uaRefreshMs) return uaAutoState.version
  uaAutoState.at = now
  try {
    // Official CLI is now `@opencode/cli` (2.x); old `opencode-ai` is stale.
    // Try new package first, fall back to legacy.
    let v = ""
    for (const pkg of ["@opencode/cli", "opencode-ai"]) {
      try {
        const res = await fetch(`https://registry.npmjs.org/${pkg}/latest`, {
          headers: { accept: "application/json" },
          signal: AbortSignal.timeout(10_000),
        })
        if (!res.ok) continue
        const data = await res.json()
        const cand = String(data?.version ?? "")
        if (/^\d+\.\d+\.\d+/.test(cand)) {
          v = cand
          break
        }
      } catch {}
    }
    if (!v) return uaAutoState.version
    uaAutoState.version = v
    const next = `opencode/latest/${v}/cli`
    if (next !== config.ua && /^opencode\/(latest\/)?\d+\.\d+\.\d+(\/cli)?$/.test(config.ua)) {
      log(`auto-UA: opencode ${v} released — updating User-Agent`)
      try { saveConfig({ ua: next }) } catch {}
    }
    return v
  } catch {
    return uaAutoState.version
  }
}

let uaTimer = null
function scheduleUA() {
  if (uaTimer) clearTimeout(uaTimer)
  if (!config.autoUA || config.uaRefreshMs <= 0) return
  uaTimer = setTimeout(async () => {
    await refreshUA()
    scheduleUA()
  }, config.uaRefreshMs)
  if (uaTimer.unref) uaTimer.unref()
}

async function handleModels(req, res) {
  if (!adminAuth(req, res)) return
  const cache = await fetchModels()
  json(res, 200, { object: "list", data: cache.data, ok: cache.ok })
}

function adminAuth(req, res) {
  if (config.proxyKey && bearer(req) !== config.proxyKey) {
    json(res, 401, { error: "unauthorized" })
    return false
  }
  return true
}

async function handleApiConfig(req, res) {
  if (!adminAuth(req, res)) return
  if (req.method === "GET") return json(res, 200, { config: sanitize(config) })
  if (req.method === "PUT") {
    try {
      const body = JSON.parse(await readBody(req))
      if (typeof body !== "object" || body === null || Array.isArray(body)) throw new Error("body must be a JSON object")
      const cleaned = {}
      for (const key of Object.keys(DEFAULT_CONFIG)) {
        if (key in body) cleaned[key] = body[key]
      }
      cleaned.port = num(cleaned.port ?? config.port, config.port)
      cleaned.timeoutMs = num(cleaned.timeoutMs ?? config.timeoutMs, config.timeoutMs)
      cleaned.cacheMs = num(cleaned.cacheMs ?? config.cacheMs, config.cacheMs)
      cleaned.autoSyncIntervalMs = num(cleaned.autoSyncIntervalMs ?? config.autoSyncIntervalMs, config.autoSyncIntervalMs)
      cleaned.uaRefreshMs = num(cleaned.uaRefreshMs ?? config.uaRefreshMs, config.uaRefreshMs)
      if (cleaned.cacheMs < 0) cleaned.cacheMs = config.cacheMs
      cleaned.trustForwarded = toBool(cleaned.trustForwarded, config.trustForwarded)
      cleaned.autoSync = toBool(cleaned.autoSync, config.autoSync)
      cleaned.autoUA = toBool(cleaned.autoUA, config.autoUA)
      cleaned.injectSession = toBool(cleaned.injectSession, config.injectSession)
      if (cleaned.proxyKey === "••••••••") cleaned.proxyKey = config.proxyKey
      if (cleaned.defaultZenKey === sanitize({ defaultZenKey: config.defaultZenKey }).defaultZenKey) {
        cleaned.defaultZenKey = config.defaultZenKey
      }
      if (!Array.isArray(cleaned.fallbackModels)) cleaned.fallbackModels = config.fallbackModels
      if (typeof cleaned.modelAliases !== "object" || cleaned.modelAliases === null) {
        cleaned.modelAliases = config.modelAliases
      }
      saveConfig(cleaned)
      scheduleSync()
      scheduleUA()
      log("config updated via UI")
      return json(res, 200, { config: sanitize(config) })
    } catch (err) {
      return json(res, 400, { error: err.message })
    }
  }
  return json(res, 405, { error: "method not allowed" })
}

async function handleStatus(req, res) {
  if (!adminAuth(req, res)) return
  const cache = await fetchModels()
  const now = Date.now()
  while (requestStats.window60.length && requestStats.window60[0] < now - 60_000) requestStats.window60.shift()
  const minute = Math.floor(now / 60000)
  const lastMinute = requestStats.window60.length
  let last5m = 0
  for (const [m, c] of requestStats.perMinute) {
    if (minute - m <= 5) last5m += c
  }
  const authMode = config.defaultZenKey ? (config.proxyKey ? "proxy+byok" : "byok") : config.proxyKey ? "proxy" : "public"
  json(res, 200, {
    uptime: Math.floor(process.uptime()),
    upstreamOk: cache.ok,
    upstream: config.upstream,
    ua: config.ua,
    uaAutoVersion: uaAutoState.version,
    defaultModel: config.defaultModel,
    effectiveDefault: effectiveDefault(),
    auth: { mode: authMode, zenKey: maskKey(config.defaultZenKey), proxyKey: !!config.proxyKey },
    models: { total: cache.data.length, allowed: ALLOWED().size },
    sync: {
      ok: syncState.ok,
      at: syncState.at,
      running: syncState.running,
      ms: syncState.ms,
      working: [...syncState.working],
      rateLimited: [...syncState.rateLimited],
      flaky: [...syncState.flaky],
      dead: [...syncState.dead],
      error: syncState.error,
    },
    requests: { total: requestStats.total, errors: requestStats.errors, lastMinute, last5m },
    recent: requestStats.recent.map(([k, count, ms]) => ({ ...parseKey(k), count, ms })),
  })
}

function parseKey(key) {
  const [at, model, status] = key.split("|")
  return { at: Number(at), model, status: Number(status) }
}

async function handleTest(req, res) {
  if (!adminAuth(req, res)) return
  try {
    const body = JSON.parse(await readBody(req))
    const model = String(body.model ?? effectiveDefault())
    const start = Date.now()
    // Explicit key override lets the dashboard "test my key" flow verify a typed
    // key before saving it. Falls back to the normal auth path otherwise.
    const auth =
      typeof body.zenKey === "string" && body.zenKey.trim()
        ? `Bearer ${body.zenKey.trim()}`
        : (authForUpstream(req) ?? "Bearer public")
    const isRespTest = isResponsesModel(model)
    const testSess = genOfficialId("ses")
    const testProj = genProjectId()
    const testUrl = isRespTest ? `${config.upstream}/responses` : `${config.upstream}/chat/completions`
    const testBody = isRespTest
      ? {
          model,
          input: [{ role: "user", content: [{ type: "input_text", text: "ping" }] }],
          tools: MIN_OFFICIAL_TOOLS.map((n) => ({
            type: "function", name: n,
            description: `opencode tool ${n}`,
            parameters: { type: "object", properties: {} },
          })),
          store: false,
          prompt_cache_key: testSess,
          include: ["reasoning.encrypted_content"],
          stream: false,
        }
      : {
          model,
          messages: [{ role: "user", content: "ping" }],
          tools: mkOfficialTools(),
          stream: false,
          // NOTE: free tier requires stream:true upstream; the test endpoint
          // uses non-stream for simplicity and will 403 on free models.
          // For accurate free-model health, use /api/sync (which streams).
        }
    // For free models, force stream:true for the probe (else always 403).
    if (isFreeModel(model)) {
      testBody.stream = true
      if (!isRespTest) testBody.stream_options = { include_usage: true }
    }
    const upstreamRes = await fetch(testUrl, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json, text/event-stream",
        authorization: auth,
        "user-agent": config.ua,
        "x-opencode-session": testSess,
        "x-opencode-client": "cli",
        "x-opencode-project": testProj,
        "x-session-affinity": testSess,
        "x-session-id": testSess,
      },
      body: JSON.stringify(testBody),
      signal: AbortSignal.timeout(config.timeoutMs),
    })
    let detail = ""
    try {
      const ctype = upstreamRes.headers.get("content-type") ?? ""
      if (ctype.includes("text/event-stream")) {
        const t = await upstreamRes.text()
        detail = t.slice(0, 300)
        // SSE 200 means working even though it's not JSON
        if (upstreamRes.ok && !detail.includes("FreeTierError") && !detail.includes("error")) {
          detail = "stream ok: " + detail.slice(0, 200)
        }
      } else {
        const parsed = await upstreamRes.json()
        detail = parsed.error?.message ?? parsed.choices?.[0]?.message?.content ?? ""
      }
    } catch {}
    json(res, 200, { ok: upstreamRes.ok, model, status: upstreamRes.status, ms: Date.now() - start, detail })
  } catch (err) {
    json(res, 400, { ok: false, error: err.message })
  }
}

function handleLogs(req, res) {
  if (!adminAuth(req, res)) return
  const n = Number(new URL(req.url, "http://x").searchParams.get("n") ?? 200)
  json(res, 200, { logs: logLines.slice(-n) })
}

async function router(req, res) {
  const url = new URL(req.url, `http://${req.headers.host ?? "localhost"}`)
  const p = url.pathname

  if (req.method === "GET" && (p === "/" || p === "/index.html" || p === "/ui")) {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" })
    return res.end(uiHtml || "<h1>UI not found</h1>")
  }
  if (req.method === "GET" && p.startsWith("/assets/")) {
    const file = path.join(__dirname, "assets", path.basename(p))
    try {
      const data = fs.readFileSync(file)
      const types = {
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".svg": "image/svg+xml", ".webp": "image/webp", ".gif": "image/gif", ".ico": "image/x-icon",
      }
      res.writeHead(200, {
        "content-type": types[path.extname(file).toLowerCase()] ?? "application/octet-stream",
        "cache-control": "public, max-age=3600",
      })
      return res.end(data)
    } catch {
      return json(res, 404, { error: "not found" })
    }
  }
  if (req.method === "GET" && p === "/health") {
    const cache = await fetchModels()
    return json(res, 200, { ok: cache.ok, upstream: config.upstream })
  }

  if (p.startsWith("/api/")) {
    if (p === "/api/config") return handleApiConfig(req, res)
    if (p === "/api/status" && req.method === "GET") return handleStatus(req, res)
    if (p === "/api/test" && req.method === "POST") return handleTest(req, res)
    if (p === "/api/logs" && req.method === "GET") return handleLogs(req, res)
    if (p === "/api/sync" && req.method === "POST") {
      if (!adminAuth(req, res)) return
      syncModels().then((s) => json(res, 200, { ok: s.ok, ...s }))
      return
    }
    if (p === "/api/reset" && req.method === "POST") {
      if (!adminAuth(req, res)) return
      requestStats.total = 0
      requestStats.errors = 0
      requestStats.recent = []
      requestStats.perMinute.clear()
      requestStats.window60 = []
      return json(res, 200, { ok: true })
    }
    return json(res, 404, { error: "not found" })
  }

  if (req.method === "GET" && (p === "/v1/models" || p === "/models")) return handleModels(req, res)
  if (req.method === "POST" && (p === "/v1/chat/completions" || p === "/chat/completions")) {
    return handleChat(req, res)
  }
  if (req.method === "POST" && (p === "/v1/responses" || p === "/responses")) {
    return handleResponses(req, res)
  }
  json(res, 404, { error: { type: "not_found", message: p } })
}

const server = http.createServer(router)

server.requestTimeout = 0
server.headersTimeout = 60_000

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    console.error(`Port ${config.port} already in use. Set PORT or edit zen-proxy.json.`)
  } else {
    console.error(err)
  }
  process.exit(1)
})

if (isMain) {
  server.listen(config.port, config.host, () => {
    log(`zen-proxy listening on http://${config.host}:${config.port}`)
    log(`upstream ${config.upstream}  UA ${config.ua}  default ${config.defaultModel || "(auto)"}`)
    log(`config file: ${CONFIG_PATH}  UI: /`)
    if (!fs.existsSync(CONFIG_PATH)) {
      try {
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2))
        log(`created default config: ${CONFIG_PATH}`)
      } catch {}
    }
    if (config.autoUA) {
      log("auto-UA enabled — checking for new opencode releases…")
      refreshUA()
    }
    if (config.autoSync) {
      log(`auto-sync enabled (every ${Math.round(config.autoSyncIntervalMs / 60000)} min) — probing free models…`)
      syncModels()
    }
    scheduleSync()
    scheduleUA()
  })
}

export {
  isMain,
  config,
  loadConfig,
  saveConfig,
  sanitize,
  maskKey,
  resolveModel,
  effectiveDefault,
  authForUpstream,
  clientIp,
  ipOmit,
  zenHeaders,
  recordReq,
  requestStats,
  syncState,
  handleChat,
  handleResponses,
  relayStream,
  relayResponsesStream,
  rewriteSSE,
  fetchModels,
  handleModels,
  handleApiConfig,
  handleStatus,
  handleTest,
  handleLogs,
  logLines,
  router,
  syncModels,
  scheduleSync,
  refreshUA,
  scheduleUA,
  parseRetryAfter,
  retryableUpstream,
  toBool,
  sessionFor,
  sessionHeader,
  genOfficialId,
  genProjectId,
  mkOfficialTools,
  hasEnoughOfficialTools,
  isFreeModel,
  isResponsesModel,
  ensureChatFreeTier,
  ensureResponsesFreeTier,
  loadLocalZenKey,
  resolveZenKey,
  MAX_BODY,
  VALID_MODEL_ID,
}