import { field, logger } from "@coder/logger"
import * as crypto from "crypto"
import * as express from "express"
import * as http from "http"
import * as https from "https"
import * as path from "path"
import { HttpCode, HttpError } from "../common/http"

/**
 * Raised when x-service rejects the id-token (HTTP 401).
 */
export class TokenRejectedError extends Error {}

/**
 * Raised when x-service cannot find the session (non-SUC0000 return code or
 * missing artifactsPath).
 */
export class SessionNotFoundError extends Error {}

/**
 * Raised when x-service cannot be reached (network error, timeout, or 5xx).
 */
export class UpstreamError extends Error {}

/**
 * Supported JWT signature algorithms.  `none` and the HMAC family (`HS*`) are
 * rejected to prevent algorithm-confusion attacks.
 */
const SIGNATURE_ALGORITHMS: Record<string, { hash: string; dsaEncoding?: "ieee-p1363" }> = {
  RS256: { hash: "sha256" },
  RS384: { hash: "sha384" },
  RS512: { hash: "sha512" },
  PS256: { hash: "sha256" },
  PS384: { hash: "sha384" },
  PS512: { hash: "sha512" },
  ES256: { hash: "sha256", dsaEncoding: "ieee-p1363" },
  ES384: { hash: "sha384", dsaEncoding: "ieee-p1363" },
  ES512: { hash: "sha512", dsaEncoding: "ieee-p1363" },
}

/** How long a fetched JWK set stays valid when no TTL is configured. */
const DEFAULT_JWK_CACHE_TTL = 300000
/** Timeout in milliseconds for fetching the JWK set from an auth domain. */
const JWK_REQUEST_TIMEOUT = 5000
/** Refetch at most this often when a token references an unknown kid. */
const JWK_UNKNOWN_KID_COOLDOWN = 10000
/** Do not retry a failed JWK fetch more often than this. */
const JWK_FAILURE_COOLDOWN = 5000

interface JwkCacheEntry {
  keys: Map<string, crypto.KeyObject>
  fetchedAt: number
  expireAt: number
}

const jwkCache = new Map<string, JwkCacheEntry>()
const inflightJwkFetches = new Map<string, Promise<JwkCacheEntry>>()
const jwkFailureAt = new Map<string, number>()

/**
 * Fetch and parse the JWK set published by an auth domain at /jwk.
 *
 * domain must include a protocol (http:// or https://).  TLS certificates are
 * not verified for the same reason as x-service requests.
 */
const requestJwks = async (domain: string): Promise<Map<string, crypto.KeyObject>> => {
  const url = `${domain.replace(/\/+$/, "")}/jwk`
  const request = url.startsWith("https://") ? https.request : http.request
  // rejectUnauthorized is only read by https; harmless for plain http.
  const options: https.RequestOptions = {
    timeout: JWK_REQUEST_TIMEOUT,
    rejectUnauthorized: false,
    secureOptions:
      crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
  }

  let response: http.IncomingMessage
  try {
    response = await new Promise((resolve, reject) => {
      const req = request(url, options, resolve)
      req.on("timeout", () => req.destroy(new Error(`jwk request timed out after ${JWK_REQUEST_TIMEOUT}ms`)))
      req.on("error", reject)
      req.end()
    })
  } catch (error) {
    throw new UpstreamError(
      error instanceof Error ? `auth domain unreachable: ${error.message}` : "auth domain unreachable",
    )
  }

  const status = response.statusCode || 0
  if (status < 200 || status >= 300) {
    response.resume()
    throw new UpstreamError(`auth domain returned ${status} for /jwk`)
  }

  let body: unknown
  try {
    const text = await new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = []
      response.on("data", (chunk: Buffer) => chunks.push(chunk))
      response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")))
      response.on("error", reject)
    })
    body = JSON.parse(text)
  } catch {
    throw new UpstreamError("auth domain returned an invalid /jwk response")
  }

  // Accept either a bare array or the standard { keys: [...] } wrapper.
  const items = Array.isArray(body)
    ? body
    : body && typeof body === "object" && Array.isArray((body as { keys?: unknown }).keys)
      ? (body as { keys: unknown[] }).keys
      : undefined
  if (!items) {
    throw new UpstreamError("auth domain returned no JWK keys")
  }

  const keys = new Map<string, crypto.KeyObject>()
  for (const item of items) {
    try {
      const key = crypto.createPublicKey({ key: item as crypto.JsonWebKey, format: "jwk" })
      const kid =
        item && typeof item === "object" && typeof (item as { kid?: unknown }).kid === "string"
          ? (item as { kid: string }).kid
          : ""
      keys.set(kid, key)
    } catch {
      // Skip individual keys that cannot be parsed.
    }
  }
  if (keys.size === 0) {
    throw new UpstreamError("auth domain returned no usable JWK keys")
  }
  return keys
}

/**
 * Fetch the JWK set for a domain, deduplicating concurrent fetches and caching
 * the result for cacheTtl milliseconds.
 */
const fetchJwks = async (domain: string, cacheTtl: number): Promise<JwkCacheEntry> => {
  const existing = inflightJwkFetches.get(domain)
  if (existing) {
    return existing
  }
  const promise = (async () => {
    const keys = await requestJwks(domain)
    const now = Date.now()
    const entry: JwkCacheEntry = { keys, fetchedAt: now, expireAt: now + cacheTtl }
    jwkCache.set(domain, entry)
    jwkFailureAt.delete(domain)
    return entry
  })()
  inflightJwkFetches.set(domain, promise)
  try {
    return await promise
  } finally {
    if (inflightJwkFetches.get(domain) === promise) {
      inflightJwkFetches.delete(domain)
    }
  }
}

/**
 * Select the key matching kid, or the single unnamed key when the token has no
 * kid and exactly one unnamed key is published.
 */
const selectJwk = (keys: Map<string, crypto.KeyObject>, kid?: string): crypto.KeyObject | undefined => {
  if (kid) {
    return keys.get(kid)
  }
  const unnamed = keys.get("")
  if (unnamed) {
    return unnamed
  }
  if (keys.size === 1) {
    return keys.values().next().value
  }
  return undefined
}

/**
 * Resolve the public key for a kid from the domain's JWK set, refetching when
 * the cache is stale, the kid is unknown, and the failure cooldown has elapsed.
 */
const getPublicKey = async (
  domain: string,
  kid: string | undefined,
  cacheTtl: number,
): Promise<crypto.KeyObject | undefined> => {
  const now = Date.now()
  const cached = jwkCache.get(domain)
  if (cached && cached.expireAt > now) {
    const key = selectJwk(cached.keys, kid)
    if (key) {
      return key
    }
    // Avoid a fetch storm when tokens keep referencing unknown kids.
    if (now - cached.fetchedAt < JWK_UNKNOWN_KID_COOLDOWN) {
      return undefined
    }
  }

  const failedAt = jwkFailureAt.get(domain)
  if (failedAt !== undefined && now - failedAt < JWK_FAILURE_COOLDOWN) {
    throw new UpstreamError("auth domain JWK fetch is cooling down after a failure")
  }

  let entry: JwkCacheEntry
  try {
    entry = await fetchJwks(domain, cacheTtl)
  } catch (error) {
    jwkFailureAt.set(domain, Date.now())
    if (error instanceof UpstreamError) {
      throw error
    }
    throw new UpstreamError(error instanceof Error ? error.message : String(error))
  }
  return selectJwk(entry.keys, kid)
}

export type IdTokenVerification =
  | { ok: true }
  | { ok: false; reason: "missing" | "malformed" | "expired" | "invalid" | "upstream" }

/**
 * Verify an id-token: structure and exp locally, then the signature against the
 * JWK set published by `domain` at /jwk.  Only asymmetric algorithms are
 * accepted; tokens signed with `none` or an HMAC algorithm are refused.
 */
export const verifyIdToken = async (
  idToken: string | undefined,
  domain: string | undefined,
  cacheTtl: number = DEFAULT_JWK_CACHE_TTL,
): Promise<IdTokenVerification> => {
  if (!idToken) {
    return { ok: false, reason: "missing" }
  }

  const parts = idToken.split(".")
  if (parts.length !== 3) {
    return { ok: false, reason: "malformed" }
  }

  let header: { alg?: unknown; kid?: unknown } | null
  let payload: { exp?: unknown } | null
  try {
    header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"))
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
  } catch {
    return { ok: false, reason: "malformed" }
  }
  if (!header || !payload) {
    return { ok: false, reason: "malformed" }
  }

  const exp = payload.exp
  if (typeof exp !== "number") {
    return { ok: false, reason: "malformed" }
  }
  // exp is in seconds.
  if (exp <= Math.floor(Date.now() / 1000)) {
    return { ok: false, reason: "expired" }
  }

  const alg = typeof header.alg === "string" ? header.alg : undefined
  const algorithm = alg ? SIGNATURE_ALGORITHMS[alg] : undefined
  if (!algorithm) {
    return { ok: false, reason: "invalid" }
  }
  if (!domain) {
    logger.error("no auth domain configured for the request's run-env")
    return { ok: false, reason: "upstream" }
  }

  const kid = typeof header.kid === "string" ? header.kid : undefined
  let key: crypto.KeyObject | undefined
  try {
    key = await getPublicKey(domain, kid, cacheTtl)
  } catch (error) {
    logger.error(error instanceof Error ? error.message : String(error), field("auth-domain", domain))
    return { ok: false, reason: "upstream" }
  }
  if (!key) {
    return { ok: false, reason: "invalid" }
  }

  const isEc = key.asymmetricKeyType === "ec"
  const isRsa = key.asymmetricKeyType === "rsa" || key.asymmetricKeyType === "rsa-pss"
  if ((alg.startsWith("ES") && !isEc) || (!alg.startsWith("ES") && !isRsa)) {
    return { ok: false, reason: "invalid" }
  }

  try {
    const ok = crypto.verify(
      algorithm.hash,
      Buffer.from(`${parts[0]}.${parts[1]}`, "utf8"),
      { key, dsaEncoding: algorithm.dsaEncoding },
      Buffer.from(parts[2], "base64url"),
    )
    return ok ? { ok: true } : { ok: false, reason: "invalid" }
  } catch {
    return { ok: false, reason: "invalid" }
  }
}

/**
 * Fetch the session detail from x-service and return the artifacts path.
 *
 * host must include a protocol (http:// or https://).  TLS certificates are
 * not verified because x-service may be exposed with self-signed certificates.
 *
 * Throws TokenRejectedError, SessionNotFoundError, or UpstreamError.
 */
export const fetchSessionDetail = async (
  host: string,
  sessionId: string,
  idToken: string,
  timeout: number,
): Promise<string> => {
  const url = `${host.replace(/\/+$/, "")}/api/v1/sessions/${encodeURIComponent(sessionId)}/detail`
  const request = url.startsWith("https://") ? https.request : http.request
  // rejectUnauthorized is only read by https; harmless for plain http.
  // x-service TLS infrastructure may use legacy renegotiation (e.g. nginx
  // ssl_verify_client), which OpenSSL 3 rejects by default.
  const options: https.RequestOptions = {
    headers: { "id-token": idToken },
    timeout,
    rejectUnauthorized: false,
    secureOptions:
      crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
  }

  let response: http.IncomingMessage
  try {
    response = await new Promise((resolve, reject) => {
      const req = request(url, options, resolve)
      req.on("timeout", () => req.destroy(new Error(`x-service request timed out after ${timeout}ms`)))
      req.on("error", reject)
      req.end()
    })
  } catch (error) {
    throw new UpstreamError(error instanceof Error ? `x-service unreachable: ${error.message}` : "x-service unreachable")
  }

  const status = response.statusCode || 0
  if (status === HttpCode.Unauthorized) {
    throw new TokenRejectedError(`x-service rejected the id-token (${status})`)
  }
  // A session is a resource on this endpoint, so 404 means the session does
  // not exist (a definitive result), not a transient upstream failure.
  if (status === HttpCode.NotFound) {
    throw new SessionNotFoundError("session not found in x-service (404)")
  }
  if (status < 200 || status >= 300) {
    throw new UpstreamError(`x-service returned ${status}`)
  }

  let body: { returnCode?: string; data?: { artifactsPath?: string } }
  try {
    const text = await new Promise<string>((resolve, reject) => {
      const chunks: Buffer[] = []
      response.on("data", (chunk: Buffer) => chunks.push(chunk))
      response.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")))
      response.on("error", reject)
    })
    body = JSON.parse(text) as { returnCode?: string; data?: { artifactsPath?: string } }
  } catch {
    throw new UpstreamError("x-service returned an invalid response")
  }
  if (body?.returnCode !== "SUC0000" || typeof body?.data?.artifactsPath !== "string" || !body.data.artifactsPath) {
    throw new SessionNotFoundError("session not found in x-service")
  }
  return body.data.artifactsPath
}

/**
 * Return true if folder is artifactsPath itself or one of its subdirectories,
 * after normalizing both (normalize and strip trailing slashes).  Sibling
 * directories with a common prefix (e.g. /proj vs /proj2) do not match.
 */
export const authorizeFolder = (folder: string, artifactsPath: string): boolean => {
  const normalized = (p: string): string => path.normalize(p).replace(/\/+$/, "")
  const rel = path.relative(normalized(artifactsPath), normalized(folder))
  return rel === "" || (!rel.startsWith(`..${path.sep}`) && rel !== ".." && !path.isAbsolute(rel))
}

/**
 * Authorize the folder query parameter against the x-service session detail.
 * Throws an HttpError on failure which the existing error handlers render.
 */
export const authorizeFolderRequest = async (req: express.Request): Promise<void> => {
  const { folder, workspace } = req.query
  if (typeof folder !== "string" || !folder || !path.isAbsolute(folder)) {
    throw new HttpError("必须携带 folder 参数", HttpCode.BadRequest)
  }
  if (workspace !== undefined) {
    throw new HttpError("该认证模式不支持 workspace 参数", HttpCode.BadRequest)
  }

  const sessionId = req.cookies["session_id"] as string | undefined
  const runEnv = req.cookies["run_env"] as string | undefined
  if (!sessionId || !runEnv) {
    throw new HttpError("缺少会话信息", HttpCode.Unauthorized)
  }

  const hosts = req.args["x-service-hosts"]
  const host = hosts[runEnv] || req.args["x-service-default-host"]

  let artifactsPath: string
  try {
    artifactsPath = await fetchSessionDetail(host, sessionId, req.cookies["id_token"], req.args["x-service-timeout"])
  } catch (error) {
    if (error instanceof TokenRejectedError) {
      logger.warn(error.message, field("session-id", sessionId), field("run-env", runEnv))
      throw new HttpError("认证信息已被拒绝", HttpCode.Unauthorized)
    }
    if (error instanceof SessionNotFoundError) {
      logger.warn(error.message, field("session-id", sessionId), field("run-env", runEnv))
      throw new HttpError("会话不存在或已失效", HttpCode.Unauthorized)
    }
    if (error instanceof UpstreamError) {
      logger.error(error.message, field("session-id", sessionId), field("run-env", runEnv))
      throw new HttpError("认证服务不可用，请稍后重试", HttpCode.BadGateway)
    }
    throw error
  }

  if (!authorizeFolder(folder, artifactsPath)) {
    throw new HttpError("无权访问该目录", HttpCode.Forbidden)
  }
}

/**
 * Verify the id-token cookie, throwing an HttpError with a specific message on
 * failure.  Used by authenticated() in XToken mode.
 */
export const assertXTokenAuthenticated = async (req: express.Request): Promise<void> => {
  const runEnv = req.cookies["run_env"] as string | undefined
  const authDomains = req.args["auth-domains"]
  const domain = (runEnv ? authDomains[runEnv] : undefined) || authDomains["default"]

  const result = await verifyIdToken(req.cookies["id_token"], domain, req.args["auth-jwk-cache-ttl"])
  if (result.ok) {
    return
  }
  switch (result.reason) {
    case "missing":
      throw new HttpError("未认证", HttpCode.Unauthorized)
    case "malformed":
    case "invalid":
      throw new HttpError("认证信息无效", HttpCode.Unauthorized)
    case "expired":
      throw new HttpError("认证信息已过期", HttpCode.Unauthorized)
    case "upstream":
      throw new HttpError("认证服务不可用，请稍后重试", HttpCode.BadGateway)
  }
}
