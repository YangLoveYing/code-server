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

/**
 * A credential and where it was read from, e.g. "cookie:id_token".  Only the
 * source is ever logged, never the value, so a mismatch between what the client
 * sends and what code-server reads is immediately visible.
 */
interface Credential {
  value?: string
  source: string
}

/**
 * Read a credential from the canonical cookie name, the legacy hyphenated
 * cookie name, or a request header.  Verification is identical regardless of
 * the source.  Returns source "none" when no source carries a value.
 */
const readCredential = (req: express.Request, cookieNames: string[], headerNames: string[]): Credential => {
  for (const name of cookieNames) {
    const value = req.cookies ? req.cookies[name] : undefined
    if (typeof value === "string" && value) {
      return { value, source: `cookie:${name}` }
    }
  }
  for (const name of headerNames) {
    const value = req.headers[name]
    if (typeof value === "string" && value) {
      return { value, source: `header:${name}` }
    }
  }
  return { source: "none" }
}

/** The id-token cookie/header: `id_token` is canonical, `id-token` is legacy. */
const readIdToken = (req: express.Request): Credential =>
  readCredential(req, ["id_token", "id-token"], ["id-token", "x-id-token"])

/** The session cookie/header: `session_id` is canonical, `session-id` is legacy. */
const readSessionId = (req: express.Request): Credential =>
  readCredential(req, ["session_id", "session-id"], ["x-session-id"])

/** The run-env cookie/header: `run_env` is canonical, `run-env` is legacy. */
const readRunEnv = (req: express.Request): Credential =>
  readCredential(req, ["run_env", "run-env"], ["x-run-env"])

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
  if (!alg || !algorithm) {
    return { ok: false, reason: "invalid" }
  }
  if (!domain) {
    logger.error("[Auth] no auth domain configured for the request's run-env")
    return { ok: false, reason: "upstream" }
  }

  const kid = typeof header.kid === "string" ? header.kid : undefined
  let key: crypto.KeyObject | undefined
  try {
    key = await getPublicKey(domain, kid, cacheTtl)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    logger.error(`[Auth] jwk fetch failed: ${message}`, field("auth-domain", domain))
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
 * Verify the id-token against each auth domain of the run-env in order and
 * accept it as soon as one domain verifies the signature.
 *
 * A run-env can list several domains because developers sometimes obtain the
 * token from another environment (e.g. production) while using the dev
 * environment, so the token may be signed by any of them.
 *
 * Failures that do not depend on the domain (missing, malformed, expired) stop
 * the loop immediately.  When no domain verifies the token, an upstream failure
 * wins over a rejection: the token may have been signed by a domain that is
 * currently unavailable, which is worth retrying rather than reporting 401.
 */
export const verifyIdTokenAgainstDomains = async (
  idToken: string | undefined,
  domains: string[] | undefined,
  cacheTtl: number = DEFAULT_JWK_CACHE_TTL,
): Promise<IdTokenVerification> => {
  if (!domains || domains.length === 0) {
    // Keeps the original order of checks: a missing token is "missing", not
    // "upstream", even when no auth domain is configured.
    return verifyIdToken(idToken, undefined, cacheTtl)
  }

  let rejection: IdTokenVerification = { ok: false, reason: "invalid" }
  let sawUpstream = false
  for (const domain of domains) {
    const result = await verifyIdToken(idToken, domain, cacheTtl)
    if (result.ok) {
      return result
    }
    if (result.reason === "missing" || result.reason === "malformed" || result.reason === "expired") {
      // These checks only look at the token itself, so every domain would return
      // the same reason; trying the remaining domains cannot change the outcome.
      return result
    }
    if (result.reason === "upstream") {
      sawUpstream = true
    } else {
      rejection = result
    }
  }
  return sawUpstream ? { ok: false, reason: "upstream" } : rejection
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

  const sessionId = readSessionId(req)
  const runEnv = readRunEnv(req)
  const idToken = readIdToken(req)
  const sessionIdValue = sessionId.value
  const runEnvValue = runEnv.value
  const idTokenValue = idToken.value
  if (!sessionIdValue || !runEnvValue || !idTokenValue) {
    logger.warn(
      "[Auth] session context missing",
      field("session-id-source", sessionId.source),
      field("run-env-source", runEnv.source),
      field("id-token-source", idToken.source),
    )
    throw new HttpError("缺少会话信息", HttpCode.Unauthorized)
  }

  const hosts = req.args["x-service-hosts"]
  const host = hosts[runEnvValue] || req.args["x-service-default-host"]

  let artifactsPath: string
  try {
    artifactsPath = await fetchSessionDetail(host, sessionIdValue, idTokenValue, req.args["x-service-timeout"])
  } catch (error) {
    if (error instanceof TokenRejectedError) {
      logger.warn(
        "[Auth] x-service rejected the id-token",
        field("session-id", sessionIdValue),
        field("run-env", runEnvValue),
        field("x-service-host", host),
      )
      throw new HttpError("认证信息已被拒绝", HttpCode.Unauthorized)
    }
    if (error instanceof SessionNotFoundError) {
      logger.warn(
        "[Auth] session not found in x-service",
        field("session-id", sessionIdValue),
        field("run-env", runEnvValue),
        field("x-service-host", host),
      )
      throw new HttpError("会话不存在或已失效", HttpCode.Unauthorized)
    }
    if (error instanceof UpstreamError) {
      logger.error(
        `[Auth] x-service unreachable: ${error.message}`,
        field("session-id", sessionIdValue),
        field("run-env", runEnvValue),
        field("x-service-host", host),
      )
      throw new HttpError("认证服务不可用，请稍后重试", HttpCode.BadGateway)
    }
    throw error
  }

  if (!authorizeFolder(folder, artifactsPath)) {
    logger.warn(
      "[Auth] folder is outside the session artifacts path",
      field("run-env", runEnvValue),
      field("session-id", sessionIdValue),
      field("folder", folder),
      field("artifacts-path", artifactsPath),
    )
    throw new HttpError("无权访问该目录", HttpCode.Forbidden)
  }
}

/**
 * Verify the id-token cookie, throwing an HttpError with a specific message on
 * failure.  Used by authenticated() in XToken mode.
 */
export const assertXTokenAuthenticated = async (req: express.Request): Promise<void> => {
  const idToken = readIdToken(req)
  const runEnv = readRunEnv(req)
  const authDomains = req.args["auth-domains"]
  // run-env is a per-request value (cookie `run_env`, legacy `run-env`, or an
  // `x-run-env` header).  There is no process-wide environment identifier:
  // the request value selects an entry from --auth-domains, falling back to its
  // `default` entry when the value is absent or not in the map.  An entry may
  // list several domains (e.g. dev + prd) and any one of them may verify the
  // token.
  const mappedDomains = runEnv.value ? authDomains[runEnv.value] : undefined
  const domains = mappedDomains && mappedDomains.length > 0 ? mappedDomains : authDomains["default"] || []

  const result = await verifyIdTokenAgainstDomains(idToken.value, domains, req.args["auth-jwk-cache-ttl"])
  if (result.ok) {
    return
  }
  // 401 responses are not logged by the HTTP error handler, so log the rejection
  // reason and the context needed to locate it here.  The token itself is never
  // logged; only where it came from.
  logger.warn(
    "[Auth] id-token rejected",
    field("reason", result.reason),
    field("auth-type", req.args.auth),
    field("id-token-source", idToken.source),
    field("run-env", runEnv.value || "none"),
    field("run-env-source", runEnv.source),
    field("run-env-matched", mappedDomains ? "yes" : "no"),
    field("auth-domains", domains.join(",") || "none"),
    field("auth-domain-source", mappedDomains ? "auth-domains" : domains.length > 0 ? "auth-domains.default" : "none"),
  )
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
