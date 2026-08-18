import { field, logger } from "@coder/logger"
import * as express from "express"
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
 * The result of verifying an id-token (a JWT).  The signature is not verified;
 * only the payload is decoded and the exp claim checked.  The trust boundary is
 * x-service which authenticates the token itself.
 */
export type IdTokenVerification = { ok: true } | { ok: false; reason: "missing" | "malformed" | "expired" }

/**
 * Decode the payload of an id-token and check its exp claim.
 */
export const verifyIdToken = (idToken?: string): IdTokenVerification => {
  if (!idToken) {
    return { ok: false, reason: "missing" }
  }
  // JWTs are header.payload.signature; we only care about the payload.
  let payload: unknown
  try {
    payload = JSON.parse(Buffer.from(idToken.split(".")[1], "base64url").toString("utf8"))
  } catch {
    return { ok: false, reason: "malformed" }
  }
  const exp = (payload as { exp?: unknown } | null)?.exp
  if (typeof exp !== "number") {
    return { ok: false, reason: "malformed" }
  }
  // exp is in seconds.
  if (exp <= Math.floor(Date.now() / 1000)) {
    return { ok: false, reason: "expired" }
  }
  return { ok: true }
}

/**
 * Fetch the session detail from x-service and return the artifacts path.
 *
 * Throws TokenRejectedError, SessionNotFoundError, or UpstreamError.
 */
export const fetchSessionDetail = async (
  host: string,
  sessionId: string,
  idToken: string,
  timeout: number,
): Promise<string> => {
  let response: Response
  try {
    response = await fetch(`${host.replace(/\/+$/, "")}/api/v1/sessions/${encodeURIComponent(sessionId)}/detail`, {
      headers: { "id-token": idToken },
      signal: AbortSignal.timeout(timeout),
    })
  } catch (error) {
    throw new UpstreamError(error instanceof Error ? `x-service unreachable: ${error.message}` : "x-service unreachable")
  }
  if (response.status === HttpCode.Unauthorized) {
    throw new TokenRejectedError(`x-service rejected the id-token (${response.status})`)
  }
  // A session is a resource on this endpoint, so 404 means the session does
  // not exist (a definitive result), not a transient upstream failure.
  if (response.status === HttpCode.NotFound) {
    throw new SessionNotFoundError("session not found in x-service (404)")
  }
  if (!response.ok) {
    throw new UpstreamError(`x-service returned ${response.status}`)
  }
  let body: { returnCode?: string; data?: { artifactsPath?: string } }
  try {
    body = (await response.json()) as { returnCode?: string; data?: { artifactsPath?: string } }
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
export const assertXTokenAuthenticated = (req: express.Request): void => {
  const result = verifyIdToken(req.cookies["id_token"])
  if (result.ok) {
    return
  }
  switch (result.reason) {
    case "missing":
      throw new HttpError("未认证", HttpCode.Unauthorized)
    case "malformed":
      throw new HttpError("认证信息无效", HttpCode.Unauthorized)
    case "expired":
      throw new HttpError("认证信息已过期", HttpCode.Unauthorized)
  }
}
