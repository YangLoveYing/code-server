import { once } from "events"
import * as http from "http"
import { AddressInfo } from "net"
import type { Page } from "playwright"
import { clean, tmpdir } from "../utils/helpers"
import { describe, test, expect } from "./baseFixture"
import type { CodeServer } from "./models/CodeServer"

/**
 * Mock x-service.  Answers GET /session/:id/detail; the response depends on the
 * id-token header and session id so each test can pick a scenario.
 */
const startMockXService = (artifactsPath: string): http.Server => {
  return http.createServer((req, res) => {
    if (req.headers["id-token"] === "bad-token") {
      res.writeHead(401, { "Content-Type": "application/json" })
      return res.end(JSON.stringify({ returnCode: "AUT0001", data: {} }))
    }
    const sessionId = decodeURIComponent((req.url || "").split("/")[2] || "")
    if (sessionId === "sess-hang") {
      return // Never respond; the client should time out.
    }
    const body =
      sessionId === "sess-gone"
        ? { returnCode: "ERR404", data: {} }
        : { returnCode: "SUC0000", data: { id: 84445, uid: "u", artifactsPath } }
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify(body))
  })
}

// JWT-shaped string.  code-server only decodes the payload to check exp.
const makeToken = (exp: number): string => {
  const encode = (obj: object): string => Buffer.from(JSON.stringify(obj)).toString("base64url")
  return `${encode({ alg: "none" })}.${encode({ exp })}.signature`
}

const tokenExp = (secondsFromNow: number): number => Math.floor(Date.now() / 1000) + secondsFromNow

const VALID_TOKEN = makeToken(tokenExp(300))
const EXPIRED_TOKEN = makeToken(tokenExp(-300))

const args = ["--auth=x-token", "--x-service-timeout=500"]

describe("x-token auth", args, {}, () => {
  let mockXService: http.Server
  let artifactsPath: string

  test.beforeAll(async () => {
    await clean("xauth")
    artifactsPath = await tmpdir("xauth")
    mockXService = startMockXService(artifactsPath)
    mockXService.listen(0, "127.0.0.1")
    await once(mockXService, "listening")
    const port = (mockXService.address() as AddressInfo).port
    // The args array is shared with the lazily-spawned code-server instance.
    args.push(`--x-service-default-host=127.0.0.1:${port}`)
  })

  test.afterAll(async () => {
    mockXService.close()
  })

  const get = async (codeServer: CodeServer, page: Page, pathname: string, cookies: Record<string, string> = {}) => {
    const addr = await codeServer.address()
    const origin = new URL(addr).origin
    if (Object.keys(cookies).length > 0) {
      await page.context().addCookies(
        Object.entries(cookies).map(([name, value]) => ({ name, value, url: origin })),
      )
    }
    return page.request.get(addr.replace(/\/$/, "") + pathname, { headers: { accept: "text/html" } })
  }

  const sessionCookies = (token: string, sessionId: string): Record<string, string> => ({
    "id-token": token,
    "session-id": sessionId,
    "run-env": "dev",
  })

  test("should reject a request without an id-token (401)", async ({ codeServer, page }) => {
    const res = await get(codeServer, page, "/")
    expect(res.status()).toBe(401)
    expect(await res.text()).toContain("未认证")
  })

  test("should reject an expired id-token (401)", async ({ codeServer, page }) => {
    const res = await get(codeServer, page, "/", { "id-token": EXPIRED_TOKEN })
    expect(res.status()).toBe(401)
    expect(await res.text()).toContain("认证信息已过期")
  })

  test("should reject when the session cookies are missing (401)", async ({ codeServer, page }) => {
    const res = await get(codeServer, page, `/?folder=${encodeURIComponent(artifactsPath)}`, {
      "id-token": VALID_TOKEN,
    })
    expect(res.status()).toBe(401)
    expect(await res.text()).toContain("缺少 session-id / run-env")
  })

  test("should reject a missing folder (400)", async ({ codeServer, page }) => {
    const res = await get(codeServer, page, "/", sessionCookies(VALID_TOKEN, "sess-ok"))
    expect(res.status()).toBe(400)
    expect(await res.text()).toContain("必须携带 folder 参数")
  })

  test("should reject a workspace parameter (400)", async ({ codeServer, page }) => {
    const res = await get(
      codeServer,
      page,
      `/?folder=${encodeURIComponent(artifactsPath)}&workspace=${encodeURIComponent(artifactsPath)}`,
      sessionCookies(VALID_TOKEN, "sess-ok"),
    )
    expect(res.status()).toBe(400)
    expect(await res.text()).toContain("该认证模式不支持 workspace 参数")
  })

  test("should reject a token the x-service refuses (401)", async ({ codeServer, page }) => {
    const res = await get(
      codeServer,
      page,
      `/?folder=${encodeURIComponent(artifactsPath)}`,
      sessionCookies("bad-token", "sess-ok"),
    )
    expect(res.status()).toBe(401)
    expect(await res.text()).toContain("认证信息已被拒绝")
  })

  test("should reject an unknown session (401)", async ({ codeServer, page }) => {
    const res = await get(
      codeServer,
      page,
      `/?folder=${encodeURIComponent(artifactsPath)}`,
      sessionCookies(VALID_TOKEN, "sess-gone"),
    )
    expect(res.status()).toBe(401)
    expect(await res.text()).toContain("会话不存在或已失效")
  })

  test("should reject a folder mismatch (403)", async ({ codeServer, page }) => {
    const res = await get(
      codeServer,
      page,
      `/?folder=${encodeURIComponent(artifactsPath + "/other")}`,
      sessionCookies(VALID_TOKEN, "sess-ok"),
    )
    expect(res.status()).toBe(403)
    expect(await res.text()).toContain("无权访问该目录")
  })

  test("should reject when the x-service does not respond (502)", async ({ codeServer, page }) => {
    const res = await get(
      codeServer,
      page,
      `/?folder=${encodeURIComponent(artifactsPath)}`,
      sessionCookies(VALID_TOKEN, "sess-hang"),
    )
    expect(res.status()).toBe(502)
    expect(await res.text()).toContain("认证服务不可用，请稍后重试")
  })

  test("should serve the editor when the folder matches", async ({ codeServer, page }) => {
    const res = await get(
      codeServer,
      page,
      `/?folder=${encodeURIComponent(artifactsPath)}`,
      sessionCookies(VALID_TOKEN, "sess-ok"),
    )
    expect(res.status()).toBe(200)
    expect(await res.text()).toContain("/_static/")
  })
})
