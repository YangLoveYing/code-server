# code-server x-token 认证鉴权 实现计划

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 code-server 新增 `--auth=x-token` 认证模式：校验 `id-token` cookie（JWT 解包 + exp），并在 `/`、`/vscode` 页面加载时经 x-service 校验 `folder` 与会话 `artifactsPath` 一致，防水平越权。

**Architecture:** 新增独立模块 `src/node/xauth.ts`（纯函数 + 请求级守卫），在 `cli.ts` 增加 `AuthType.XToken` 与三个配置项，在 `http.ts` 的 `authenticated()` 加分支使全部现有调用方自动获得 401 语义，在 `routes/vscode.ts` 的 `GET /` 处理器前挂 xTokenGuard。password 认证路径零改动。

**Tech Stack:** TypeScript（Node 22）、Express 5、Jest（ts-jest，jest 位于 `test/node_modules`）、Node 原生 `fetch`/`Buffer.from(..., "base64url")`（**不新增任何依赖**）。

**Spec:** `docs/superpowers/specs/2026-08-13-code-server-xauth-design.md`（已确认）

## Global Constraints

- Node 22；`npm run test:unit` 通过；`npm run lint:ts`、`npm run fmt` 通过。
- 不改动 password / none 认证的任何现有行为；login/logout 路由挂载条件不动。
- 报错信息为中文硬编码（不走 i18n），文案以 spec 第 7 节表格为准。
- 不引入新 npm 依赖；JWT 不验签；不对 x-service 响应做缓存。
- 代码风格匹配现有代码：2 空格缩进、双引号、分号、prettier printWidth 120。
- 每个 commit 末尾加 `Co-Authored-By: Claude <noreply@anthropic.com>`；只 `git add` 本任务涉及的文件（工作区还有其他未提交改动，不要误提交）。
- 运行单个测试文件用 `./test/node_modules/.bin/jest --coverage=false <file>`（jest 全局 collectCoverage:true，单文件跑会撞 60% 阈值，必须 --coverage=false）。

---

### Task 1: CLI 层——AuthType.XToken 与三个配置项

**Files:**
- Modify: `src/node/cli.ts:13-16`（AuthType）、`:69-102`（UserProvidedArgs）、`:145-155`（options 表）、`:755-769`（parseConfigFile）、`:516-540`（DefaultedArgs）、`:545-700`（setDefaults）
- Test: `test/unit/node/cli.test.ts`

**Interfaces:**
- Produces: `AuthType.XToken = "x-token"`；`UserProvidedArgs["x-service-hosts"?: string]`（JSON 字符串）、`"x-service-default-host"?: string`、`"x-service-timeout"?: number`；`DefaultedArgs["x-service-hosts"]: Record<string, string>`、`"x-service-default-host": string`（默认 `localhost:9090`）、`"x-service-timeout": number`（默认 `5000`）；导出 `parseXServiceHosts(value?: string): Record<string, string>`（非法 JSON 抛错）。

- [ ] **Step 1: 更新测试文件（先写失败测试）**

`test/unit/node/cli.test.ts`：
1. 在 `defaults` 常量（约 line 28）中追加三个字段：

```ts
const defaults = {
  // ...existing fields...
  "x-service-hosts": {},
  "x-service-default-host": "localhost:9090",
  "x-service-timeout": 5000,
}
```

2. 在 `describe("parser")` 的 `beforeEach` 里追加环境变量清理（与已有 `delete process.env.PASSWORD` 等并列）：

```ts
    delete process.env.X_SERVICE_HOSTS
    delete process.env.X_SERVICE_DEFAULT_HOST
    delete process.env.X_SERVICE_TIMEOUT
```

3. 在文件末尾新增两个 describe（`parseXServiceHosts` 需加入文件顶部 import 列表）：

```ts
describe("parseXServiceHosts", () => {
  it("should parse a JSON object string", () => {
    expect(parseXServiceHosts('{"dev":"http://x.dev:9090","st":"http://x.st:9090"}')).toStrictEqual({
      dev: "http://x.dev:9090",
      st: "http://x.st:9090",
    })
  })

  it("should return an empty map for empty input", () => {
    expect(parseXServiceHosts(undefined)).toStrictEqual({})
    expect(parseXServiceHosts("")).toStrictEqual({})
  })

  it("should throw on invalid JSON", () => {
    expect(() => parseXServiceHosts("not-json")).toThrow("--x-service-hosts must be a valid JSON object")
  })

  it("should throw on non-object JSON", () => {
    expect(() => parseXServiceHosts('["a"]')).toThrow("--x-service-hosts must be a valid JSON object")
  })
})

describe("x-service options", () => {
  it("should convert a YAML map from the config file to a JSON string", () => {
    const config = parseConfigFile(
      'auth: x-token\nx-service-hosts:\n  dev: "http://x.dev:9090"\n  st: "http://x.st:9090"\n',
      "test",
    )
    expect(config["x-service-hosts"]).toBe('{"dev":"http://x.dev:9090","st":"http://x.st:9090"}')
  })

  it("should apply x-service defaults", async () => {
    expect(await setDefaults(parse([]))).toMatchObject({
      "x-service-hosts": {},
      "x-service-default-host": "localhost:9090",
      "x-service-timeout": 5000,
    })
  })

  it("should read x-service options from the environment", async () => {
    process.env.X_SERVICE_HOSTS = '{"dev":"http://env:1"}'
    process.env.X_SERVICE_DEFAULT_HOST = "http://fallback:1"
    process.env.X_SERVICE_TIMEOUT = "1234"
    const args = await setDefaults(parse([]))
    expect(args["x-service-hosts"]).toStrictEqual({ dev: "http://env:1" })
    expect(args["x-service-default-host"]).toBe("http://fallback:1")
    expect(args["x-service-timeout"]).toBe(1234)
  })
})
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/cli.test.ts`
Expected: FAIL——`parseXServiceHosts` 未导出；`defaults` 对比失败（setDefaults 尚未返回新字段）。

- [ ] **Step 3: 实现 cli.ts 改动**

3a. AuthType（line 13-16）：

```ts
export enum AuthType {
  Password = "password",
  None = "none",
  XToken = "x-token",
}
```

3b. `UserProvidedArgs`（在 `"idle-timeout-seconds"?: number` 后追加）：

```ts
  "x-service-hosts"?: string
  "x-service-default-host"?: string
  "x-service-timeout"?: number
```

3c. options 表（在 `auth` 条目后追加）：

```ts
  "x-service-hosts": {
    type: "string",
    description:
      'JSON object mapping run-env to x-service hosts for x-token auth, e.g. {"dev":"http://x.dev:9090"}. ' +
      "Can be written as a YAML map in the config file.",
  },
  "x-service-default-host": {
    type: "string",
    description: "Fallback x-service host for x-token auth when run-env is not in x-service-hosts.",
  },
  "x-service-timeout": {
    type: "number",
    description: "Timeout in milliseconds for x-service session detail requests.",
  },
```

3d. `DefaultedArgs`（line ~516）：把 `export interface DefaultedArgs extends ConfigArgs {` 改为：

```ts
export interface DefaultedArgs extends Omit<ConfigArgs, "x-service-hosts"> {
```

并在接口内（`"session-socket": string` 之后）追加：

```ts
  "x-service-hosts": Record<string, string>
  "x-service-default-host": string
  "x-service-timeout": number
```

3e. 新增导出函数 `parseXServiceHosts`（放在 `parseConfigFile` 之前）：

```ts
/**
 * Parse the x-service-hosts option (a JSON object string) into a map of
 * run-env to host.  An empty value yields an empty map.  Throws on invalid
 * JSON so misconfiguration fails at startup.
 */
export function parseXServiceHosts(value?: string): Record<string, string> {
  if (!value) {
    return {}
  }
  let parsed: unknown
  try {
    parsed = JSON.parse(value)
  } catch {
    throw new Error("--x-service-hosts must be a valid JSON object")
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("--x-service-hosts must be a valid JSON object")
  }
  return parsed as Record<string, string>
}
```

3f. `parseConfigFile` 的 `.map` 回调（line ~759），在 `Array.isArray` 分支与最终 return 之间插入对象分支：

```ts
      } else if (Array.isArray(opt)) {
        return opt.map((o) => `--${optName}=${o}`)
      } else if (opt && typeof opt === "object") {
        // YAML maps (e.g. x-service-hosts) become JSON strings for the parser.
        return `--${optName}=${JSON.stringify(opt)}`
      }
      return `--${optName}=${opt}`
```

3g. `setDefaults` 环境变量（在 `if (process.env.GITHUB_TOKEN)` 块之后）：

```ts
  if (process.env.X_SERVICE_HOSTS) {
    args["x-service-hosts"] = process.env.X_SERVICE_HOSTS
  }

  if (process.env.X_SERVICE_DEFAULT_HOST) {
    args["x-service-default-host"] = process.env.X_SERVICE_DEFAULT_HOST
  }

  if (process.env.X_SERVICE_TIMEOUT) {
    args["x-service-timeout"] = Number(process.env.X_SERVICE_TIMEOUT)
  }
```

3h. `setDefaults` 末尾 return（当前为 `return { ...args, usingEnvPassword, usingEnvHashedPassword } as DefaultedArgs`）改为：

```ts
  return {
    ...args,
    "x-service-hosts": parseXServiceHosts(args["x-service-hosts"]),
    "x-service-default-host": args["x-service-default-host"] || "localhost:9090",
    "x-service-timeout": args["x-service-timeout"] || 5000,
    usingEnvPassword,
    usingEnvHashedPassword,
  } as DefaultedArgs // TODO: Technically no guarantee this is fulfilled.
```

（`X_SERVICE_TIMEOUT` 为非法数字时 `Number()` 得 NaN，`NaN || 5000` 自动回退默认值。）

- [ ] **Step 4: 运行测试确认通过**

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/cli.test.ts`
Expected: PASS（含原有全部用例）。

- [ ] **Step 5: 格式检查并提交**

```bash
npx prettier --write src/node/cli.ts test/unit/node/cli.test.ts
git add src/node/cli.ts test/unit/node/cli.test.ts
git commit -m "feat: 新增 x-token 认证的 CLI 配置项

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 2: xauth 模块（`src/node/xauth.ts`）+ `HttpCode.BadGateway`

**Files:**
- Modify: `src/common/http.ts:1-10`（HttpCode 加 BadGateway）
- Create: `src/node/xauth.ts`
- Test: `test/unit/node/xauth.test.ts`

**Interfaces:**
- Consumes: Task 1 的 `AuthType.XToken`、`DefaultedArgs`（`x-service-hosts`/`x-service-default-host`/`x-service-timeout`）。
- Produces（后续任务依赖的精确签名）:
  - `type TokenFailure = "missing" | "malformed" | "expired"`
  - `type TokenVerification = { ok: true } | { ok: false; reason: TokenFailure }`
  - `verifyIdToken(idToken?: string): TokenVerification`
  - `class UpstreamError extends Error {}`、`class TokenRejectedError extends Error {}`、`class SessionNotFoundError extends Error {}`
  - `interface SessionDetail { returnCode: string; data?: { artifactsPath?: string } }`
  - `fetchSessionDetail(host: string, sessionId: string, idToken: string, timeoutMs: number): Promise<SessionDetail>`
  - `authorizeFolder(folder: string, artifactsPath: string): boolean`
  - `getXServiceHost(args: DefaultedArgs, runEnv: string): string`
  - `assertXTokenAuthenticated(req: express.Request): void`（失败抛 `HttpError(401, 中文信息)`）
  - `authorizeFolderRequest(req: express.Request): Promise<void>`（失败抛 HttpError 400/401/403/502）

- [ ] **Step 1: 修改 HttpCode**

`src/common/http.ts` 的枚举追加（Forbidden 之后）：

```ts
  Forbidden = 403,
  BadGateway = 502,
```

- [ ] **Step 2: 写失败测试 `test/unit/node/xauth.test.ts`**

```ts
import * as express from "express"
import { HttpCode } from "../../../src/common/http"
import type { DefaultedArgs } from "../../../src/node/cli"
import {
  SessionNotFoundError,
  TokenRejectedError,
  UpstreamError,
  authorizeFolder,
  authorizeFolderRequest,
  fetchSessionDetail,
  getXServiceHost,
  verifyIdToken,
} from "../../../src/node/xauth"
import { mockLogger } from "../../utils/helpers"

describe("xauth", () => {
  beforeAll(() => {
    mockLogger()
  })

  const args = {
    "x-service-hosts": { dev: "http://x.dev:9090" },
    "x-service-default-host": "http://x.default:9090",
    "x-service-timeout": 5000,
  } as DefaultedArgs

  const makeToken = (payload: object) => {
    const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url")
    return `${enc({ alg: "none" })}.${enc(payload)}.sig`
  }

  const fakeReq = (overrides: Partial<express.Request> = {}) =>
    ({ args, query: {}, cookies: {}, ...overrides }) as express.Request

  describe("verifyIdToken", () => {
    it("should reject a missing token", () => {
      expect(verifyIdToken(undefined)).toStrictEqual({ ok: false, reason: "missing" })
    })

    it("should reject a malformed token", () => {
      expect(verifyIdToken("not-a-jwt")).toStrictEqual({ ok: false, reason: "malformed" })
    })

    it("should reject an expired token", () => {
      expect(verifyIdToken(makeToken({ exp: Math.floor(Date.now() / 1000) - 60 }))).toStrictEqual({
        ok: false,
        reason: "expired",
      })
    })

    it("should accept a valid token", () => {
      expect(verifyIdToken(makeToken({ exp: Math.floor(Date.now() / 1000) + 3600 }))).toStrictEqual({ ok: true })
    })
  })

  describe("authorizeFolder", () => {
    it("should accept an equal path", () => {
      expect(authorizeFolder("/home/x/sessions/s/artifacts", "/home/x/sessions/s/artifacts")).toBe(true)
    })

    it("should normalize trailing slashes", () => {
      expect(authorizeFolder("/home/x/sessions/s/artifacts/", "/home/x/sessions/s/artifacts")).toBe(true)
    })

    it("should reject subdirectories", () => {
      expect(authorizeFolder("/home/x/sessions/s/artifacts/src", "/home/x/sessions/s/artifacts")).toBe(false)
    })

    it("should reject unrelated paths", () => {
      expect(authorizeFolder("/home/other", "/home/x/sessions/s/artifacts")).toBe(false)
    })
  })

  describe("fetchSessionDetail", () => {
    afterEach(() => {
      jest.restoreAllMocks()
    })

    const mockFetch = (status: number, body: unknown) => {
      jest.spyOn(global, "fetch").mockResolvedValue({
        status,
        ok: status >= 200 && status < 300,
        json: async () => body,
      } as unknown as Response)
    }

    it("should return the session detail", async () => {
      mockFetch(200, { returnCode: "SUC0000", data: { artifactsPath: "/home/x/artifacts" } })
      expect(await fetchSessionDetail("localhost:9090", "abc", "token", 5000)).toStrictEqual({
        returnCode: "SUC0000",
        data: { artifactsPath: "/home/x/artifacts" },
      })
    })

    it("should throw TokenRejectedError on 401", async () => {
      mockFetch(401, {})
      await expect(fetchSessionDetail("localhost:9090", "abc", "token", 5000)).rejects.toThrow(TokenRejectedError)
    })

    it("should throw SessionNotFoundError on non-SUC0000", async () => {
      mockFetch(200, { returnCode: "ERR0000", data: {} })
      await expect(fetchSessionDetail("localhost:9090", "abc", "token", 5000)).rejects.toThrow(SessionNotFoundError)
    })

    it("should throw SessionNotFoundError without artifactsPath", async () => {
      mockFetch(200, { returnCode: "SUC0000", data: {} })
      await expect(fetchSessionDetail("localhost:9090", "abc", "token", 5000)).rejects.toThrow(SessionNotFoundError)
    })

    it("should throw UpstreamError on network failure", async () => {
      jest.spyOn(global, "fetch").mockRejectedValue(new TypeError("fetch failed"))
      await expect(fetchSessionDetail("localhost:9090", "abc", "token", 5000)).rejects.toThrow(UpstreamError)
    })
  })

  describe("authorizeFolderRequest", () => {
    afterEach(() => {
      jest.restoreAllMocks()
    })

    it("should throw 400 without folder", async () => {
      await expect(authorizeFolderRequest(fakeReq())).rejects.toMatchObject({ statusCode: HttpCode.BadRequest })
    })

    it("should throw 400 with a relative folder", async () => {
      await expect(authorizeFolderRequest(fakeReq({ query: { folder: "artifacts" } }))).rejects.toMatchObject({
        statusCode: HttpCode.BadRequest,
      })
    })

    it("should throw 400 with a workspace param", async () => {
      await expect(
        authorizeFolderRequest(fakeReq({ query: { folder: "/home/x/artifacts", workspace: "/w.code-workspace" } })),
      ).rejects.toMatchObject({ statusCode: HttpCode.BadRequest })
    })

    it("should throw 401 without session cookies", async () => {
      await expect(
        authorizeFolderRequest(fakeReq({ query: { folder: "/home/x/artifacts" }, cookies: { "id-token": "t" } })),
      ).rejects.toMatchObject({ statusCode: HttpCode.Unauthorized })
    })

    it("should throw 403 on mismatch", async () => {
      jest.spyOn(global, "fetch").mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({ returnCode: "SUC0000", data: { artifactsPath: "/home/x/s/artifacts" } }),
      } as unknown as Response)
      await expect(
        authorizeFolderRequest(
          fakeReq({
            query: { folder: "/home/evil" },
            cookies: { "id-token": "t", "session-id": "abc", "run-env": "dev" },
          }),
        ),
      ).rejects.toMatchObject({ statusCode: HttpCode.Forbidden })
    })

    it("should throw 502 when the fetch fails", async () => {
      jest.spyOn(global, "fetch").mockRejectedValue(new TypeError("fetch failed"))
      await expect(
        authorizeFolderRequest(
          fakeReq({
            query: { folder: "/home/x/s/artifacts" },
            cookies: { "id-token": "t", "session-id": "abc", "run-env": "dev" },
          }),
        ),
      ).rejects.toMatchObject({ statusCode: HttpCode.BadGateway })
    })

    it("should resolve on match", async () => {
      jest.spyOn(global, "fetch").mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({ returnCode: "SUC0000", data: { artifactsPath: "/home/x/s/artifacts" } }),
      } as unknown as Response)
      await expect(
        authorizeFolderRequest(
          fakeReq({
            query: { folder: "/home/x/s/artifacts" },
            cookies: { "id-token": "t", "session-id": "abc", "run-env": "dev" },
          }),
        ),
      ).resolves.toBeUndefined()
    })
  })

  describe("getXServiceHost", () => {
    it("should return the mapped host", () => {
      expect(getXServiceHost(args, "dev")).toBe("http://x.dev:9090")
    })

    it("should fall back to the default host", () => {
      expect(getXServiceHost(args, "prd")).toBe("http://x.default:9090")
    })
  })
})
```

- [ ] **Step 3: 运行测试确认失败**

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/xauth.test.ts`
Expected: FAIL——`Cannot find module '../../../src/node/xauth'`。

- [ ] **Step 4: 实现 `src/node/xauth.ts`**

```ts
import * as express from "express"
import * as path from "path"
import { HttpCode, HttpError } from "../common/http"
import type { DefaultedArgs } from "./cli"

export type TokenFailure = "missing" | "malformed" | "expired"
export type TokenVerification = { ok: true } | { ok: false; reason: TokenFailure }

export class UpstreamError extends Error {}
export class TokenRejectedError extends Error {}
export class SessionNotFoundError extends Error {}

export interface SessionDetail {
  returnCode: string
  data?: {
    artifactsPath?: string
  }
}

const ID_TOKEN_ERRORS: Record<TokenFailure, string> = {
  missing: "未提供 id-token",
  malformed: "id-token 格式无效",
  expired: "id-token 已过期",
}

/**
 * Check an id-token cookie: it must be a JWT with a payload whose `exp`
 * (seconds since epoch) is in the future.  No signature verification is
 * performed; x-service is the trust boundary.
 */
export function verifyIdToken(idToken?: string): TokenVerification {
  if (!idToken) {
    return { ok: false, reason: "missing" }
  }
  const parts = idToken.split(".")
  if (parts.length < 2) {
    return { ok: false, reason: "malformed" }
  }
  let payload: { exp?: unknown }
  try {
    payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"))
  } catch {
    return { ok: false, reason: "malformed" }
  }
  if (typeof payload.exp !== "number" || Number.isNaN(payload.exp)) {
    return { ok: false, reason: "malformed" }
  }
  if (payload.exp * 1000 <= Date.now()) {
    return { ok: false, reason: "expired" }
  }
  return { ok: true }
}

/**
 * Throw an HttpError (401 with a specific message) if the id-token cookie is
 * missing, malformed, or expired.
 */
export function assertXTokenAuthenticated(req: express.Request): void {
  const result = verifyIdToken(req.cookies["id-token"] as string | undefined)
  if (!result.ok) {
    throw new HttpError(ID_TOKEN_ERRORS[result.reason], HttpCode.Unauthorized)
  }
}

/**
 * Fetch a session's detail from x-service.  Throws TokenRejectedError when
 * x-service rejects the token (401), SessionNotFoundError when the session
 * cannot be resolved, and UpstreamError on any transport or protocol failure.
 */
export async function fetchSessionDetail(
  host: string,
  sessionId: string,
  idToken: string,
  timeoutMs: number,
): Promise<SessionDetail> {
  let resp: Response
  try {
    resp = await fetch(`http://${host}/session/${encodeURIComponent(sessionId)}/detail`, {
      headers: { "id-token": idToken },
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch {
    throw new UpstreamError()
  }
  if (resp.status === HttpCode.Unauthorized) {
    throw new TokenRejectedError()
  }
  if (!resp.ok) {
    throw new UpstreamError()
  }
  let body: SessionDetail
  try {
    body = (await resp.json()) as SessionDetail
  } catch {
    throw new UpstreamError()
  }
  if (body.returnCode !== "SUC0000" || !body.data?.artifactsPath) {
    throw new SessionNotFoundError()
  }
  return body
}

/**
 * Return true if folder (after normalization) is exactly the artifactsPath.
 * Subdirectories are rejected.
 */
export function authorizeFolder(folder: string, artifactsPath: string): boolean {
  const normalizePath = (p: string) => path.normalize(p.replace(/\/+$/, ""))
  return normalizePath(folder) === normalizePath(artifactsPath)
}

/**
 * Resolve the x-service host for a run-env, falling back to the default host.
 */
export function getXServiceHost(args: DefaultedArgs, runEnv: string): string {
  return args["x-service-hosts"][runEnv] || args["x-service-default-host"]
}

/**
 * Authorize a page-load request in x-token mode: the folder query param is
 * required and must match the session's artifactsPath from x-service.
 * Throws HttpError with 400/401/403/502 as appropriate.
 */
export async function authorizeFolderRequest(req: express.Request): Promise<void> {
  const folder = req.query.folder
  if (typeof folder !== "string" || folder.length === 0) {
    throw new HttpError("必须携带 folder 参数", HttpCode.BadRequest)
  }
  if (!path.isAbsolute(folder)) {
    throw new HttpError("folder 必须是绝对路径", HttpCode.BadRequest)
  }
  if (req.query.workspace) {
    throw new HttpError("该认证模式不支持 workspace 参数", HttpCode.BadRequest)
  }

  const sessionId = req.cookies["session-id"] as string | undefined
  const runEnv = req.cookies["run-env"] as string | undefined
  const idToken = req.cookies["id-token"] as string | undefined
  if (!sessionId || !runEnv || !idToken) {
    throw new HttpError("缺少 session-id / run-env", HttpCode.Unauthorized)
  }

  let detail: SessionDetail
  try {
    detail = await fetchSessionDetail(getXServiceHost(req.args, runEnv), sessionId, idToken, req.args["x-service-timeout"])
  } catch (error) {
    if (error instanceof TokenRejectedError) {
      throw new HttpError("id-token 已被服务端拒绝", HttpCode.Unauthorized)
    }
    if (error instanceof SessionNotFoundError) {
      throw new HttpError("会话不存在或已失效", HttpCode.Unauthorized)
    }
    throw new HttpError("认证服务不可用，请稍后重试", HttpCode.BadGateway)
  }

  if (!authorizeFolder(folder, detail.data!.artifactsPath!)) {
    throw new HttpError("无权访问该目录", HttpCode.Forbidden)
  }
}
```

- [ ] **Step 5: 运行测试确认通过**

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/xauth.test.ts`
Expected: PASS。

- [ ] **Step 6: 格式检查并提交**

```bash
npx prettier --write src/common/http.ts src/node/xauth.ts test/unit/node/xauth.test.ts
git add src/common/http.ts src/node/xauth.ts test/unit/node/xauth.test.ts
git commit -m "feat: 新增 xauth 模块（id-token 校验与会话目录授权）

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 3: `http.ts` 的 `authenticated()` 支持 x-token 模式

**Files:**
- Modify: `src/node/http.ts:17-22`（import）、`:117-139`（authenticated）
- Test: `test/unit/node/http.test.ts`

**Interfaces:**
- Consumes: Task 2 的 `assertXTokenAuthenticated(req)`、Task 1 的 `AuthType.XToken`。
- Produces: `authenticated()` 在 `req.args.auth === AuthType.XToken` 时校验 id-token（失败抛 HttpError 401），成功返回 true——`ensureAuthenticated` 及其所有调用方（catch-all、WS、domainProxy、pathProxy）自动获得 x-token 语义。

- [ ] **Step 1: 写失败测试**

`test/unit/node/http.test.ts` 顶部 import 追加：

```ts
import * as express from "express"
import { AuthType } from "../../../src/node/cli"
import type { DefaultedArgs } from "../../../src/node/cli"
```

在 `describe("http")` 内新增：

```ts
  describe("authenticated with x-token auth", () => {
    it("should throw 401 without an id-token", async () => {
      const req = getMockReq() as express.Request
      req.args = { auth: AuthType.XToken } as unknown as DefaultedArgs
      await expect(http.authenticated(req)).rejects.toMatchObject({ statusCode: 401 })
    })
  })
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/http.test.ts`
Expected: FAIL——`Unsupported auth type x-token`（authenticated 尚无 XToken 分支）。

- [ ] **Step 3: 实现 `authenticated()` 分支**

`src/node/http.ts` import 区末尾追加：

```ts
import { assertXTokenAuthenticated } from "./xauth"
```

`authenticated()` 的 switch 中，在 `case AuthType.Password` 之后新增：

```ts
    case AuthType.XToken: {
      // Throws an HttpError with a specific message when the id-token is
      // missing, malformed, or expired.
      assertXTokenAuthenticated(req)
      return true
    }
```

- [ ] **Step 4: 运行测试确认通过**

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/http.test.ts`
Expected: PASS。

- [ ] **Step 5: 格式检查并提交**

```bash
npx prettier --write src/node/http.ts test/unit/node/http.test.ts
git add src/node/http.ts test/unit/node/http.test.ts
git commit -m "feat: authenticated 支持 x-token 模式

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 4: `GET /` 页面的 folder 授权（routes/vscode.ts）

**Files:**
- Modify: `src/node/routes/vscode.ts:10`（import）、`:118-172`（GET / 处理器）
- Test: `test/unit/node/routes/vscode.test.ts`

**Interfaces:**
- Consumes: Task 2 的 `authorizeFolderRequest(req)`；Task 1 的 `AuthType.XToken`。
- Produces: XToken 模式下 `GET /`、`GET /vscode` 页面加载经过 xTokenGuard（401/400/403/502）；last-opened/CLI 重定向与 settings.write 在 XToken 模式下跳过。Password/None 行为不变。

**注意：** 400/401/403/502 用例不触发 VS Code 加载（guard 挂在 `ensureVSCodeLoaded` 之前）；200 用例需要 VS Code 已构建（`lib/vscode/out/server-main.js`，`npm install`/CI 已构建）。

- [ ] **Step 1: 写失败测试**

`test/unit/node/routes/vscode.test.ts` 中，在现有 `describe("vscode")` 内（复用其 `codeServer` 变量与 beforeEach/afterEach）新增：

```ts
  describe("x-token auth", () => {
    const makeToken = (payload: object) => {
      const enc = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url")
      return `${enc({ alg: "none" })}.${enc(payload)}.sig`
    }
    const validToken = () => makeToken({ exp: Math.floor(Date.now() / 1000) + 3600 })
    const expiredToken = () => makeToken({ exp: Math.floor(Date.now() / 1000) - 3600 })
    const cookie = (token: string) => `id-token=${token}; session-id=abc; run-env=dev`
    const mockSessionDetail = (artifactsPath: string) => {
      jest.spyOn(global, "fetch").mockResolvedValue({
        status: 200,
        ok: true,
        json: async () => ({ returnCode: "SUC0000", data: { artifactsPath } }),
      } as unknown as Response)
    }
    const setupXToken = () => integration.setup(["--auth=x-token"], "")

    afterEach(() => {
      jest.restoreAllMocks()
    })

    it("should 401 without an id-token", async () => {
      codeServer = await setupXToken()
      const resp = await codeServer.fetch("/", {}, { folder: "/home/x/artifacts" })
      expect(resp.status).toBe(401)
    })

    it("should 401 with an expired id-token", async () => {
      codeServer = await setupXToken()
      const resp = await codeServer.fetch("/", { headers: { cookie: cookie(expiredToken()) } }, { folder: "/home/x/artifacts" })
      expect(resp.status).toBe(401)
    })

    it("should 400 without a folder", async () => {
      codeServer = await setupXToken()
      const resp = await codeServer.fetch("/", { headers: { cookie: cookie(validToken()) } })
      expect(resp.status).toBe(400)
    })

    it("should 400 with a workspace param", async () => {
      codeServer = await setupXToken()
      const resp = await codeServer.fetch(
        "/",
        { headers: { cookie: cookie(validToken()) } },
        { folder: "/home/x/artifacts", workspace: "/w.code-workspace" },
      )
      expect(resp.status).toBe(400)
    })

    it("should 401 when x-service rejects the token", async () => {
      codeServer = await setupXToken()
      jest.spyOn(global, "fetch").mockResolvedValue({ status: 401, ok: false } as unknown as Response)
      const resp = await codeServer.fetch("/", { headers: { cookie: cookie(validToken()) } }, { folder: "/home/x/artifacts" })
      expect(resp.status).toBe(401)
    })

    it("should 403 when the folder does not match artifactsPath", async () => {
      codeServer = await setupXToken()
      mockSessionDetail("/home/x/projects/p/sessions/s/artifacts")
      const resp = await codeServer.fetch("/", { headers: { cookie: cookie(validToken()) } }, { folder: "/home/evil" })
      expect(resp.status).toBe(403)
    })

    it("should 502 when x-service is unreachable", async () => {
      codeServer = await setupXToken()
      jest.spyOn(global, "fetch").mockRejectedValue(new TypeError("fetch failed"))
      const resp = await codeServer.fetch("/", { headers: { cookie: cookie(validToken()) } }, { folder: "/home/x/artifacts" })
      expect(resp.status).toBe(502)
    })

    it("should load when the folder matches artifactsPath", async () => {
      codeServer = await setupXToken()
      mockSessionDetail("/home/x/projects/p/sessions/s/artifacts")
      const resp = await codeServer.fetch(
        "/",
        { headers: { cookie: cookie(validToken()) } },
        { folder: "/home/x/projects/p/sessions/s/artifacts" },
      )
      expect(resp.status).toBe(200)
    })
  })
```

- [ ] **Step 2: 运行测试确认失败**

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/routes/vscode.test.ts`
Expected: FAIL——守卫未挂载：`should 400 without a folder` 得到 200/302 而非 400；`should 403 when the folder does not match` 得到 200 而非 403（此时 Task 3 已使无 token/过期 token 的 401 用例通过）。

- [ ] **Step 3: 实现 `routes/vscode.ts` 改动**

3a. import 区改动：

```ts
import { AuthType, CodeArgs, toCodeArgs } from "../cli"
```

（原为 `import { CodeArgs, toCodeArgs } from "../cli"`），并追加：

```ts
import { authorizeFolderRequest } from "../xauth"
```

3b. 在 `ensureVSCodeLoaded` 之后新增守卫（约 line 117 之前）：

```ts
/**
 * Guard for the x-token auth mode on page loads: asserts the id-token and
 * authorizes the folder query param against the x-service session.  Throws
 * HttpError (401/400/403/502) on failure.  A no-op for other auth modes.
 * Mounted before ensureVSCodeLoaded so auth failures never load VS Code.
 */
const xTokenGuard = async (req: express.Request, _: express.Response, next: express.NextFunction): Promise<void> => {
  if (req.args.auth !== AuthType.XToken) {
    return next()
  }
  await authorizeFolderRequest(req)
  next()
}
```

3c. 挂载点：`router.get("/", ensureVSCodeLoaded, async (req, res, next) => {` 改为：

```ts
router.get("/", xTokenGuard, ensureVSCodeLoaded, async (req, res, next) => {
```

3d. 处理器主体：将 last-opened 重定向块与 settings.write 包进 XToken 排除分支。当前代码（line 131-169）：

```ts
  if (NO_FOLDER_OR_WORKSPACE_QUERY && !FOLDER_OR_WORKSPACE_WAS_CLOSED) {
    // ...existing last-opened redirect block, unchanged...
  }

  // Store the query parameters so we can use them on the next load.  This
  // also allows users to create functionality around query parameters.
  await req.settings.write({ query: req.query })
```

改为（内部块整体缩进 +4，内容不变）：

```ts
  // In x-token mode the folder was already authorized by xTokenGuard and the
  // last-opened/CLI redirect behavior is disabled.
  if (req.args.auth !== AuthType.XToken) {
    if (NO_FOLDER_OR_WORKSPACE_QUERY && !FOLDER_OR_WORKSPACE_WAS_CLOSED) {
      // ...existing last-opened redirect block, unchanged...
    }

    // Store the query parameters so we can use them on the next load.  This
    // also allows users to create functionality around query parameters.
    await req.settings.write({ query: req.query })
  }
```

- [ ] **Step 4: 运行测试确认通过**

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/routes/vscode.test.ts`
Expected: PASS。若 200 用例报 VS Code 加载错误，先执行 `npm run build:vscode` 再跑。

- [ ] **Step 5: 格式检查并提交**

```bash
npx prettier --write src/node/routes/vscode.ts test/unit/node/routes/vscode.test.ts
git add src/node/routes/vscode.ts test/unit/node/routes/vscode.test.ts
git commit -m "feat: 页面加载时校验 folder 与会话目录一致

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 5: 真实 x-service 往返测试（in-process 集成矩阵）

> 说明：spec 8.2 的集成矩阵放在 `test/unit/node/routes/vscode.test.ts`（in-process，真实 HTTP + 真实 TCP mock x-service），因为 `test:integration` 需要 release 二进制、无法方便地托管 mock 服务进程。覆盖实质一致：真实 fetch 网络路径 + 真实 cookie 解析。

**Files:**
- Test: `test/unit/node/routes/vscode.test.ts`

**Interfaces:**
- Consumes: Task 4 的全部路由行为；`test/utils/httpserver.ts` 的 `HttpServer`；`test/utils/integration.ts` 的 `setup(argv, configFile)`。

- [ ] **Step 1: 写失败测试**

在 `describe("x-token auth")` 后追加（复用文件顶部已有 import `* as httpserver`、`* as integration`）：

```ts
  describe("x-token auth with a real x-service", () => {
    let xService: httpserver.HttpServer | undefined
    const artifactsPath = "/home/x/projects/p/sessions/s/artifacts"

    beforeEach(async () => {
      xService = new httpserver.HttpServer()
      await xService.listen((_, res) => {
        res.setHeader("Content-Type", "application/json")
        res.end(JSON.stringify({ returnCode: "SUC0000", data: { artifactsPath } }))
      })
    })

    afterEach(async () => {
      if (xService) {
        await xService.dispose()
        xService = undefined
      }
    })

    it("should load the matching folder (real x-service round trip)", async () => {
      codeServer = await integration.setup(
        ["--auth=x-token", `--x-service-hosts={"dev":"http://127.0.0.1:${xService!.port()}"}`],
        "",
      )
      const cookie = `id-token=${makeToken({ exp: Math.floor(Date.now() / 1000) + 3600 })}; session-id=abc; run-env=dev`
      const resp = await codeServer.fetch("/", { headers: { cookie } }, { folder: artifactsPath })
      expect(resp.status).toBe(200)
    })

    it("should 403 for a mismatching folder (real x-service round trip)", async () => {
      codeServer = await integration.setup(
        ["--auth=x-token", `--x-service-hosts={"dev":"http://127.0.0.1:${xService!.port()}"}`],
        "",
      )
      const cookie = `id-token=${makeToken({ exp: Math.floor(Date.now() / 1000) + 3600 })}; session-id=abc; run-env=dev`
      const resp = await codeServer.fetch("/", { headers: { cookie } }, { folder: "/home/evil" })
      expect(resp.status).toBe(403)
    })
  })
```

注意：`makeToken` 在 `describe("x-token auth")` 块内定义，若作用域不可达，将其上移到外层 `describe("vscode")` 顶部共享。

- [ ] **Step 2: 运行测试确认通过**（实现已由 Task 4 完成，此处为新用例）

Run: `./test/node_modules/.bin/jest --coverage=false test/unit/node/routes/vscode.test.ts`
Expected: PASS（200 用例需 VS Code 已构建）。

- [ ] **Step 3: 格式检查并提交**

```bash
npx prettier --write test/unit/node/routes/vscode.test.ts
git add test/unit/node/routes/vscode.test.ts
git commit -m "test: x-service 真实往返的 x-token 鉴权用例

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

### Task 6: 文档与全量回归

**Files:**
- Modify: `CLAUDE.md`（Authentication 小节）

- [ ] **Step 1: 更新 CLAUDE.md**

`CLAUDE.md` 的 `**Authentication**` 段落（当前内容 "Password-based auth using argon2 hashing. Auth is checked via middleware (`ensureAuthenticated`, `ensureOrigin`). Supports `--skip-auth-preflight` for CORS preflight requests."）追加：

```markdown
- `x-token` mode (`--auth=x-token`) for the intranet portal: verifies the `id-token` cookie (JWT payload decode + `exp` check, no signature verification) on the `/` and `/vscode` routes; on page loads it also authorizes the `folder` query param against the session's `artifactsPath` from x-service (`GET http://{host}/session/{session-id}/detail` with the `id-token` header). Configure via `--x-service-hosts` (JSON map of run-env → host, or a YAML map in config.yaml), `--x-service-default-host` (default `localhost:9090`) and `--x-service-timeout` (ms, default 5000). See `docs/superpowers/specs/2026-08-13-code-server-xauth-design.md`.
```

- [ ] **Step 2: lint 与格式**

```bash
npm run lint:ts
npx prettier --write src/node/cli.ts src/node/http.ts src/node/xauth.ts src/node/routes/vscode.ts src/common/http.ts test/unit/node/cli.test.ts test/unit/node/http.test.ts test/unit/node/xauth.test.ts test/unit/node/routes/vscode.test.ts
```

如有 lint 报错，修复后重跑直至通过。

- [ ] **Step 3: 全量单测回归**

```bash
npm run test:unit
```

Expected: PASS（全部既有用例 + 新用例）。

- [ ] **Step 4: 提交**

```bash
git add CLAUDE.md
git commit -m "docs: 补充 x-token 认证说明

Co-Authored-By: Claude <noreply@anthropic.com>"
```

---

## 计划说明与偏差记录

- **spec 8.2 偏差**：spec 的"集成测试"落为 in-process 真实 HTTP 矩阵（Task 5），理由见该任务说明；覆盖矩阵与 spec 完全一致（401 无 cookie / 401 过期 / 400 无 folder / 400 workspace / 401 x-service 拒绝 / 403 不匹配 / 200 匹配 / 502 服务挂）。
- **spec 6.3**（routes/index.ts 零改动）无需任务，验证方式：Task 4 的路由测试在 `--auth=x-token` 下通过即证明 login/logout 分支与 catch-all 行为正确。
- **spec 9（YAGNI）**：无对应任务——不验签、不缓存、不动 manifest/mint-key/_static/healthz、不动 password 逻辑。
- **运行 200 用例的前置**：`lib/vscode/out/server-main.js` 需已构建（`npm install` 的 postinstall 或 `npm run build:vscode`）。
