# code-server x-token 认证鉴权设计

日期：2026-08-13
状态：已与需求方对齐，已实现

## 1. 背景与目标

内网定制 code-server，接入 x-service 会话体系，实现：

1. 认证：请求携带 `id_token` cookie（JWT），缺失、畸形或过期一律 401 + 报错信息。
2. 鉴权（防水平越权）：访问 `/` 和 `/vscode` 根路径时，`folder` 参数必须非空，且必须是 x-service 查询到的会话 `artifactsPath` 本身或其子目录，否则 403。

x-service 会话查询接口：`GET {host}/api/v1/sessions/{session-id}/detail`（host 含协议），header 携带 `id-token`（否则 401）。返回：

```json
{
  "returnCode": "SUC0000",
  "data": { "id": 84445, "uid": "…", "artifactsPath": "/home/x/projects/…/artifacts", "…": "…" }
}
```

其中 `data.artifactsPath` 即会话对应工作目录。

## 2. 已对齐决策

| 决策点 | 结论 |
|---|---|
| 与现有 password 认证的关系 | 完全替换：新增 `AuthType.XToken`，该模式下 password 逻辑不生效 |
| 校验范围 | 仅 `/` 和 `/vscode`（含 WebSocket 升级）；`/_static`、`/healthz` 等保持公开（401 错误页自身依赖 `/_static` 资源） |
| JWT 校验深度 | 仅解 payload + 验 `exp`，不验签（信任边界在 x-service，它用 token 鉴权） |
| x-service host 配置 | 按 `run_env` cookie 映射 host 表；run_env 缺失或未命中时回退默认 host |
| folder 缺失 / 为空 / 非绝对路径 | 400 Bad Request |
| workspace 参数 / last-opened 重定向 | 新模式下禁用（workspace 参数 400；.code-workspace 可引用任意目录，放行会绕过校验） |
| x-service 异常映射 | 返回 401 → 401；非 SUC0000 / 无 artifactsPath → 401；网络错误 / 超时 / 5xx → 502 |
| folder 比对 | 双方 `path.normalize` + 去尾部斜杠后，用 `path.relative` 判断 folder 为 artifactsPath 本身或其子目录；前缀相同的兄弟目录（如 /proj 与 /proj2）不放行 |
| 错误响应格式 | 复用现有 `errorHandler` / `wsErrorHandler`（浏览器 HTML 错误页，XHR/WS 纯文本） |

## 3. 方案总览

采用「新增 AuthType（`x-token`）+ 独立模块」：

- `cli.ts`：新增 `AuthType.XToken` 与 3 个配置项（x-service hosts 映射、默认 host、超时）。
- 新模块 `src/node/xauth.ts`：JWT 解包验 exp、x-service 会话查询、folder 比对，全部可独立单测。
- `http.ts`：`authenticated()` 增加 `AuthType.XToken` 分支，失败抛带具体信息的 `HttpError`，使现有 `ensureAuthenticated`（HTTP catch-all、WS 升级、update 路由）与 domainProxy/pathProxy/login 的调用方在 XToken 模式下自动获得 401 语义，且不会重定向到 /login 造成循环。
- `routes/vscode.ts`：`GET /` 处理器在 XToken 模式下增加 folder 授权（400/401/403/502），并跳过 last-opened / CLI 参数重定向。
- `routes/index.ts`：零改动（login/logout 挂载条件 `args.auth === AuthType.Password` 不变，XToken 自然走 else 分支）。
- password 认证路径完全不被触碰，可回归。

## 4. 配置与 CLI（`src/node/cli.ts`）

### 4.1 AuthType

```ts
export enum AuthType {
  Password = "password",
  None = "none",
  XToken = "x-token", // 新增
}
```

`--auth=x-token` 启用。password 相关逻辑（login/logout 路由挂载、密码校验）在 XToken 模式下不生效。

### 4.2 新配置项

| 配置项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `x-service-hosts` | string（JSON 对象，如 `{"dev":"http://x.dev:9090","st":"https://x.st:9090"}`） | `{}`（空 map） | run_env → x-service host 映射 |
| `x-service-default-host` | string | `http://localhost:9090` | run_env 缺失或未命中映射时的回退 host |
| `x-service-timeout` | number（毫秒） | `10000` | 调用 x-service 的超时 |

⚠️ host **必须携带协议**（`http://` 或 `https://`）：代码不写死前缀，`fetchSessionDetail` 直接用 `${host}` 拼 URL（xauth.ts）。未带协议的 host 会在启动时直接报错（`setDefaults` 校验）。

#### 4.2.1 三种配置通道

三个配置项均可通过 CLI 参数、环境变量、config.yaml 配置，与 code-server 既有配置机制一致：

**1. CLI 参数**（`parse` 解析 argv，entry.ts）：

```bash
code-server --auth=x-token \
  --x-service-hosts='{"dev":"http://127.0.0.1:9999","prod":"http://x.prod:9090"}' \
  --x-service-default-host=http://127.0.0.1:9090 \
  --x-service-timeout=3000
```

**2. 环境变量**（`setDefaults` 中按 `PASSWORD` 等既有模式逐个 `if` 处理，cli.ts；变量非空才生效）：

| 环境变量 | 对应配置项 |
|---|---|
| `X_SERVICE_HOSTS` | `x-service-hosts`（JSON 字符串） |
| `X_SERVICE_DEFAULT_HOST` | `x-service-default-host` |
| `X_SERVICE_TIMEOUT` | `x-service-timeout` |

```bash
X_SERVICE_HOSTS='{"dev":"http://127.0.0.1:9999"}' \
X_SERVICE_DEFAULT_HOST=http://127.0.0.1:9090 \
X_SERVICE_TIMEOUT=3000 \
code-server --auth=x-token
```

**3. config.yaml**（默认 `~/.config/code-server/config.yaml`；可用 `--config <path>` 指定，或 `$CODE_SERVER_CONFIG` 覆盖路径）。`x-service-hosts` 可直接写原生 YAML map，`parseConfigFile` 会 `JSON.stringify` 后走统一解析，无需手写 JSON 字符串：

```yaml
auth: x-token
x-service-hosts:
  dev: http://127.0.0.1:9999
  prod: http://x.prod:9090
x-service-default-host: http://127.0.0.1:9090
x-service-timeout: 3000
```

#### 4.2.2 优先级

**环境变量 > CLI 参数 > config.yaml。**

`entry.ts` 中 `setDefaults(cliArgs, configArgs)` 先 `Object.assign({}, configArgs, cliArgs)`（CLI 覆盖配置文件），随后环境变量按「非空才覆盖」规则最后写入（`setDefaults` 内的 `if (process.env.X_SERVICE_…)`），故最终生效顺序为 env > CLI > config。

示例（config.yaml 中 timeout 为 8000）：

```bash
X_SERVICE_TIMEOUT=3000 code-server --x-service-timeout=9000
# 最终 timeout = 3000：环境变量覆盖 CLI，CLI 覆盖 config.yaml
```

与 `password` / `hashed-password` / `github-auth` 不同（禁止 CLI 传入），这三个 `x-service-*` 参数三种通道均可配置。

`setDefaults` 阶段完成 `JSON.parse` 与校验（`x-service-hosts` 非法 JSON 启动时报错），归一为 `Record<string, string>`。

#### 4.2.3 各环境 x-service host

| run_env | host |
|---|---|
| dev | `http://x-service.example.com` |
| st | `http://x-service-st.example.com` |
| oa | `http://x-service-oa.example.com` |
| prd | `http://x-service-prd.example.com` |

config.yaml 完整示例：

```yaml
auth: x-token
x-service-hosts:
  dev: http://x-service.example.com
  st: http://x-service-st.example.com
  oa: http://x-service-oa.example.com
  prd: http://x-service-prd.example.com
x-service-default-host: http://x-service.example.com
x-service-timeout: 10000
```

## 5. 认证组件 `src/node/xauth.ts`（新模块）

### 5.1 `verifyIdToken(idToken?: string)`

返回 `{ ok: true } | { ok: false; reason: "missing" | "malformed" | "expired" }`。

- 缺 token → `missing`；
- `split(".")` 取 payload 段，`Buffer.from(part, "base64url")` + `JSON.parse`，失败 → `malformed`；
- `payload.exp`（秒）≤ 当前时间 → `expired`。

不验签。无外部依赖（Node 22 原生 base64url）。

### 5.2 `fetchSessionDetail(host, sessionId, idToken, timeout)`

- `GET ${host}/api/v1/sessions/${encodeURIComponent(sessionId)}/detail`（host 含协议），header `id-token: <token>`，`AbortSignal.timeout(timeout)`。
- `returnCode !== "SUC0000"` 或 `data.artifactsPath` 缺失 → 抛 `SessionNotFoundError`。
- 网络错误 / 超时 → 抛 `UpstreamError`。
- x-service 返回 401 → 抛 `TokenRejectedError`。

### 5.3 `authorizeFolder(folder, artifactsPath)`

双方 `path.normalize` + 去尾部斜杠后，用 `path.relative(artifactsPath, folder)` 判断：

- 相对结果为 `""`（自身）→ 放行；
- 相对结果不以 `..` 开头且非绝对路径（子目录）→ 放行；
- 其余（兄弟目录、父目录）→ 不放行，403。

### 5.4 `authorizeFolderRequest(req)`（GET / 处理器调用）

按序校验并抛 `HttpError`：

1. folder 缺失 / 为空 → 400 `必须携带 folder 参数`
2. folder 非绝对路径 → 400
3. 携带 workspace 参数 → 400 `该认证模式不支持 workspace 参数`
4. session_id / run_env cookie 缺失 → 401 `缺少会话信息`
5. 按 run_env 查 hosts 表（未命中回退 `x-service-default-host`）→ `fetchSessionDetail`
6. artifactsPath 与 folder 比对，不等 → 403 `无权访问该目录`

## 6. 路由接入与数据流

### 6.1 `src/node/http.ts`

`authenticated()` 增加分支：

```ts
case AuthType.XToken:
  assertXTokenAuthenticated(req) // verifyIdToken 失败时抛 HttpError(401, 具体信息)
  return true
```

关键收益：`ensureAuthenticated` 覆盖的 HTTP catch-all、WS 升级、update 路由，以及 domainProxy/pathProxy/login 中直接调 `authenticated()` 的调用方，在 XToken 模式下自动变为「抛 401 + 报错信息」，而非「跳转 /login」——避免 redirect 循环（XToken 模式下 /login 会重定向回 /）。Password/None 分支零改动。

### 6.2 `src/node/routes/vscode.ts` 的 `GET /` 处理器（现 line 118）

- Password/None 分支保持原样。
- XToken 模式：`authenticated(req)` 已覆盖 token 校验（抛 401）；随后调用 `authorizeFolderRequest(req)`；跳过 last-opened / CLI 参数目录重定向、跳过 `settings.write`。

### 6.3 `src/node/routes/index.ts`

零改动。login/logout 挂载条件不变，XToken 走 else 分支（/login /logout 重定向到 /，最终由 GET / 抛 401）。catch-all 与 WS 路由由 `ensureAuthenticated` 自动获得 XToken 语义（仅验 token，不查 x-service、不查 folder）。

### 6.4 数据流（一次成功页面加载）

```
GET /?folder={artifactsPath} + cookies(run_env, session_id, id_token)
 → cookieParser → common → vscode.router GET /
 → authenticated(): 验 id_token（解包 + exp，失败抛 401）
 → authorizeFolderRequest(): 参数校验(400/401)
   → x-service 查会话（异常映射 401/502）→ 目录比对（403）
 → 原处理器 XToken 分支跳过重定向 → next()
 → catch-all: ensureAuthenticated（仅 token）→ VS Code 返回页面 HTML
后续子资源 /static、API、WS 请求 → catch-all 的 ensureAuthenticated（仅 token，零 x-service 调用）
```

**x-service 每个页面加载只被调用 1 次**，后续子资源请求零额外网络开销。

已知行为细节：VS Code 关闭工作区时会请求 `/?ew=...`（无 folder），XToken 模式下会得到 400 错误页——可接受（portal 始终带 folder 重新打开）。

## 7. 错误处理

全部通过 `HttpError` + 现有 `errorHandler` / `wsErrorHandler` 渲染，不新增渲染机制。浏览器（Accept 含 text/html）→ HTML 错误页；XHR/WS → 纯文本。

| 场景 | 状态码 | 信息 |
|---|---|---|
| 缺 id_token | 401 | `未认证` |
| 缺 session_id / run_env | 401 | `缺少会话信息` |
| token 畸形 | 401 | `认证信息无效` |
| token 过期 | 401 | `认证信息已过期` |
| x-service 返回 401 | 401 | `认证信息已被拒绝` |
| 会话不存在 / 非 SUC0000 / 无 artifactsPath | 401 | `会话不存在或已失效` |
| folder 缺失 / 空 / 非绝对路径 | 400 | `必须携带 folder 参数` |
| 携带 workspace 参数 | 400 | `该认证模式不支持 workspace 参数` |
| 目录不匹配 | 403 | `无权访问该目录` |
| x-service 网络错误 / 超时 / 5xx | 502 | `认证服务不可用，请稍后重试` |

日志安全：x-service 调用失败记 `logger.warn/error`，只含 session_id、run_env、状态码，不记录 id_token 全文。

## 8. 测试

### 8.1 单元测试（Jest，`test/unit/`）

- `xauth.test.ts`：
  - `verifyIdToken`：缺失 / 畸形 / 未过期 / 过期边界；
  - `authorizeFolder`：标准化、尾斜杠、自身/子目录放行、兄弟目录与父目录拒绝；
  - `fetchSessionDetail`（mock fetch）：x-service 401、非 SUC0000、缺 artifactsPath、网络错误、超时、正常返回。
- `cli.test.ts` 增补：`x-service-hosts` JSON 解析、非法 JSON 启动报错、默认值。
- 路由测试：XToken 模式下 `authenticated` 抛错分支、`GET /` 的 400/403 分支。

### 8.2 集成测试（`test/integration/`）

- 起 mock x-service（Node http server，按 id-token header 返回构造响应），起 code-server `--auth=x-token`。
- 断言：无 cookie → 401；过期 token → 401；无 folder → 400；带 workspace → 400；folder 为兄弟目录 → 403；folder 为会话目录本身 → 200；子目录 → 200；x-service 挂掉 → 502。

## 9. 不覆盖（YAGNI）

- 不验 JWT 签名（不引入 JWKS / 公钥配置）。
- 不做会话详情缓存（仅页面加载时查询一次，已足够）。
- 不改 `/manifest.json`、`/mint-key`、`/_static`、`/healthz`。
- 不动 password 认证逻辑。

## 10. 风险与备注

- 无本地缓存意味着 x-service 故障期间无法打开新页面（502），但已打开的会话不受影响（子资源请求不查 x-service）——符合预期。
- 报错信息为中文硬编码（内网产品，不走 i18n 体系）；如需 i18n 可在实现时挂入。
