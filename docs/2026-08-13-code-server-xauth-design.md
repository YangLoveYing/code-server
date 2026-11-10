# code-server x-token 认证鉴权设计

日期：2026-08-13
状态：已与需求方对齐，已实现（认证部分已加入 JWT 签名验签）
更新：2026-11-10 `auth-domains` 支持每个 run_env 配置多个认证域，按顺序验签，任一通过即放行

## 1. 背景与目标

内网定制 code-server，接入 x-service 会话体系，实现：

1. 认证：请求携带 `id_token` cookie（JWT）。本地校验结构与 `exp`，再按 `run_env` 对应认证域发布的 JWK 验签；缺失、畸形、过期、签名无效一律 401，认证域不可用 502，错误信息随响应返回。一个 `run_env` 可以配置多个认证域，按配置顺序依次尝试，任意一个验签通过即视为通过（开发环境常见做法：同时配置开发域与生产域，开发者用生产域签发的 token 访问开发环境也能通过）。
2. 鉴权（防水平越权）：访问 `/` 和 `/vscode` 根路径时，`folder` 参数必须非空，且必须是 x-service 查询到的会话 `artifactsPath` 本身或其子目录，否则 403。

x-service 会话查询接口：`GET {host}/api/v1/sessions/{session-id}/detail`（host 含协议），header 携带 `id-token`（否则 401）。返回：

```json
{
  "returnCode": "SUC0000",
  "data": { "id": 84445, "uid": "…", "artifactsPath": "/home/x/projects/…/artifacts", "…": "…" }
}
```

其中 `data.artifactsPath` 即会话对应工作目录。

认证域 JWK 接口：`GET {auth-domain}/jwk`，返回标准 JWK Set（`{"keys":[{...}]}`，也接受裸数组）。key 至少包含 `kty`、`kid`、`alg` 与公钥参数（RSA 的 `n`/`e`，EC 的 `crv`/`x`/`y`）。JWK 只用于验签，不感知业务身份。

> `x-service` 与 `auth-domain` 是两套独立端点：前者判「这个 token 对应哪个会话、能访问哪个目录」，后者判「这个 token 是不是它自己签发的」。缺一不可，见第 6.4 节数据流。

### 1.1 请求凭证（浏览器 → code-server 的 cookie）

本节只描述**入站**方向，即浏览器请求 code-server 时携带的 cookie。code-server 主动调用 x-service、认证域时走的是**出站**方向，传参方式完全不同（x-service 用 header `id-token`，见本节上方接口说明；认证域用 `GET /jwk`），不要把两者混为一谈。

实测抓到的入站请求 cookie 为三个参数：`id_token`、`run_env`、`session_id`。**下划线命名是规范名、也是实际使用的名字**；历史版本曾使用 `id-token` / `session-id` / `run-env`（提交 `086bea8d`），后续在 `85fc2476` 统一为下划线，现仅在读取时作为**兼容兜底**保留，不属于规范用法。请求头兜底（`id-token` / `x-id-token`、`x-session-id`、`x-run-env`）只为非浏览器客户端准备，浏览器侧一律走 cookie。

| 入站 cookie | 作用 | 代码读取入口 | 缺失时 | 非法 / 未命中时 |
|---|---|---|---|---|
| `id_token` | 待验签的 JWT。本地解 header/payload 校验结构与 `exp`，再用认证域 JWK 验签 | `readIdToken`（xauth.ts:82）← `assertXTokenAuthenticated`（xauth.ts:519）、`authorizeFolderRequest`（xauth.ts:461） | 401 `未认证`（所有经过 `ensureAuthenticated` 的请求） | 结构/`exp`/`alg`/签名不通过 → 401 `认证信息无效` 或 `认证信息已过期`；认证域不可用 → 502 |
| `run_env` | 环境选择键。决定验签用 `auth-domains[run_env]`（可能是多个域，依次尝试）还是 `auth-domains.default`；同时决定 `x-service-hosts[run_env]` 还是默认 host | `readRunEnv`（xauth.ts:90）← `assertXTokenAuthenticated`（xauth.ts:520-527）、`authorizeFolderRequest`（xauth.ts:449-464） | 不直接返回 401：验签侧回退 `auth-domains.default`，无 `default` 则 502 `认证服务不可用，请稍后重试`；但 `GET /` 的 folder 授权阶段需要它 → 401 `缺少会话信息` | 未命中映射时同上回退 `default`；无 `default` → 502 |
| `session_id` | 会话标识。folder 授权阶段用它向 x-service 查询该会话的 `artifactsPath`，再据此做 folder 比对 | `readSessionId`（xauth.ts:86）← 仅 `authorizeFolderRequest`（xauth.ts:447-460）；`ensureAuthenticated` 不读它 | 仅 `GET /` / `/vscode` 根路由 → 401 `缺少会话信息`；子资源请求不受影响 | 会话不存在（x-service 404 / 非 SUC0000 / 无 `artifactsPath`）→ 401 `会话不存在或已失效`；归属不匹配（x-service 401）→ 401 `认证信息已被拒绝`；网络/超时/5xx → 502 |

补充：三个来源（规范 cookie、历史连字符 cookie、header）在读取时按此优先级依次尝试，验签逻辑与来源无关；`id_token` 三处都没有值时返回 401 `未认证`——说明客户端根本没把 token 发到 code-server，不是验签失败。三者被读取后如何用于**出站**调用（把 `id_token` 值放进 `id-token` header、把 `session_id` 拼进会话路径、按 `run_env` 选 host），见第 6.4 节数据流。

## 2. 已对齐决策

| 决策点 | 结论 |
|---|---|
| 与现有 password 认证的关系 | 完全替换：新增 `AuthType.XToken`，该模式下 password 逻辑不生效 |
| 校验范围 | 仅 `/` 和 `/vscode`（含 WebSocket 升级）；`/_static`、`/healthz` 等保持公开（401 错误页自身依赖 `/_static` 资源） |
| JWT 校验深度 | 解 header/payload 校验结构与 `exp`，再按 `alg` 白名单从认证域 `/jwk` 拉公钥验签；拒绝 `none` 与 `HS*`（防算法混淆），仅接受 RS/PS/ES 系列 |
| 认证域配置 | 按 `run_env` cookie 映射 `auth-domains` 表；未命中回退 `default` 项；每个 run_env 可配一个或多个认证域（字符串或数组），多个域按顺序依次验签、任一通过即放行；`--auth=x-token` 下必须至少配置一项，否则启动即报错。认证域不像 x-service host 有内置默认值 |
| JWK 缓存 | 按认证域缓存公钥，默认 TTL 300s（`auth-jwk-cache-ttl`）；未知 kid 10s 内不重复拉取，拉取失败 5s 内不重试 |
| 验签失败语义 | 结构/`exp`/签名任一不通过 → 401（具体文案见第 7 节）；认证域不可达、超时、5xx、未配置 → 502。多个认证域时：任一域验签通过即 200；全部失败时，若有域属"不可用"类失败则返回 502，否则 401 |
| x-service host 配置 | 按 `run_env` cookie 映射 host 表；run_env 缺失或未命中时回退默认 host |
| folder 缺失 / 为空 / 非绝对路径 | 400 Bad Request |
| workspace 参数 / last-opened 重定向 | 新模式下禁用（workspace 参数 400；.code-workspace 可引用任意目录，放行会绕过校验） |
| x-service 异常映射 | 返回 401 → 401；返回 404 → 401（会话不存在）；非 SUC0000 / 无 artifactsPath → 401；网络错误 / 超时 / 5xx → 502 |
| folder 比对 | 双方 `path.normalize` + 去尾部斜杠后，用 `path.relative` 判断 folder 为 artifactsPath 本身或其子目录；前缀相同的兄弟目录（如 /proj 与 /proj2）不放行 |
| 错误响应格式 | 复用现有 `errorHandler` / `wsErrorHandler`（浏览器 HTML 错误页，XHR/WS 纯文本） |

## 3. 方案总览

采用「新增 AuthType（`x-token`）+ 独立模块」：

- `cli.ts`：新增 `AuthType.XToken` 与 5 个配置项（x-service hosts 映射、默认 host、超时；认证域映射、JWK 缓存 TTL）。
- 新模块 `src/node/xauth.ts`：JWT 解包验 exp、按 run_env 的认证域列表逐个 JWK 验签（任一通过即放行，含公钥缓存）、x-service 会话查询、folder 比对，全部可独立单测。
- `http.ts`：`authenticated()` 增加 `AuthType.XToken` 分支，`await assertXTokenAuthenticated(req)`；验签失败抛带具体信息的 `HttpError`，使现有 `ensureAuthenticated`（HTTP catch-all、WS 升级、update 路由）与 domainProxy/pathProxy/login 的调用方在 XToken 模式下自动获得 401/502 语义，且不会重定向到 /login 造成循环。
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

**x-service 侧（会话与目录鉴权）**

| 配置项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `x-service-hosts` | string（JSON 对象，如 `{"dev":"http://x.dev:9090","st":"https://x.st:9090"}`） | `{}`（空 map） | run_env → x-service host 映射 |
| `x-service-default-host` | string | `http://localhost:9090` | run_env 缺失或未命中映射时的回退 host |
| `x-service-timeout` | number（毫秒） | `10000` | 调用 x-service 的超时 |

**认证域侧（JWK 验签）**

| 配置项 | 类型 | 默认值 | 说明 |
|---|---|---|---|
| `auth-domains` | string（JSON 对象，值可以是字符串或字符串数组，如 `{"dev":["https://sso.dev.example.com","https://sso.prd.example.com"]}`） | `{}`（空 map），但 `--auth=x-token` 下必填 | run_env → 认证域（一个或多个）映射；未命中时回退 `default` 项。多个域按数组顺序依次验签，任一通过即放行。代码从 `${auth-domain}/jwk` 拉公钥验签 |
| `auth-jwk-cache-ttl` | number（毫秒） | `300000`（5 分钟） | JWK（公钥集合）缓存有效期，到期后下次验签重新拉取 |

验签配置的约束与行为：

- **必须带协议**：`auth-domains` 的每个值（包括数组中的每一项）都必须是 `http://` 或 `https://` 开头，否则 `setDefaults` 启动即抛错。末尾多余 `/` 会被自动去掉。
- **值类型**：每个 run_env 的值可以是单个字符串，也可以是字符串数组；数组不能为空，元素必须是字符串，否则启动报错（`auth domains for run-env "x" must not be empty` / `auth domains for run-env "x" must be a string or an array of strings`）。数组内重复的域会被去重（保留首次出现的顺序）。
- **必填性**：`--auth=x-token` 且 `auth-domains` 为空对象时，启动报错 `--auth-domains is required when --auth=x-token`。这与 x-service host 不同——后者有内置默认值，前者没有"内置认证域"这一概念，必须显式配置。
- **run_env 回退**：`run_env` cookie 缺失或未命中映射时使用 `auth-domains.default`；若连 `default` 也没有，请求以 502「认证服务不可用，请稍后重试」失败，而不是 401（属于部署配置缺失，不是客户端凭证错误）。
- **多域验签**：命中映射后按数组顺序逐个用该域的 `/jwk` 验签，**第一个通过即返回成功，不再访问后面的域**。典型场景是开发环境的 `dev` 同时配置开发域与生产域：开发者用生产域签发的 token 访问开发环境时，第一个域签名不匹配、第二个域通过。配置文件仍是一个 run_env 一个映射项，不需要改 `x-service-hosts`。
- **TLS**：与 x-service 一致，`rejectUnauthorized: false` 不校验证书（兼容内网自签名），并允许 legacy renegotiation；不跟随重定向，3xx 归入 502。
- **算法**：仅接受非对称算法 `RS256/384/512`、`PS256/384/512`、`ES256/384/512`；`alg=none` 与 `HS*` 一律拒绝（防算法混淆攻击），公钥类型（RSA/EC）与 `alg` 不匹配也拒绝。
- **缓存**：公钥按认证域缓存（不是按 run_env），并发请求合并为一次拉取；token 的 `kid` 在缓存中找不到时最多每 10s 重拉一次；拉取失败后 5s 内不再重试（该域直接视为 502 来源），避免认证域抖动时打爆上游。多域配置下每个域独立缓存、独立冷却。

⚠️ host **必须携带协议**（`http://` 或 `https://`）：代码不写死前缀，`fetchSessionDetail` 直接用 `${host}` 拼 URL（xauth.ts）。未带协议的 host 会在启动时直接报错（`setDefaults` 校验）。

https 支持：传输层用 `node:http/https`（xauth.ts），TLS 证书**不校验**（`rejectUnauthorized: false`，兼容自签名证书的内网部署），并开启 `SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION | SSL_OP_LEGACY_SERVER_CONNECT`（x-service 链路存在 legacy renegotiation，OpenSSL 3 默认拒绝，否则报 `EPROTO ... unsafe legacy renegotiation disabled`），且不跟随重定向（3xx 归入 502 上游异常）。

#### 4.2.1 三种配置通道

五个配置项均可通过 CLI 参数、环境变量、config.yaml 配置，与 code-server 既有配置机制一致：

**1. CLI 参数**（`parse` 解析 argv，entry.ts）：

```bash
code-server --auth=x-token \
  --x-service-hosts='{"dev":"http://127.0.0.1:9999","prod":"http://x.prod:9090"}' \
  --x-service-default-host=http://127.0.0.1:9090 \
  --x-service-timeout=3000 \
  --auth-domains='{"dev":["http://127.0.0.1:9999","https://sso.prod.example.com"],"prod":"https://sso.prod.example.com"}' \
  --auth-jwk-cache-ttl=300000
```

**2. 环境变量**（`setDefaults` 中按 `PASSWORD` 等既有模式逐个 `if` 处理，cli.ts；变量非空才生效）：

| 环境变量 | 对应配置项 |
|---|---|
| `X_SERVICE_HOSTS` | `x-service-hosts`（JSON 字符串） |
| `X_SERVICE_DEFAULT_HOST` | `x-service-default-host` |
| `X_SERVICE_TIMEOUT` | `x-service-timeout` |
| `AUTH_DOMAINS` | `auth-domains`（JSON 字符串） |
| `AUTH_JWK_CACHE_TTL` | `auth-jwk-cache-ttl`（毫秒） |

```bash
X_SERVICE_HOSTS='{"dev":"http://127.0.0.1:9999"}' \
X_SERVICE_DEFAULT_HOST=http://127.0.0.1:9090 \
X_SERVICE_TIMEOUT=3000 \
AUTH_DOMAINS='{"dev":["http://127.0.0.1:9999","https://sso.prd.example.com"]}' \
AUTH_JWK_CACHE_TTL=60000 \
code-server --auth=x-token
```

**3. config.yaml**（默认 `~/.config/code-server/config.yaml`；可用 `--config <path>` 指定，或 `$CODE_SERVER_CONFIG` 覆盖路径）。`x-service-hosts` 与 `auth-domains` 都可直接写原生 YAML map，`parseConfigFile` 会把对象值 `JSON.stringify` 后走统一解析，无需手写 JSON 字符串。`auth-domains` 的每个 run_env 既可以写单个域名，也可以写 YAML 列表：

```yaml
auth: x-token
x-service-hosts:
  dev: http://127.0.0.1:9999
  prod: http://x.prod:9090
x-service-default-host: http://127.0.0.1:9090
x-service-timeout: 3000
auth-domains:
  dev:
    - http://127.0.0.1:9999
    - https://sso.prod.example.com
  prod: https://sso.prod.example.com
auth-jwk-cache-ttl: 300000
```

#### 4.2.2 优先级

**环境变量 > CLI 参数 > config.yaml。**

`entry.ts` 中 `setDefaults(cliArgs, configArgs)` 先 `Object.assign({}, configArgs, cliArgs)`（CLI 覆盖配置文件），随后环境变量按「非空才覆盖」规则最后写入（`setDefaults` 内的 `if (process.env.X_SERVICE_…)`），故最终生效顺序为 env > CLI > config。

示例（config.yaml 中 timeout 为 8000）：

```bash
X_SERVICE_TIMEOUT=3000 code-server --x-service-timeout=9000
# 最终 timeout = 3000：环境变量覆盖 CLI，CLI 覆盖 config.yaml
```

与 `password` / `hashed-password` / `github-auth` 不同（禁止 CLI 传入），这五个 `x-service-*` / `auth-*` 参数三种通道均可配置。

`setDefaults` 阶段完成 `JSON.parse` 与校验（`x-service-hosts`、`auth-domains` 非法 JSON 启动时报错），`auth-domains` 归一为 `Record<string, string[]>`（单值自动包装成数组，去重、去尾斜杠）；`auth-jwk-cache-ttl` 未配置时取默认 300000。

#### 4.2.3 各环境 x-service host 与认证域

| run_env | x-service host | 认证域（JWK，按顺序尝试） |
|---|---|---|
| dev | `http://x-service.example.com` | `http://sso.example.com`、`http://sso-prd.example.com` |
| st | `http://x-service-st.example.com` | `http://sso-st.example.com`、`http://sso-prd.example.com` |
| oa | `http://x-service-oa.example.com` | `http://sso-oa.example.com`、`http://sso-prd.example.com` |
| prd | `http://x-service-prd.example.com` | `http://sso-prd.example.com` |

config.yaml 完整示例（非生产环境额外允许生产认证域签发的 token，便于开发者跨环境取 token；`x-service-hosts` 保持单域名不变）：

```yaml
auth: x-token
x-service-hosts:
  dev: http://x-service.example.com
  st: http://x-service-st.example.com
  oa: http://x-service-oa.example.com
  prd: http://x-service-prd.example.com
x-service-default-host: http://x-service.example.com
x-service-timeout: 10000
auth-domains:
  dev:
    - http://sso.example.com
    - http://sso-prd.example.com
  st:
    - http://sso-st.example.com
    - http://sso-prd.example.com
  oa:
    - http://sso-oa.example.com
    - http://sso-prd.example.com
  prd: http://sso-prd.example.com
auth-jwk-cache-ttl: 300000
```

## 5. 认证组件 `src/node/xauth.ts`（新模块）

### 5.1 `verifyIdToken(idToken?, domain?, cacheTtl?)`

```ts
verifyIdToken(
  idToken: string | undefined,
  domain: string | undefined,   // 该请求 run_env 对应的认证域
  cacheTtl = 300000,            // JWK 缓存 TTL
): Promise<{ ok: true } | { ok: false; reason: "missing" | "malformed" | "expired" | "invalid" | "upstream" }>
```

按序执行，任一步失败即提前返回，**不再继续后续步骤**：

| 步骤 | 检查内容 | 失败 reason |
|---|---|---|
| 1 | 无 `id_token` | `missing` |
| 2 | `split(".")` 不是 3 段 | `malformed` |
| 3 | 解码并 `JSON.parse` header/payload（`Buffer.from(part, "base64url")`） | `malformed` |
| 4 | JSON 结果为 `null` | `malformed` |
| 5 | `payload.exp` 不是 number | `malformed` |
| 6 | `payload.exp`（秒）≤ 当前时间 | `expired` |
| 7 | `header.alg` 不在白名单（`none`、`HS*` 均不在内） | `invalid` |
| 8 | `domain` 未配置（run_env 与 default 都未命中） | `upstream` |
| 9 | 从认证域拉取 JWK 失败（网络/超时/非 2xx/无可用 key/失败冷却中） | `upstream` |
| 10 | 缓存中找不到匹配 `kid` 的公钥 | `invalid` |
| 11 | 公钥类型与 `alg` 不匹配（ES* 需 EC，RS*/PS* 需 RSA） | `invalid` |
| 12 | `crypto.verify(hash, "${header}.${payload}", publicKey, signature)` 返回 false 或抛错 | `invalid` |
| 13 | 以上全部通过 | `ok: true` |

实现要点：

- **验签位于 base64url 解码之后，但"解码成功"不等于"一定验签"**：步骤 1、2 在解码之前就会返回；步骤 3~11 也会在到达 `crypto.verify` 之前提前返回。函数只有两种出口——`ok: true` 仅由第 12 步通过产生；其余所有路径都返回 `ok: false`。不存在"解码通过即放行"的分支。
- **`exp` 读取的是未验签的 payload**：这一步只用于提前拒绝，不能作为任何业务判断依据；真正的信任边界在第 12 步的签名校验。后续若要读取 `sub` / `uid` 等声明，必须只在 `ok: true` 之后使用。
- **验签输入**是 `${parts[0]}.${parts[1]}` 的原始字符串（不能先解码再拼接），签名是 `Buffer.from(parts[2], "base64url")`。
- 只用 Node 原生 `crypto`（`crypto.createPublicKey({ format: "jwk" })` + `crypto.verify`），**不引入 jose / jsonwebtoken 等依赖**。
- 不校验 `iss` / `aud` / `nbf`：本场景下 token 由固定认证域签发并由 x-service 二次校验会话归属，`iss`/`aud` 的语义由认证域自身保证。

#### 5.1.1 JWK 拉取与缓存

`GET ${domain}/jwk`，5s 请求超时；接受 `{ "keys": [...] }` 或裸数组，逐个 key 尝试 `crypto.createPublicKey`，解析失败的 key 跳过；一个可用 key 都没有则视为上游异常。

| 缓存项 | 行为 |
|---|---|
| 正向缓存 | 以认证域为 key（不是 run_env），缓存整份 JWK Set，TTL = `auth-jwk-cache-ttl` |
| 并发合并 | 同一域同时触发的拉取合并为一个 in-flight Promise，避免冷启动打爆认证域 |
| kid 未命中 | 缓存未过期但找不到 `kid` 时，最多每 10s 重新拉取一次（应对密钥轮换），其余请求直接 `invalid` |
| 失败冷却 | 拉取失败后 5s 内不再发起请求，直接 `upstream`（502），避免认证域故障时雪崩 |
| 无 kid | token 头无 `kid` 时，优先用无 kid 的 key；只有唯一 key 时也可匹配 |

#### 5.1.2 多域验签 `verifyIdTokenAgainstDomains(idToken?, domains?, cacheTtl?)`

```ts
verifyIdTokenAgainstDomains(
  idToken: string | undefined,
  domains: string[] | undefined,   // 该请求 run_env 对应的认证域列表，按配置顺序
  cacheTtl = 300000,
): Promise<IdTokenVerification>
```

`assertXTokenAuthenticated` 调用的是这个函数（内部逐个调用 `verifyIdToken`）：

| 情况 | 行为 |
|---|---|
| `domains` 为空 / 未配置 | 等价于调用 `verifyIdToken(idToken, undefined)`：缺失 token 仍返回 `missing`（401 未认证），结构/`exp` 校验照旧，之后才是 `upstream`（502） |
| 某个域返回 `ok: true` | 立即返回成功，**不再尝试后续域**（正常场景下第一个域即通过，多域无额外开销） |
| 某个域返回 `missing` / `malformed` / `expired` | 立即返回该结果：这三项是本地检查，与域名无关，继续尝试其他域没有意义 |
| 所有域都返回 `invalid`（签名不匹配 / 未知 kid / `alg` 不支持） | 返回 `invalid` → 401 `认证信息无效` |
| 所有域都失败，且其中至少一个域是 `upstream`（不可达 / 超时 / 非 2xx / 冷却中） | 返回 `upstream` → 502。优先报上游异常，因为 token 可能由那个暂时不可用的域签发，稍后重试可能成功 |

顺序按配置数组顺序，每个域的 JWK 缓存、未知 kid 冷却、失败冷却都互相独立（缓存 key 是域名，不是 run_env）。

### 5.2 `fetchSessionDetail(host, sessionId, idToken, timeout)`

- `GET ${host}/api/v1/sessions/${encodeURIComponent(sessionId)}/detail`（host 含协议），header `id-token: <token>`，socket 超时 `timeout`。传输层为 `node:http/https`，`rejectUnauthorized: false`（不校验 TLS 证书），`secureOptions` 允许 legacy renegotiation，不跟随重定向。
- `returnCode !== "SUC0000"` 或 `data.artifactsPath` 缺失 → 抛 `SessionNotFoundError`。
- x-service 返回 404（会话不存在）→ 抛 `SessionNotFoundError`。
- 网络错误 / 超时 / 3xx → 抛 `UpstreamError`。
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
  // 先本地解码校验，再用 run_env 对应认证域的公钥验签；
  // 失败抛 HttpError(401/502, 具体信息)。
  await assertXTokenAuthenticated(req)
  return true
```

`assertXTokenAuthenticated(req)` 的取域逻辑：`authDomains[run_env] || authDomains["default"]`（类型为 `string[]`），然后 `await verifyIdTokenAgainstDomains(id_token, domains, auth-jwk-cache-ttl)` 按顺序逐域验签，任一通过即放行；全部失败时按 `reason` 映射为 `HttpError`（见第 7 节）。

关键收益：`ensureAuthenticated` 覆盖的 HTTP catch-all、WS 升级、update 路由，以及 domainProxy/pathProxy/login 中直接调 `authenticated()` 的调用方，在 XToken 模式下自动变为「抛 401/502 + 报错信息」，而非「跳转 /login」——避免 redirect 循环（XToken 模式下 /login 会重定向回 /）。Password/None 分支零改动。

### 6.2 `src/node/routes/vscode.ts` 的 `GET /` 处理器（现 line 118）

- Password/None 分支保持原样。
- XToken 模式：`authenticated(req)` 已覆盖「解码 + exp + 验签」（失败抛 401/502）；随后调用 `authorizeFolderRequest(req)`；跳过 last-opened / CLI 参数目录重定向、跳过 `settings.write`。

### 6.3 `src/node/routes/index.ts`

零改动。login/logout 挂载条件不变，XToken 走 else 分支（/login /logout 重定向到 /，最终由 GET / 抛 401）。catch-all 与 WS 路由由 `ensureAuthenticated` 自动获得 XToken 语义（验签 + 验 exp，不查 x-service、不查 folder）。

### 6.4 数据流（一次成功页面加载）

```
GET /?folder={artifactsPath} + cookies(run_env, session_id, id_token)
 → cookieParser → common → vscode.router GET /
 → authenticated(): assertXTokenAuthenticated()
     ① 解 header/payload + 验 exp（失败 401）
     ② 按 run_env 取认证域列表（数组），依次用每个域的 JWK 验签，任一通过即继续；全部失败时签名错 401、有域不可达 502
 → authorizeFolderRequest(): 参数校验(400/401)
   → x-service 查会话（异常映射 401/502）→ 目录比对（403）
 → 原处理器 XToken 分支跳过重定向 → next()
 → catch-all: ensureAuthenticated（验签 + exp）→ VS Code 返回页面 HTML
后续子资源 /static、API、WS 请求 → catch-all 的 ensureAuthenticated（验签 + exp）
```

**x-service 每个页面加载只被调用 1 次**；认证域 JWK 按 TTL 缓存，正常命中缓存时后续子资源请求不产生任何上游 HTTP 调用（缓存过期后的首个请求会触发一次 `/jwk` 拉取，同样有并发合并）。

已知行为细节：VS Code 关闭工作区时会请求 `/?ew=...`（无 folder），XToken 模式下会得到 400 错误页——可接受（portal 始终带 folder 重新打开）。

## 7. 错误处理

全部通过 `HttpError` + 现有 `errorHandler` / `wsErrorHandler` 渲染，不新增渲染机制。浏览器（Accept 含 text/html）→ HTML 错误页；XHR/WS → 纯文本。

| 场景 | 状态码 | 信息 |
|---|---|---|
| 缺 id_token | 401 | `未认证` |
| token 畸形（非 3 段 / 解码失败 / `exp` 非数字） | 401 | `认证信息无效` |
| token 过期 | 401 | `认证信息已过期` |
| 签名无效 / `alg` 不支持 / 公钥类型不匹配 / 未知 kid | 401 | `认证信息无效` |
| 缺 session_id / run_env（仅 `GET /` 的 folder 授权阶段） | 401 | `缺少会话信息` |
| x-service 返回 401 | 401 | `认证信息已被拒绝` |
| 会话不存在（HTTP 404 / 非 SUC0000 / 无 artifactsPath） | 401 | `会话不存在或已失效` |
| folder 缺失 / 空 / 非绝对路径 | 400 | `必须携带 folder 参数` |
| 携带 workspace 参数 | 400 | `该认证模式不支持 workspace 参数` |
| 目录不匹配 | 403 | `无权访问该目录` |
| 认证域未配置 / 认证域不可达 / 超时 / 非 2xx / 无可用 JWK | 502 | `认证服务不可用，请稍后重试`（多域时：任一域通过则不出错；全部失败且含不可用类失败则 502，否则按下一条 401） |
| x-service 网络错误 / 超时 / 5xx | 502 | `认证服务不可用，请稍后重试` |

日志安全：所有认证相关日志统一以 `[Auth]` 前缀。启动时（`setDefaults`，仅 `--auth=x-token`）各打一条 info：环境解析方式与已配置的 run_env 列表、`auth-domains` 是否有 `default`，以及 `x-service-hosts` / `x-service-default-host` / `x-service-timeout` / `auth-domains` / `auth-jwk-cache-ttl` 的完整取值（这些字段只含 URL 与数值，不含凭证）。请求侧只在失败时打一条，包含 `reason`、`auth-type`、`id-token-source`（cookie/header 具体来源）、`run-env` 与来源、`run-env-matched`、`auth-domains`（本次尝试的全部认证域，逗号分隔）与来源；不记录 token 全文，也不记录公钥内容。

## 8. 测试

### 8.1 单元测试（Jest，`test/unit/node/xauth.test.ts`）

- `verifyIdToken`：缺失 / 畸形 / 过期边界 / 合法 RS256 / 合法 ES256；
- 验签负例：篡改 payload、`alg=none`、`HS256`（后两者断言**不发起 JWK 请求**）、未知 `kid`、JWK 端点报错（`upstream`）、run_env 无匹配且无 default（`upstream`）；
- 缓存行为：并发验签只拉一次 JWK、TTL 内命中缓存、TTL 过期后重新拉取；
- 取域回退：run_env 未配置时使用 `default`；run_env 的值是数组时按顺序尝试；
- 多域验签（`assertXTokenAuthenticated` + `verifyIdTokenAgainstDomains`）：第一个域通过即成功且不再请求后续域、第二个域才通过时成功、所有域都不匹配 → 401 `认证信息无效`、一个域不可用且无域通过 → 502；
- `assertXTokenAuthenticated`：各 `reason` 映射为对应的 401/502 文案；
- `authorizeFolder`：标准化、尾斜杠、自身/子目录放行、兄弟目录与父目录拒绝；
- `fetchSessionDetail`：x-service 401、非 SUC0000、缺 artifactsPath、网络错误、超时、正常返回。

`test/unit/node/cli.test.ts` 另有 `auth-domains` 专项：x-token 模式必填、JSON 字符串解析、字符串/数组两种值形态、多域去重、YAML 列表、空数组与非字符串元素报错、末尾斜杠归一、非法 JSON 报错、`auth-jwk-cache-ttl` 默认值与显式值。

### 8.2 E2E 测试（Playwright，`test/e2e/xauth.test.ts`）

- mock server 同时提供 `GET /jwk`（返回测试 RSA 公钥）与 session detail；测试用私钥对 `{alg:"RS256",kid:"test-key"}.{exp}` 现场签发 token。
- 启动参数含 `--auth=x-token --x-service-timeout=500 --x-service-default-host=… --auth-domains={"dev":"…"}`。
- 断言：无 token → 401 `未认证`；过期 → 401 `认证信息已过期`；缺 session_id → 401 `缺少会话信息`；无 folder → 400；带 workspace → 400；x-service 拒绝 → 401；会话不存在（404 与非 SUC0000 两种）→ 401；兄弟目录 → 403；会话目录本身与子目录 → 200；x-service 不响应 → 502。

## 9. 不覆盖（YAGNI）

- 不校验 `iss` / `aud` / `nbf`（见 5.1）。
- 不做 token 吊销 / 黑名单查询：本地只判「签名有效 + 未过期」，会话是否仍然有效由 x-service 判定。
- 不复用 VS Code 侧 `xserviceAuth.ts` 的会话缓存（那是 sessionID 维度、TTL 12h 的缓存，语义与 JWK 缓存不同）。
- 不做 x-service 会话详情缓存（仅页面加载时查询一次，已足够）；JWK 缓存不在此列，已实现。
- 不改 `/manifest.json`、`/mint-key`、`/_static`、`/healthz`：这些路由注册在 `ensureAuthenticated` 之前或自身无认证，本次未收口。
- 不动 password 认证逻辑。

## 10. 风险与备注

- x-service 无本地缓存：故障期间无法打开新页面（502），但已打开的会话不受影响（子资源请求不查 x-service）——符合预期。
- 认证域的影响面更大：验签覆盖所有经过 `ensureAuthenticated` 的请求，因此认证域故障会让已打开会话的子资源请求也失败（502）。JWK 缓存（默认 5 分钟）只能抵挡「缓存过期后」的那部分请求，部署时应保证认证域可用性不低于 code-server 自身。
- 密钥轮换延迟：公钥按 TTL 缓存，认证域轮换签名密钥后，最坏情况下旧 key 仍会被接受至 TTL 到期；紧急吊销可把 `auth-jwk-cache-ttl` 调小（代价是更频繁的 `/jwk` 请求）。
- 多域验签的代价：token 不属于第一个域时，需要多访问一次（或多次）后置域的 `/jwk`。JWK 按域缓存后这部分是内存查找；但某个域冷缓存/缓存过期时会增加一次上游请求与最长 5s 的等待（该域不可达时）。建议把最常用的域放在数组第一位。
- 多域配置扩大了信任面：只要 token 由该 run_env 数组中的任一认证域签发即放行，因此不要在低信任环境里加入不应互相信任的认证域。
- `exp` 由客户端携带的未验签 payload 读取，只用于提前拒绝；安全边界始终是签名校验，见 5.1。
- 报错信息为中文硬编码（内网产品，不走 i18n 体系）；如需 i18n 可在实现时挂入。

## 11. 本地调试（`npm run watch` / `npm run dev`）

两个脚本都会把 `--` 之后的参数原样透传给 `out/node/entry.js`（`ci/dev/watch.ts` 与 `ci/dev/watch-light.ts` 中均为 `process.argv.slice(2)`），所以 `--` 后面的内容就是完整的 code-server CLI 参数。

- `npm run dev`：轻量版（仅 `tsc --watch` + 重启 web 服务），内存约 500MB，改 `src/` 时用这个。
- `npm run watch`：完整版（额外编译 VS Code），仅改动 `lib/vscode` 或 patch 时需要。

### 11.1 基础参数（base64url 解码阶段就需要）

```bash
npm run dev -- --auth=x-token \
  --x-service-hosts='{"dev":"http://127.0.0.1:9999"}' \
  --x-service-default-host=http://127.0.0.1:9999 \
  --x-service-timeout=3000
```

**引号很重要**：`--x-service-hosts='{"dev":"..."}'` 必须用单引号包住整个参数。若不加单引号，shell 会吞掉内层双引号，最终 argv 变成 `--x-service-hosts={dev:http://...}`，JSON 非法，启动直接报 `--x-service-hosts must be a valid JSON object`。

### 11.2 本次新增的验签参数

```bash
npm run dev -- --auth=x-token \
  --x-service-default-host=http://127.0.0.1:9999 \
  --auth-domains='{"dev":["http://127.0.0.1:9999","http://127.0.0.1:9998"]}' \
  --auth-jwk-cache-ttl=60000
```

`auth-domains` 指向一个能提供 `GET /jwk` 的服务，值可以是单个域名字符串，也可以是域名数组（数组按顺序逐个尝试，任一通过即放行）。本地没有真实认证域时，可参考 `test/e2e/xauth.test.ts` 的 `startMockXService`：它用 `crypto.generateKeyPairSync("rsa")` 生成密钥对，`/jwk` 返回公钥，同时充当 x-service 返回 session detail。调试期把 `auth-jwk-cache-ttl` 调小（如 60000）便于验证密钥更新。

认证域与 x-service 可以指向同一地址（如上例），也可以分开配置；`auth-domains` 未配置时 x-token 模式启动即失败。想验证多域回退时，可以让数组第一项指向一个返回 500 或密钥不匹配的地址，第二项指向 mock 服务。

两个脚本参数完全一致，需要同时调试 VS Code 侧时把 `npm run dev` 换成 `npm run watch`：

```bash
npm run watch -- --auth=x-token \
  --x-service-default-host=http://127.0.0.1:9999 \
  --auth-domains='{"dev":["http://127.0.0.1:9999","http://127.0.0.1:9998"]}' \
  --auth-jwk-cache-ttl=60000
```

### 11.3 环境变量方式（避免引号问题，优先级最高）

```bash
AUTH_DOMAINS='{"dev":["http://127.0.0.1:9999","http://127.0.0.1:9998"]}' \
AUTH_JWK_CACHE_TTL=60000 \
X_SERVICE_DEFAULT_HOST=http://127.0.0.1:9999 \
npm run dev -- --auth=x-token
```

环境变量 > CLI > config.yaml；`AUTH_DOMAINS` 为非空字符串即覆盖其他来源。

### 11.4 浏览器侧造 cookie

认证依赖三个 cookie，本地调试可在 DevTools Console 直接写入：

```js
document.cookie = "id_token=<签名后的 JWT>; path=/"
document.cookie = "session_id=sess-ok; path=/"
document.cookie = "run_env=dev; path=/"
```

然后访问 `http://localhost:8080/?folder=<artifactsPath>`。注意 `folder` 必须与 x-service 返回的 `artifactsPath` 一致或是其子目录；`id_token` 必须由 `auth-domains.dev` 列表中任一域的私钥签发（或直接复用 mock 服务签发的 token）。

### 11.5 快速自检清单

| 现象 | 排查方向 |
|---|---|
| 启动报 `--auth-domains is required when --auth=x-token` | 未配置 `auth-domains`，或 JSON 非法被解析成空对象 |
| 启动报 `auth domain for run-env "x" must include a protocol` | 认证域缺 `http://` / `https://`（数组中的每一项都会校验） |
| 启动报 `auth domains for run-env "x" must not be empty` | 该 run_env 配了空数组，删掉该项或至少给一个域名 |
| 启动报 `auth domains for run-env "x" must be a string or an array of strings` | 值写成了对象/数字等不支持的类型 |
| 401 `认证信息无效` | 用了伪造/未签名 token，或 `alg`/`kid` 与所有已配置域的 `/jwk` 都不匹配（可先 `curl <domain>/jwk` 看返回） |
| 401 `认证信息已过期` | token 的 `exp` 已过，重新签发 |
| 502 `认证服务不可用` | 认证域不可达/超时/`/jwk` 非 2xx（多域时至少一个域如此且无域通过）；也可能是 `run_env` 与 `default` 都没配 |
| 502 但认证域正常 | 检查 JWK 结构：必须是 `{"keys":[...]}` 或裸数组，且 key 能被 `crypto.createPublicKey` 解析 |
| 改了密钥但一直验不过 | JWK 缓存未过期，调小 `auth-jwk-cache-ttl` 或重启进程 |
| 某环境的 token 一直 401 | 确认该 token 的签发域确实写在这个 run_env 的 `auth-domains` 数组里（数组不跨 run_env 共享，回退只用 `default`） |
