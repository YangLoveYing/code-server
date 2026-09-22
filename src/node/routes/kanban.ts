import { field, logger } from "@coder/logger"
import * as crypto from "crypto"
import * as express from "express"
import * as http from "http"
import * as https from "https"
import { HttpCode, HttpError } from "../../common/http"

export const router = express.Router()

/**
 * GET /tasks — proxy XService kanban tasks API.
 * Reads run_env + id_token from cookies, forwards to XService, returns JSON.
 */
router.get("/tasks", async (req, res) => {
  const runEnv = req.cookies["run_env"] as string | undefined
  const idToken = req.cookies["id_token"] as string | undefined
  if (!runEnv || !idToken) {
    throw new HttpError("缺少会话认证信息", HttpCode.Unauthorized)
  }

  const hosts = req.args["x-service-hosts"]
  const host = hosts[runEnv] || req.args["x-service-default-host"]
  if (!host) {
    throw new HttpError("未知的运行环境", HttpCode.BadRequest)
  }

  const url = `${host.replace(/\/+$/, "")}/api/v1/usersMng/kanban/tasks`
  const requestFn = url.startsWith("https://") ? https.request : http.request
  const options: https.RequestOptions = {
    headers: { "ID-Token": idToken },
    timeout: 10000,
    rejectUnauthorized: false,
    secureOptions:
      crypto.constants.SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION |
      crypto.constants.SSL_OP_LEGACY_SERVER_CONNECT,
  }

  try {
    const response = await new Promise<http.IncomingMessage>((resolve, reject) => {
      const proxyReq = requestFn(url, options, resolve)
      proxyReq.on("timeout", () =>
        proxyReq.destroy(new Error("x-service kanban tasks request timed out")),
      )
      proxyReq.on("error", reject)
      proxyReq.end()
    })

    if (response.statusCode === 401) {
      throw new HttpError("认证信息已过期", HttpCode.Unauthorized)
    }
    if (response.statusCode && (response.statusCode < 200 || response.statusCode >= 300)) {
      throw new HttpError(`XService 返回 ${response.statusCode}`, HttpCode.BadGateway)
    }

    const chunks: Buffer[] = []
    response.on("data", (chunk: Buffer) => chunks.push(chunk))
    await new Promise<void>((resolve, reject) => {
      response.on("end", resolve)
      response.on("error", reject)
    })

    const body = Buffer.concat(chunks).toString("utf8")
    res.type("application/json").send(body)
  } catch (error) {
    if (error instanceof HttpError) {
      throw error
    }
    logger.error(`kanban tasks proxy failed: ${(error as Error).message}`, field("run-env", runEnv))
    throw new HttpError("看板任务服务不可用", HttpCode.BadGateway)
  }
})
