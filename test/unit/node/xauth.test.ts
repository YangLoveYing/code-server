import * as crypto from "crypto"
import { once } from "events"
import * as express from "express"
import * as http from "http"
import { AddressInfo } from "net"
import { HttpError } from "../../../src/common/http"
import type { DefaultedArgs } from "../../../src/node/cli"
import { assertXTokenAuthenticated, verifyIdToken } from "../../../src/node/xauth"
import { mockLogger } from "../../utils/helpers"

const { publicKey: rsaPublicKey, privateKey: rsaPrivateKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
})
const { publicKey: ecPublicKey, privateKey: ecPrivateKey } = crypto.generateKeyPairSync("ec", {
  namedCurve: "P-256",
})

const RSA_JWK = { ...rsaPublicKey.export({ format: "jwk" }), kid: "test-key", alg: "RS256", use: "sig" }
const EC_JWK = { ...ecPublicKey.export({ format: "jwk" }), kid: "test-key", alg: "ES256", use: "sig" }

const HASHES: Record<string, string> = { RS256: "sha256", ES256: "sha256" }

const encode = (obj: object): string => Buffer.from(JSON.stringify(obj)).toString("base64url")

const signJwt = (payload: object, privateKey: crypto.KeyObject, alg = "RS256", kid = "test-key"): string => {
  const input = `${encode({ alg, kid })}.${encode(payload)}`
  const dsaEncoding = alg.startsWith("ES") ? ("ieee-p1363" as const) : undefined
  const signature = crypto.sign(HASHES[alg], Buffer.from(input, "utf8"), { key: privateKey, dsaEncoding })
  return `${input}.${signature.toString("base64url")}`
}

const unsignedToken = (header: object, payload: object): string => `${encode(header)}.${encode(payload)}.signature`

const tokenExp = (secondsFromNow: number): number => Math.floor(Date.now() / 1000) + secondsFromNow

const VALID_TOKEN = signJwt({ exp: tokenExp(300) }, rsaPrivateKey)
const EXPIRED_TOKEN = signJwt({ exp: tokenExp(-300) }, rsaPrivateKey)

const servers: http.Server[] = []

/**
 * Start an isolated JWK server.  A new port gives a new domain which keeps the
 * module-level JWK cache from leaking between tests.
 */
const startJwkServer = async (
  handler?: (req: http.IncomingMessage, res: http.ServerResponse) => void,
): Promise<{ url: string; requests: () => number }> => {
  let requests = 0
  const server = http.createServer((req, res) => {
    if (req.url !== "/jwk") {
      res.writeHead(404)
      res.end()
      return
    }
    requests++
    if (handler) {
      handler(req, res)
      return
    }
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ keys: [RSA_JWK] }))
  })
  servers.push(server)
  server.listen(0, "127.0.0.1")
  await once(server, "listening")
  const port = (server.address() as AddressInfo).port
  return { url: `http://127.0.0.1:${port}`, requests: () => requests }
}

const startEcJwkServer = async (): Promise<{ url: string; requests: () => number }> => {
  let requests = 0
  const server = http.createServer((req, res) => {
    requests++
    res.writeHead(200, { "Content-Type": "application/json" })
    res.end(JSON.stringify({ keys: [EC_JWK] }))
  })
  servers.push(server)
  server.listen(0, "127.0.0.1")
  await once(server, "listening")
  const port = (server.address() as AddressInfo).port
  return { url: `http://127.0.0.1:${port}`, requests: () => requests }
}

const makeReq = (cookies: Record<string, string>, args: Partial<DefaultedArgs> = {}): express.Request =>
  ({
    cookies,
    args: {
      "auth-domains": {},
      "auth-jwk-cache-ttl": 300000,
      "x-service-timeout": 500,
      ...args,
    },
  }) as unknown as express.Request

const expectHttpError = async (promise: Promise<void>, statusCode: number, message: string): Promise<void> => {
  const error = await promise.then(
    () => undefined,
    (e: unknown) => e,
  )
  expect(error).toBeInstanceOf(HttpError)
  expect((error as HttpError).statusCode).toBe(statusCode)
  expect((error as HttpError).message).toBe(message)
}

describe("verifyIdToken", () => {
  beforeEach(() => {
    mockLogger()
  })

  afterEach(async () => {
    await Promise.all(servers.map((server) => new Promise<void>((resolve) => server.close(() => resolve()))))
    servers.length = 0
    jest.restoreAllMocks()
  })

  it("should reject a missing token", async () => {
    await expect(verifyIdToken(undefined, undefined)).resolves.toStrictEqual({ ok: false, reason: "missing" })
  })

  it("should reject malformed tokens", async () => {
    await expect(verifyIdToken("not-a-jwt", undefined)).resolves.toStrictEqual({ ok: false, reason: "malformed" })
    await expect(verifyIdToken("a.b.c", undefined)).resolves.toStrictEqual({ ok: false, reason: "malformed" })
  })

  it("should reject an expired token", async () => {
    await expect(verifyIdToken(EXPIRED_TOKEN, undefined)).resolves.toStrictEqual({ ok: false, reason: "expired" })
  })

  it("should accept a valid RS256 token", async () => {
    const server = await startJwkServer()
    await expect(verifyIdToken(VALID_TOKEN, server.url)).resolves.toStrictEqual({ ok: true })
    expect(server.requests()).toBe(1)
  })

  it("should reject a token with a tampered payload", async () => {
    const server = await startJwkServer()
    const [, , signature] = VALID_TOKEN.split(".")
    const tampered = `${VALID_TOKEN.split(".")[0]}.${encode({ exp: tokenExp(300) + 1 })}.${signature}`
    await expect(verifyIdToken(tampered, server.url)).resolves.toStrictEqual({ ok: false, reason: "invalid" })
  })

  it("should reject alg none without fetching the JWK set", async () => {
    const server = await startJwkServer()
    const token = unsignedToken({ alg: "none" }, { exp: tokenExp(300) })
    await expect(verifyIdToken(token, server.url)).resolves.toStrictEqual({ ok: false, reason: "invalid" })
    expect(server.requests()).toBe(0)
  })

  it("should reject HMAC algorithms without fetching the JWK set", async () => {
    const server = await startJwkServer()
    const token = unsignedToken({ alg: "HS256" }, { exp: tokenExp(300) })
    await expect(verifyIdToken(token, server.url)).resolves.toStrictEqual({ ok: false, reason: "invalid" })
    expect(server.requests()).toBe(0)
  })

  it("should reject an unknown kid after fetching the JWK set", async () => {
    const server = await startJwkServer()
    const token = signJwt({ exp: tokenExp(300) }, rsaPrivateKey, "RS256", "unknown-key")
    await expect(verifyIdToken(token, server.url)).resolves.toStrictEqual({ ok: false, reason: "invalid" })
    expect(server.requests()).toBe(1)
  })

  it("should only fetch the JWK set once for concurrent verifications", async () => {
    const server = await startJwkServer()
    await Promise.all(Array.from({ length: 5 }, () => verifyIdToken(VALID_TOKEN, server.url)))
    expect(server.requests()).toBe(1)
  })

  it("should cache the JWK set for the ttl and refetch once it expires", async () => {
    const longLived = await startJwkServer()
    await verifyIdToken(VALID_TOKEN, longLived.url, 300000)
    await verifyIdToken(VALID_TOKEN, longLived.url, 300000)
    expect(longLived.requests()).toBe(1)

    const shortLived = await startJwkServer()
    await verifyIdToken(VALID_TOKEN, shortLived.url, 50)
    await new Promise((resolve) => setTimeout(resolve, 80))
    await verifyIdToken(VALID_TOKEN, shortLived.url, 50)
    expect(shortLived.requests()).toBe(2)
  })

  it("should fail upstream when the JWK endpoint returns an error", async () => {
    const server = await startJwkServer((_req, res) => {
      res.writeHead(500)
      res.end("boom")
    })
    await expect(verifyIdToken(VALID_TOKEN, server.url)).resolves.toStrictEqual({ ok: false, reason: "upstream" })
    expect(server.requests()).toBe(1)
  })

  it("should fail upstream when run_env has no matching or default domain", async () => {
    const server = await startJwkServer()
    await expect(verifyIdToken(VALID_TOKEN, undefined)).resolves.toStrictEqual({ ok: false, reason: "upstream" })
    await expect(
      assertXTokenAuthenticated(makeReq({ id_token: VALID_TOKEN, run_env: "prd" }, { "auth-domains": {} })),
    ).rejects.toBeInstanceOf(HttpError)
    await expectHttpError(
      assertXTokenAuthenticated(
        makeReq({ id_token: VALID_TOKEN, run_env: "prd" }, { "auth-domains": { dev: server.url } }),
      ),
      502,
      "认证服务不可用，请稍后重试",
    )
  })

  it("should use the default domain when run_env is not configured", async () => {
    const server = await startJwkServer()
    await expect(
      assertXTokenAuthenticated(
        makeReq({ id_token: VALID_TOKEN, run_env: "prd" }, { "auth-domains": { default: server.url } }),
      ),
    ).resolves.toBeUndefined()
  })

  it("should throw 401 errors with specific messages", async () => {
    await expectHttpError(assertXTokenAuthenticated(makeReq({})), 401, "未认证")
    await expectHttpError(
      assertXTokenAuthenticated(makeReq({ id_token: EXPIRED_TOKEN })),
      401,
      "认证信息已过期",
    )
    await expectHttpError(
      assertXTokenAuthenticated(
        makeReq({ id_token: unsignedToken({ alg: "none" }, { exp: tokenExp(300) }) }),
      ),
      401,
      "认证信息无效",
    )
  })

  it("should accept a valid ES256 token", async () => {
    const server = await startEcJwkServer()
    const token = signJwt({ exp: tokenExp(300) }, ecPrivateKey, "ES256")
    await expect(verifyIdToken(token, server.url)).resolves.toStrictEqual({ ok: true })
  })
})
