import { spawn, ChildProcess } from "child_process"
import * as path from "path"
import { onLine, OnLineCallback } from "../../src/node/util"

class LightWatcher {
  private rootPath = path.resolve(process.cwd())

  private webServer: ChildProcess | undefined
  private codeServerCompiler: ChildProcess

  public constructor() {
    this.codeServerCompiler = spawn("tsc", ["--watch", "--pretty", "--preserveWatchOutput"], {
      cwd: this.rootPath,
    })
  }

  private reloadWebServer = (): void => {
    if (this.webServer) {
      this.webServer.kill()
    }

    const args = process.argv.slice(2)
    this.webServer = spawn("node", [path.join(this.rootPath, "out/node/entry.js"), ...args])
    onLine(this.webServer, (line) => console.log("[code-server]", line))
    const { pid } = this.webServer

    this.webServer.on("exit", () => console.log("[code-server]", `Web process ${pid} exited`))

    console.log("\n[code-server]", `Spawned web server process ${pid}`)
  }

  public async initialize(): Promise<void> {
    for (const event of ["SIGINT", "SIGTERM"]) {
      process.on(event, () => this.dispose(0))
    }

    this.codeServerCompiler.on("exit", (code) => {
      console.log("[code-server]", "Compiler terminated unexpectedly")
      this.dispose(code)
    })

    if (this.codeServerCompiler.stderr) {
      this.codeServerCompiler.stderr.on("data", (d: string | Uint8Array) => process.stderr.write(d))
    }

    onLine(this.codeServerCompiler, this.parseCodeServerLine)
  }

  private parseCodeServerLine: OnLineCallback = (strippedLine, originalLine) => {
    if (!strippedLine.length) return

    console.log("[tsc]", originalLine)

    if (strippedLine.includes("Watching for file changes")) {
      console.log("[tsc] Finished compiling! (Refresh your web browser ♻️)")
      this.reloadWebServer()
    }
  }

  private dispose(code: number | null): void {
    console.log("[code-server]", "Killing...")
    this.codeServerCompiler?.removeAllListeners()
    this.codeServerCompiler?.kill()
    process.exit(typeof code === "number" ? code : 0)
  }
}

async function main(): Promise<void> {
  try {
    const watcher = new LightWatcher()
    await watcher.initialize()
  } catch (error: any) {
    console.error(error.message)
    process.exit(1)
  }
}

main()
