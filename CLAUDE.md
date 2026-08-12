# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

code-server runs VS Code on a remote server, accessible through a web browser. It wraps Microsoft's VS Code (`lib/vscode` git submodule, forked) with an Express HTTP server that handles authentication, proxies, and serving the VS Code web frontend.

- **Node version**: 22 (see `.node-version`)
- **VS Code submodule**: `lib/vscode` — a fork of `microsoft/vscode`. VS Code patches live in `patches/` and are applied during `postinstall`.

## Common Commands

### Build

- `npm run build` — Build code-server itself (TypeScript → `out/`)
- `npm run build:vscode` — Build the VS Code submodule
- `npm run release` — Create the release bundle
- `npm run package` — Create platform packages
- `npm run build:code` — Full pipeline: install → build → build:vscode → release → package

### Development

- `npm run watch` — Start code-server in dev/watch mode with auto-reload
- `npm install` — Triggers `postinstall` which applies patches to `lib/vscode`, installs its dependencies, and builds both code-server and VS Code

### Testing

- `npm run test:unit` — Run Jest unit tests (with `--forceExit --detectOpenHandles`)
- `npm run test:e2e` — Run Playwright end-to-end tests (Chromium only)
- `npm run test:integration` — Run integration tests
- `npm run test:scripts` — Test shell scripts
- `npm run test:native` — Run native module tests

#### Running a single test

```bash
# Unit test
npx jest test/unit/helpers.test.ts

# E2E test
npx playwright test test/e2e/login.test.ts --project Chromium
# With inspector
PWDEBUG=1 npx playwright test test/e2e/login.test.ts
```

### Linting & Formatting

- `npm run lint:ts` — ESLint on all tracked TypeScript/JavaScript files (excluding `lib/vscode`)
- `npm run lint:scripts` — Shell script linting
- `npm run fmt` — Run Prettier + doctoc

### Installing Extensions (from CLI)

```bash
code-server --install-extension <publisher>.<name>
code-server --list-extensions
```

## Architecture

### Source Layout

```
src/
  node/          # Server-side code (Express app, CLI parsing, routes, proxies)
    entry.ts     # Main entrypoint — parses args, decides parent/child, starts server
    main.ts      # runCodeServer() — the core server startup
    app.ts       # createApp() — Express + HTTP server + WebSocket setup
    cli.ts       # CLI argument parsing, config file handling, defaults
    http.ts      # Auth middleware, cookie handling, redirects, origin checking
    wsRouter.ts  # WebSocket routing (wraps Express for ws upgrade handling)
    proxy.ts     # http-proxy instance for port forwarding
    socket.ts    # TLS socket proxy provider
    vscodeSocket.ts  # Editor session manager (IPC between code-server instances)
    wrapper.ts   # Parent/child process model with IPC handshake and hotswap (SIGUSR1/SIGUSR2)
    routes/      # Express route handlers
      index.ts     # Route registration — mounts all sub-routers
      vscode.ts    # VS Code server loading, delegate all requests to VS Code's server API
      login.ts / logout.ts  # Authentication pages and logic
      domainProxy.ts  # Domain-based port proxying (e.g., code-8080.example.com)
      pathProxy.ts    # Path-based port proxying (e.g., /proxy/8080/)
      health.ts / update.ts / errors.ts
    util.ts       # Misc utilities (password hashing, cert generation, etc.)
    i18n/         # Internationalization support
  common/         # Shared between node and browser
    http.ts       # HttpCode enum, HttpError class, cookie session helpers
    util.ts       # General utilities (pluralize, UUID, normalize, logError)
    emitter.ts    # Event emitter / Disposable pattern
  browser/        # Client-side code served to the browser
    serviceWorker.ts  # PWA service worker
```

### Key Architectural Patterns

**Parent/Child Process Model** (`wrapper.ts`):

code-server runs as a parent process that forks itself as a child. The child runs the actual server. This enables:
- **Hotswap (zero-downtime reload)**: Send `SIGUSR1` or `SIGUSR2` to the parent to gracefully restart the child without dropping connections. Also used for self-updates.
- **Process lifecycle**: The child monitors the parent PID and exits if the parent dies. The parent monitors the child and exits if the child exits unexpectedly.
- **IPC handshake**: The child receives CLI args from the parent via IPC, avoiding re-parsing and credential leakage.

**VS Code Integration** (`routes/vscode.ts`):

code-server dynamically loads `lib/vscode/out/server-main.js` as an ESM module (via `eval`-`import`). It calls `createServer()` and delegates all HTTP and WebSocket requests to VS Code's server API. The VS Code module is lazily loaded on the first request.

**Patching** (`patches/`):

VS Code modifications are applied as quilt patches during `postinstall`. Each `.diff` file in `patches/` modifies the VS Code submodule to integrate with code-server (e.g., `integration.diff`, `marketplace.diff`, `telemetry.diff`, `logout.diff`). The patch series is managed in `patches/series`.

**Port Proxy System**:

- **Domain proxy**: `code-8080.example.com` proxies to `localhost:8080` (configured via `--proxy-domain`)
- **Path proxy**: `/proxy/8080/` proxies to `localhost:8080`
- **Absolute path proxy**: `/absproxy/8080/` proxies with the path preserved (app must be aware of its base path)
- The proxy strips code-server's auth cookie before forwarding to prevent leaking credentials.

**Authentication**:

Password-based auth using argon2 hashing. Auth is checked via middleware (`ensureAuthenticated`, `ensureOrigin`). Supports `--skip-auth-preflight` for CORS preflight requests.

### Configuration

Configuration is read from a YAML file (default `~/.config/code-server/config.yaml`). CLI args override config file values. Sensitive values (`--password`, `--hashed-password`, `--github-auth`) can only be set via config file or environment variables (`$PASSWORD`, `$HASHED_PASSWORD`, `$GITHUB_TOKEN`).

### Test Architecture

- **Unit tests**: Jest, run against compiled TypeScript in `out/`. Uses `ts-jest` for transformation. Config in `package.json` (jest section).
- **E2E tests**: Playwright with Chromium. Tests spawn a real code-server instance and interact via browser. Located in `test/e2e/`.
- **Integration tests**: Located in `test/integration/` (extension installation, help output).

### CI/Build Scripts (`ci/`)

- `ci/build/` — Build scripts (code-server, VS Code, release packages, platform packaging)
- `ci/dev/` — Development helpers (test runners, linting, watch script, icons generation)
- `ci/steps/` — Release/publish steps
- `ci/release-image/` — Docker image build
- `ci/helm-chart/` — Helm chart for Kubernetes deployment
