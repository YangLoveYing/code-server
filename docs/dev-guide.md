# code-server 轻量开发指南

针对低内存机器（< 8GB）的 code-server 日常开发方案。

## 背景

`npm run watch`（完整版）会同时启动 7 个编译进程（VS Code 客户端、扩展、Copilot、Web 服务端等），峰值内存 8-12GB，低配置机器会频繁 swap 导致卡顿。

新增的 `npm run dev`（轻量版）只编译 code-server 自身代码，内存约 500MB，适合日常开发 `src/` 下的路由、页面等改动。

## 一、首次搭建（新环境需要）

```bash
# 1. 安装依赖（触发 postinstall：应用 patch + 装依赖）
npm install

# 2. 构建 VS Code 产物（一次性，约 10 分钟，峰值内存 8-12GB）
npm run build:vscode

# 3. 建立软链（必需：code-server 硬编码从 lib/vscode/out/server-main.js 加载 VS Code，
#    软链把该路径桥接到构建产物；生产打包时也是把整个 vscode-reh-web-linux-x64 复制成 lib/vscode）
rm -rf lib/vscode/out && ln -s ../vscode-reh-web-linux-x64/out lib/vscode/out
```

## 二、日常开发（每次使用）

```bash
npm run dev
```

行为：

- `tsc --watch` 监听 `src/` 下 `.ts` 改动 → 编译到 `out/`
- 编译完成自动启动/重启 web 服务器（默认 http://localhost:8080）
- 改代码 → 保存 → 刷新浏览器即可看到效果
- 内存占用约 500MB，1 个 CPU 核心

### 常用参数

`--` 后面的参数透传给服务器：

```bash
# 无认证，指定端口
npm run dev -- --auth none --bind-addr 0.0.0.0:8090
```

或一劳永逸：改 `~/.config/code-server/config.yaml` 里的 `auth: none`。

## 三、注意事项

1. **不要混用 `npm run watch`（完整版）**：它的 VS Code 编译会把 `lib/vscode/out` 软链替换成开发文件目录，之后 `npm run dev` 会报 `Cannot find module server-main.js`。如果发生了，重跑上面第 3 步恢复软链。
2. **改动 VS Code 源码/patch 时**：需要重新 `npm run build:vscode`（开发 code-server 自身代码则不需要）。
3. **`product.original.json`**：每次 `build:vscode` 后会在 `lib/vscode/` 下残留此文件，记得删除，别提交。

## 四、本次改动清单

| 文件 | 改动 |
|------|------|
| `ci/dev/watch-light.ts` | 新增：轻量 watch 脚本 |
| `package.json` | 新增 `dev` 脚本（+1 行） |
| `lib/vscode/out` | 软链指向 `../vscode-reh-web-linux-x64/out` |

### 完整版 vs 轻量版对比

| 命令 | 进程数 | 内存 | 适用场景 |
|------|--------|------|----------|
| `npm run dev` | 2 | ~500MB | 日常开发 code-server 自身代码 |
| `npm run watch` | 7 | 8-12GB | 修改 VS Code 源码 / patch |
