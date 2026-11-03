# Surge GUI · Cloudflare Worker 部署手册

> **当前版本：v2.0.0（2026-11-03 修复）**
> 
> v1 → v2 修复了 **全量按钮 ReferenceError**（teardownSite 的反引号双重转义导致整个 `<script>` 块 SyntaxError）、移除所有内联事件改 addEventListener、加 window.onerror 兜底、加 CSP 响应头、加 CompressionStream 降级提示。

把 `worker/` 目录下的 **3 个文件** 部署到 Cloudflare Workers，就能得到一个公网可用的 Surge 发布工具。

```
worker/
├── worker.js       ← Worker 主程序（53KB，单文件，ESM）
├── wrangler.toml   ← 部署配置（name / main / compatibility_date）
└── package.json    ← npm 依赖声明（wrangler CLI）
```

**Worker 是无状态的**——文件全部在浏览器内存里处理（JSZip 解压 → tar.gz 压缩 → 上传），Worker 只代理 Surge API + 注入 Secret。**不需要 KV、D1、R2、队列、防火墙规则**等任何额外绑定。

---

## ⚠️ 安全红线（必读）

1. **worker.js 里绝对不能出现 token / 口令明文**。已检查，代码里零明文。
2. **Secrets 只在 Cloudflare 面板配置**。不要填到 wrangler.toml 或任何会进 Git 的文件里。
3. 仓库公开也没关系——只要 Secrets 没泄露，代码里不包含凭据，就安全。
4. 但**泄露 Secrets 等于交出你的 Surge 账号**，别人可以发布/下线你所有域名。

---

## 路径 A：Dashboard 直接粘贴（最快，5 分钟）

**适合场景**：你不想管 Git、不想装 wrangler CLI、只想跑起来。

1. 注册 Cloudflare 免费账号 → https://dash.cloudflare.com
2. 进入 **Workers & Pages** → **Create application**
3. 选 **Workers** → **Create Worker**
4. **Name** 填 `surge-gui`（或自己喜欢的，之后会生成 `xxx.workers.dev` 子域名）→ **Deploy**
5. 部署完进入你刚建的 Worker → 左侧编辑器打开 `src/index.js`
6. **全选删除默认代码** → 粘贴 [worker.js 全文](worker.js) → 右上角 **Save and Deploy**
7. **设置 Secrets**：左侧 **Settings** → **Variables and Secrets** → **Secrets** → **Add**
   | Secret 名 | 值 | 必需 |
   |-----------|---|------|
   | `SURGE_TOKEN` | 命令行执行 `npx surge token` 复制那一串 | ✅ 必需 |
   | `PASSPHRASE` | 自己设一个访问口令（至少 8 位） | ✅ 必需（防 URL 泄露） |
   | `SESSION_SECRET` | 随便一串 32+ 字符随机（签 cookie 用） | ⭕ 推荐 |
8. 回到 **Workers & Pages** 首页，点你的 Worker 名字 → URL 是 `name.your-account.workers.dev`
9. 打开那个 URL → 输入你设的 PASSPHRASE → 看到主界面 → 能用了

> **Surge Token 怎么拿？** 在本地命令行（Windows 开始菜单搜 cmd/PowerShell）执行：
> ```
> npx --yes surge token
> ```
> 输出里那一串 `tok-...` 开头的就是。如果还没注册过 Surge，第一次会提示你设邮箱密码——Surge 免费。

---

## 路径 B：GitHub + Workers Builds（推荐，可版本化）

**适合场景**：想把代码放仓库、以后想改点东西就自动重新部署。

### 1. GitHub 仓库结构

在 GitHub 新建一个仓库（比如 `surge-gui-worker`），把这 **3 个文件放在仓库根目录**：

```
surge-gui-worker/
├── worker.js        ← 复制自本项目的 worker/worker.js
├── wrangler.toml    ← 复制自本项目的 worker/wrangler.toml
└── package.json     ← 复制自本项目的 worker/package.json
```

**注意**：这 3 个文件**必须在仓库根目录**，不要放到 `worker/` 子目录下。Workers Builds 只在仓库根目录找 wrangler.toml。

提交推送：
```bash
git add worker.js wrangler.toml package.json
git commit -m "init: surge-gui worker v2"
git push origin main
```

### 2. Cloudflare 连接 GitHub

1. dash.cloudflare.com → **Workers & Pages** → **Create application**
2. 选 **Workers** → **Connect to Git**
3. **Service** 选 GitHub → 授权 Cloudflare 访问
4. 选你的仓库 → **Set up**
5. 配置构建（Cloudflare 会自动识别 wrangler.toml，以下为确认）：
   | 字段 | 值 |
   |------|---|
   | Framework preset | *(不选)* |
   | Build command | `npx wrangler deploy` |
   | Build output directory | *(空，Worker 不需要)* |
   | Root directory | **/** |
6. **Environment variables (Secrets)** → 分别添加 3 个：
   | Name | Value |
   |------|-------|
   | `SURGE_TOKEN` | 你的 Surge token |
   | `PASSPHRASE` | 你设的口令 |
   | `SESSION_SECRET` | 随机串（可选） |
   👉 **注意**：在 Cloudflare Workers Builds 的这个 Secrets 界面里，变量名不要加 `wrangler_` 前缀，直接填 `SURGE_TOKEN`。Cloudflare 会自动把它们注入为 Worker 的 `env.SURGE_TOKEN`。
7. **Deploy** → 等几秒 → 成功 → URL 就是 `name.workers.dev`

### 3. 以后更新

本地改代码 → `git push` → Cloudflare 自动触发构建部署。

---

## 日常使用

1. 浏览器打开 `https://你的-worker-name.workers.dev/`
2. 输入 PASSPHRASE 登录
3. 左侧选文件夹或 zip → 中间编辑文件 → 顶栏 **🚀 发布** → 输入域名（如 `my-site.surge.sh`）→ 开始
4. 实时日志会显示上传进度 → CDN 分布 → 证书签发 → 成功链接
5. **🌐 站点** 看你账号下所有已发布域名，可一键下线

### 免费版限制

| 项 | 限制 |
|----|------|
| Workers 每天请求 | 10 万次 |
| 单次请求体（tar.gz） | **100 MB** |
| Workers 单次 CPU 时间 | 50ms（免费）/ 30s（付费） |
| Surge 免费域名 | 只能 `xxx.surge.sh` 子域名 |
| Surge 自定义域名 HTTPS | 需 Plus 付费（$13/月起） |
| Surge 发布限流 | 每 15 分钟 30 次/域名，60 次/账号 |

### 中国大陆访问说明

- **Surge 服务器**在美西（45.55.110.124），大陆访问会慢（400ms+ RTT）
- **但 Cloudflare Workers 有北京/上海/广州边缘节点**——Worker 从 Cloudflare 边缘代理 API，大陆用户用 Worker 前端的访问会比直接用 Surge 快不少
- **但最终站点还是托管在 Surge 美西服务器**——用户访问 `your-site.surge.sh` 时的加载速度不受 Worker 影响，只受 Surge 影响

---

## 常见报错 / 故障排查（按出现概率排序）

### ❌ 页面白屏 / 所有按钮点了都报错 "XXX is not defined"

**历史上发生过一次**（v1 teardownSite 反引号双重转义 bug）。现在 v2 已经修干净，HTML 里 0 个内联事件，所有事件用 DOMContentLoaded + addEventListener 绑定。

如果你还是遇到，打开浏览器控制台（F12）看第一条错误：
- 如果是 **SyntaxError**（例如 `Invalid or unexpected token`）：Worker 代码粘贴时丢了字符。重新完整复制 worker.js 粘贴。
- 如果是 **ReferenceError** 函数未定义：说明 Worker 返回的 HTML 里 `<script>` 有语法错误导致整个 script 不执行。检查 Cloudflare Dashboard 上 Worker 的实时日志。
- 页面顶部会自动出现 **红色全局错误条**（v2 新增），直接把错误信息复制发给开发者。

### ⚠️ 控制台报 `ERR_BLOCKED_BY_CLIENT` 指向 `static.cloudflareinsights.com/beacon.min.js`

这不是 bug——是 Cloudflare **自动注入的 Web Analytics 脚本** 被你的浏览器广告拦截插件（uBlock Origin / AdGuard / 360 浏览器广告拦截）拦截了。

**这不影响 Surge GUI 正常使用**——那个脚本只是 Cloudflare 的访问统计，不阻塞我们的任何功能。如果想让控制台干净点：
1. Cloudflare Dashboard → **Analytics & Logs** → **Web Analytics** → 找到你那个 Worker 的 analytics 源 → 禁用
2. 或者在广告拦截插件里对 `*.workers.dev` 整个域名放行

### ❌ 登录后点按钮报 fetch 错误 / 401 / 500

打开 F12 → Network 面板，看具体是哪个 API 报错：

| 报错 | 原因 | 解决 |
|------|------|------|
| `/api/config` 401 | Cookie 会话失效 / 被清了 | 回到登录页重新输口令 |
| `/api/surge/account` 500 + "SURGE_TOKEN Secret" | Worker 没配置 SURGE_TOKEN | Cloudflare Dashboard → Workers → Settings → Variables → 加 Secret |
| `/api/surge/account` 401 | Token 过期 / 被撤销 | `npx surge token` 拿新的 → 修改 Secret |
| `/api/surge/publish` 401 | Token 失效 | 同上 |
| `/api/surge/publish` 403 | Surge 不让发（限流 / 域名冲突 / 配额） | 看发布日志里 Surge 返回的具体 NDJSON 错误 |
| `/api/surge/publish` 429 | Surge 限流 | 每 15 分钟 60 次，等会儿再试 |
| `CompressionStream is not defined` | 浏览器太老 | 需要 Chrome 80+ / Edge 80+ / Safari 16.4+ / Firefox 113+ |

### ❌ 发布报 "Application too large"

Surge 限制 **10,100 个文件 / 450 MB**。检查是不是误打包了 node_modules 或大型视频。v2 的 tar.gz 是浏览器端构建，Worker 不做二次处理。

### ❌ Workers Builds 构建报错 `No module named wrangler` / `ESBuild not found`

package.json 必须和 worker.js **在同一目录**（仓库根目录）。Cloudflare 只在根目录跑 `npm ci`。

### ❌ 免费版自定义域名 HTTPS 不行

对。免费版自定义域名只能 HTTP。两个解法：
- 付费 Surge Plus（$13/月起）
- 用 Cloudflare 做 **代理**：把域名 NS 指向 Cloudflare → Cloudflare 自动签 Let's Encrypt 证书 → Cloudflare 代理流量到 Surge（免费）

---

## 架构说明（v2）

```
浏览器 ───────────── Cloudflare Worker ────────────── Surge API
  │                        │                               │
  │  JSZip 解压             │  HTTP Basic auth              │ PUT /:domain
  │  Map 文件内存           │ Basic(username: "token",      │ tar.gz body
  │  CompressionStream gzip │          password: token)     │ NDJSON 流返回
  │  tar.gz 构建            │ ← SURGE_TOKEN Secret 注入     │
  │  POST tar.gz            │                               │
  │  全局错误条 兜底         │ Cookie 会话（FNV-1a 签名）   │
  │  0 内联事件 (addEventListener 统一绑定)                 │
  │  window.onerror 捕获    │ CSP 响应头                    │
  └────────────────────────┴───────────────────────────────┘
```

**Worker 不存储任何文件**——无状态、可随时重启、可多实例边缘节点同时服务。

### 关键路由

| 路由 | 鉴权 | 说明 |
|------|------|------|
| `GET /health` | 否 | 健康检查，返回 version / tokenConfigured / passphraseConfigured |
| `POST /api/login` | 否 | 提交 PASSPHRASE，设置 Cookie |
| `POST /api/logout` | 否 | 清 Cookie |
| `GET /api/config` | 否 | 只返回 boolean（loggedIn / tokenConfigured），**不回显任何 Secret** |
| `GET /api/surge/account` | 是 | 代理 Surge /account（检测 token 有效性） |
| `GET /api/surge/list` | 是 | 代理 Surge /list |
| `POST /api/surge/publish?domain=xxx` | 是 | 代理 PUT /:domain，流式透传 NDJSON |
| `POST /api/surge/teardown?domain=xxx` | 是 | 代理 DELETE /:domain |

### 安全设计

- **Secret 缺失** → 前端不会拿到空 token，但 Worker 在 `/api/surge/*` 路由上会返回明确的 500 + 消息提示
- **Token 永不回显** → `/api/config` 只返回 boolean
- **口令 Cookie 签名** → FNV-1a 哈希 + timestamp + salt，7 天过期
- **CSP** → Worker 返回页面时带上 `script-src 'unsafe-inline' 'self' cdn.tailwindcss.com cdn.jsdelivr.net`，只允许这三个来源的脚本
- **Cookie HttpOnly** → 前端 JS 读不到 `surge_gui_session`，防 XSS 窃取
