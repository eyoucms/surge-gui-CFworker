# Surge GUI · Cloudflare Worker 部署手册

把 `worker/` 目录下的 **3 个文件** 部署到 Cloudflare Workers，就能得到一个公网可用的 Surge 发布工具。

```
worker/
├── worker.js       ← Worker 主程序（39KB，单文件）
├── wrangler.toml   ← 部署配置（name / main / compatibility_date）
└── package.json    ← npm 依赖声明（wrangler CLI）
```

**Worker 是无状态的**——文件全部在浏览器内存里处理（JSZip 解压 → tar.gz 压缩 → 上传），Worker 只代理 Surge API + 注入 Secret。**不需要 KV、D1、R2、队列、防火墙规则**等任何额外绑定。

---

## ⚠️ 安全红线（必读）

1. **worker.js 里绝对不能出现 token / 口令明文**。我已经检查过，代码里零明文。
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
git commit -m "init: surge-gui worker"
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

## 常见问题

### Q: 访问 .workers.dev 直接白屏 / 500？
打开浏览器控制台（F12），看 Network 面板：
- `/api/health` 返回 500 → **Secrets 没配**（Worker 代码里 `env.SURGE_TOKEN` 是 undefined）。去 Settings → Variables 里加。
- `/api/login` 返回 401 → 口令错了。

### Q: 发布报 "401 Unauthorized"？
Token 失效了。命令行重新 `npx --yes surge token` 拿新的 → Cloudflare Dashboard → Workers → Settings → Variables → 修改 SURGE_TOKEN → Save and Deploy。

### Q: 发布报 "429 Too Many Requests"？
Surge 限流了。免费账号每 15 分钟 60 次，等一会儿再试。或者换个 Surge 账号。

### Q: 发布报 "403 Unable to publish. Application too large"？
Surge 限制 10,100 个文件 / 450 MB。检查一下是不是误打包了 node_modules 或大型视频。

### Q: 免费版用不了自定义域名 HTTPS？
对。免费版自定义域名只能 HTTP，自签证书 Chrome 会警告。两个解法：
- 付费 Surge Plus（$13/月起）
- 用 Cloudflare 做 **代理**：把域名 NS 指向 Cloudflare → Cloudflare 自动签 Let's Encrypt 证书 → Cloudflare 代理流量到 Surge（免费）。这样你既有 HTTPS 又不用付费 Surge。

### Q: Workers Builds 构建报错 `No module named wrangler`？
检查 package.json 是否正确复制了。Build command 是 `npx wrangler deploy`——Cloudflare 会自动 `npm ci` 装依赖。

### Q: 想改 Worker 名字？
wrangler.toml 里 `name = "surge-gui"` 改成你想要的，然后 `wrangler deploy` 或推 GitHub 仓库。名字决定了 `.workers.dev` 子域名。

---

## 架构说明（开发者视角）

```
浏览器 ──────────── Cloudflare Worker ──────────── Surge API
  │                      │                             │
  │  JSZip 解压           │  HTTP Basic auth            │ PUT /:domain
  │  Map 文件内存         │ Basic(username: "token",    │ tar.gz body
  │  tar.gz gzip 构建     │          password: token)   │ NDJSON 流返回
  │  POST tar.gz          │ ← Secret 注入              │
  │                       │                             │
  │  口令登录             │ Cookie 会话（FNV-1a 签名）  │
  │  无 token 在前端暴露  │                             │
  └───────────────────────┴─────────────────────────────┘
```

Worker **不存储任何文件**——无状态、可随时重启、可多实例边缘节点同时服务。
