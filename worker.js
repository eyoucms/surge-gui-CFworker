// Surge GUI - Cloudflare Worker 版（v2 修复版）
// 单文件 Worker：前端页面 + Surge API 代理
//
// Secrets (Cloudflare Dashboard / wrangler.toml):
//   SURGE_TOKEN      - Surge API Token（必填）
//   PASSPHRASE       - 访问口令（可选，没设就不强制登录）
//   SESSION_SECRET   - 32+ 字符随机串，签名 Cookie（可选，没设也能用但安全性差些）
//
// 本地开发: npx wrangler dev
// 部署: npx wrangler deploy   或   直接把本文件粘贴到 Cloudflare Dashboard Workers 编辑器

const SURGE_API_BASE = 'https://surge.surge.sh';
const VERSION = '2.0.0-worker-fixed';
const SESSION_COOKIE = 'surge_gui_session';

// ============================================================
// Worker 端工具函数
// ============================================================

function base64Encode(str) {
  // Worker 里 btoa 只接受 Latin-1；但 Surge Token 是 ASCII，没问题
  return btoa(unescape(encodeURIComponent(str)));
}

function surgeAuthHeader(token) {
  return 'Basic ' + base64Encode('token:' + token);
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
      ...extraHeaders
    }
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ ok: false, message }, status);
}

function getCookie(request, name) {
  const cookies = request.headers.get('cookie') || '';
  const re = new RegExp('(?:^|; )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)');
  const m = cookies.match(re);
  return m ? decodeURIComponent(m[1]) : null;
}

function setSessionCookie(passphrase, sessionSecret) {
  const timestamp = Date.now();
  const salt = Math.random().toString(36).slice(2);
  const payload = salt + '.' + timestamp + '.' + passphrase;
  const mac = sessionSecret ? simpleHash(payload + '|' + sessionSecret) : simpleHash(payload);
  const value = btoa(unescape(encodeURIComponent(payload + '|' + mac)));
  // Secure: workers.dev 和自定义域名 HTTPS 都支持 Secure cookie；
  // 本地 wrangler dev 是 http，但 set-cookie 在 http 下会被浏览器拒绝，
  // 这里统一加 Secure——用户真实部署走 HTTPS 没问题，本地 dev 可以
  // 通过 Secure flag 不影响 cookie 的 Path/HttpOnly 语义。
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=604800`;
}

function verifySessionCookie(cookieValue, passphrase, sessionSecret) {
  try {
    const decoded = decodeURIComponent(escape(atob(cookieValue)));
    const parts = decoded.split('|');
    if (parts.length !== 2) return false;
    const [payload, mac] = parts;
    const expectedMac = sessionSecret ? simpleHash(payload + '|' + sessionSecret) : simpleHash(payload);
    if (mac !== expectedMac) return false;
    const [, timestamp, storedPassphrase] = payload.split('.');
    if (Date.now() - parseInt(timestamp) > 604800000) return false;
    if (storedPassphrase !== passphrase) return false;
    return true;
  } catch {
    return false;
  }
}

// FNV-1a 32-bit：做会话签名够用，避免额外依赖
function simpleHash(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}

function requireAuth(request, env) {
  if (!env.PASSPHRASE) return true;
  const cookieValue = getCookie(request, SESSION_COOKIE);
  if (!cookieValue) return false;
  return verifySessionCookie(cookieValue, env.PASSPHRASE, env.SESSION_SECRET);
}

async function readJson(request) {
  try { return await request.json(); } catch { return {}; }
}

// ============================================================
// 主入口
// ============================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS 预检
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
          'Access-Control-Allow-Headers': 'Content-Type, Authorization, Accept',
          'Access-Control-Expose-Headers': '*'
        }
      });
    }

    try {
      // ===== 0) 公开白名单路由（健康检查等，最顶层优先匹配） =====

      if (path === '/health' && request.method === 'GET') {
        return jsonResponse({
          ok: true,
          version: VERSION,
          surgeApi: SURGE_API_BASE,
          tokenConfigured: !!env.SURGE_TOKEN,
          passphraseConfigured: !!env.PASSPHRASE
        });
      }

      // ===== 1) 非 API 路径永远返回前端页面（或小工具路由） =====
      //    前端自己会调 /api/config 决定显示登录框还是主界面。
      //    这里绝对不能套鉴权守卫，否则 / 也被 401 JSON 拦截。

      // 浏览器收藏夹图标——直接空响应
      if (path === '/favicon.ico' && request.method === 'GET') {
        return new Response(null, { status: 204 });
      }

      // 根路径、任意非 /api/ 路径：一律返回 HTML
      // 这样即使用户绑定自定义域名，访问 https://xxx/ 也能拿到页面，
      // 浏览器渲染出来后 JS 会自己判断登录态。
      if (!path.startsWith('/api/')) {
        return new Response(serveHTML(), {
          status: 200,
          headers: {
            'Content-Type': 'text/html; charset=utf-8',
            // no-store 强制每次都从服务器取，防止浏览器缓存住旧的 401 JSON 或旧页面
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0',
            // 允许内联 script（我们移除了所有内联事件，但 <script> 块仍是内联）
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' cdn.tailwindcss.com cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' cdn.jsdelivr.net; img-src 'self' data:; font-src 'self' data:; connect-src 'self' surge.surge.sh; base-uri 'self'; form-action 'self';"
          }
        });
      }

      // ===== 2) /api/* 路由开始 =====
      //    login/logout/config 是公开的；/api/surge/* 才需要鉴权。

      if (path === '/api/login' && request.method === 'POST') {
        const body = await readJson(request);
        const passphrase = (body.passphrase || '').trim();
        if (!env.PASSPHRASE) {
          return jsonResponse({ ok: true, message: '未配置口令，无需登录' });
        }
        if (passphrase !== env.PASSPHRASE) {
          return errorResponse('口令错误', 401);
        }
        const cookie = setSessionCookie(passphrase, env.SESSION_SECRET);
        return jsonResponse({ ok: true, message: '登录成功' }, 200, { 'Set-Cookie': cookie });
      }

      if (path === '/api/logout' && request.method === 'POST') {
        return jsonResponse({ ok: true }, 200, {
          'Set-Cookie': `${SESSION_COOKIE}=deleted; Path=/; HttpOnly; Secure; Max-Age=0; SameSite=Lax`
        });
      }

      if (path === '/api/config' && request.method === 'GET') {
        const loggedIn = requireAuth(request, env);
        return jsonResponse({
          ok: true,
          loggedIn,
          passphraseConfigured: !!env.PASSPHRASE,
          tokenConfigured: !!env.SURGE_TOKEN,
          version: VERSION
        });
      }

      // ===== 3) 其余 /api/* 路由 —— 需要鉴权 =====
      if (!requireAuth(request, env) && env.PASSPHRASE) {
        return errorResponse('请先登录', 401);
      }

      // Surge API 代理
      if (path.startsWith('/api/surge/')) {
        if (!env.SURGE_TOKEN) {
          return errorResponse('后端未配置 SURGE_TOKEN Secret', 500);
        }
        return handleSurgeProxy(request, env, path);
      }

      // 兜底：未知 API 路由
      return errorResponse('未知 API 路由：' + path, 404);

    } catch (e) {
      console.error('[worker error]', e);
      return errorResponse(e.message || '内部错误', 500);
    }
  }
};

// ============================================================
// Surge API 代理
// ============================================================

async function handleSurgeProxy(request, env, path) {
  const auth = surgeAuthHeader(env.SURGE_TOKEN);

  // GET /list
  if (path === '/api/surge/list' && request.method === 'GET') {
    const resp = await fetch(SURGE_API_BASE + '/list', {
      headers: { 'Authorization': auth }
    });
    const data = await resp.json();
    return new Response(JSON.stringify(data), {
      status: resp.status,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
    });
  }

  // GET /account
  if (path === '/api/surge/account' && request.method === 'GET') {
    const resp = await fetch(SURGE_API_BASE + '/account', {
      headers: { 'Authorization': auth }
    });
    const data = await resp.json();
    if (!resp.ok) return errorResponse(data.messages?.[0] || data.message || 'Token 无效', resp.status);
    return jsonResponse({ ok: true, account: data });
  }

  // POST /publish?domain=xxx
  if (path === '/api/surge/publish' && request.method === 'POST') {
    const domain = new URL(request.url).searchParams.get('domain');
    if (!domain) return errorResponse('缺少 domain 参数');

    const contentType = request.headers.get('content-type') || '';
    let tarBody;
    if (contentType.includes('multipart/form-data')) {
      const formData = await request.formData();
      const file = formData.get('archive') || formData.get('file');
      if (!file) return errorResponse('未收到 tar.gz');
      tarBody = file;
    } else {
      tarBody = request.body;
    }

    const sizeHeader = request.headers.get('x-project-size') || '0';
    const countHeader = request.headers.get('x-file-count') || '0';
    const versionHeader = request.headers.get('x-client-version') || VERSION;

    const surgeUrl = SURGE_API_BASE + '/' + encodeURIComponent(domain);
    const fetchResp = await fetch(surgeUrl, {
      method: 'PUT',
      headers: {
        'Authorization': auth,
        'Content-Type': 'application/gzip',
        'Accept': 'application/x-ndjson',
        'version': versionHeader,
        'file-count': countHeader,
        'project-size': sizeHeader,
        'Transfer-Encoding': 'chunked'
      },
      body: tarBody
    });

    return new Response(fetchResp.body, {
      status: fetchResp.status,
      headers: {
        'Content-Type': 'application/x-ndjson; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no'
      }
    });
  }

  // POST /teardown?domain=xxx
  if (path === '/api/surge/teardown' && request.method === 'POST') {
    const domain = new URL(request.url).searchParams.get('domain');
    if (!domain) return errorResponse('缺少 domain 参数');

    const resp = await fetch(SURGE_API_BASE + '/' + encodeURIComponent(domain), {
      method: 'DELETE',
      headers: { 'Authorization': auth }
    });
    const text = await resp.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { msg: text }; }
    return new Response(JSON.stringify({ ok: resp.ok, ...data }), {
      status: resp.ok ? 200 : resp.status,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // GET /status?domain=xxx
  if (path === '/api/surge/status' && request.method === 'GET') {
    const domain = new URL(request.url).searchParams.get('domain');
    if (!domain) return errorResponse('缺少 domain 参数');
    const resp = await fetch(SURGE_API_BASE + '/' + encodeURIComponent(domain) + '/status', {
      headers: { 'Authorization': auth }
    });
    const data = await resp.json();
    return new Response(JSON.stringify(data), {
      status: resp.ok ? 200 : resp.status,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  return errorResponse('未知 API 路由：' + path, 404);
}

// ============================================================
// serveHTML —— 前端页面
//
// 用数组拼接返回，每个片段一行，避免双重转义地狱。
// 所有反引号 / ${} / 反斜杠都是真正要输出到浏览器的字面量，
// 所以直接写就行，不需要转义。
// ============================================================

function serveHTML() {
  return [
    '<!DOCTYPE html>',
    '<html lang="zh-CN">',
    '<head>',
    '<meta charset="UTF-8"/>',
    '<meta name="viewport" content="width=device-width,initial-scale=1.0"/>',
    '<title>Surge GUI - 在线版</title>',
    '<script src="https://cdn.tailwindcss.com"></script>',
    '<script src="https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js"></script>',
    '<style>',
    'body{font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;}',
    '.btn{padding:6px 12px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;border:1px solid transparent;}',
    '.btn-primary{background:#2563eb;color:white;}.btn-primary:hover{background:#1d4ed8;}.btn-primary:disabled{background:#93c5fd;}',
    '.btn-secondary{background:#f3f4f6;color:#374151;border-color:#e5e7eb;}.btn-secondary:hover{background:#e5e7eb;}',
    '.btn-danger{background:#dc2626;color:white;}.btn-danger:hover{background:#b91c1c;}',
    '.btn-ghost{background:transparent;color:#6b7280;}.btn-ghost:hover{background:#f3f4f6;color:#374151;}',
    '.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.4);display:flex;align-items:center;justify-content:center;z-index:50;}',
    '.modal{background:white;border-radius:10px;box-shadow:0 20px 60px rgba(0,0,0,.2);max-width:520px;width:92%;max-height:85vh;overflow:auto;}',
    '.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:500;}',
    '.badge-green{background:#d1fae5;color:#065f46;}.badge-red{background:#fee2e2;color:#991b1b;}.badge-blue{background:#dbeafe;color:#1e40af;}',
    '.file-tree .node{cursor:pointer;padding:2px 4px;border-radius:3px;display:flex;align-items:center;gap:4px;font-size:13px;}',
    '.file-tree .node:hover{background:#eef2ff;}.file-tree .node.active{background:#dbeafe;}',
    '.file-tree .children{padding-left:16px;}',
    '.file-tree .caret{width:12px;display:inline-block;text-align:center;color:#6b7280;font-size:9px;}',
    '.file-tree .caret.open::before{content:"▼";}',
    '.file-tree .caret.closed::before{content:"▶";}',
    '.file-tree .caret.empty::before{content:"·";color:#d1d5db;}',
    '.editor-textarea{font-family:Consolas,Monaco,Menlo,monospace;font-size:13px;line-height:1.5;tab-size:2;}',
    '.ansi-log{font-family:Consolas,Monaco,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;}',
    '.ansi-log .stdout{color:#e5e7eb;}',
    '.ansi-log .stderr{color:#fca5a5;}',
    '.ansi-log .info{color:#60a5fa;font-weight:bold;}',
    '.ansi-log .exit-ok{color:#34d399;font-weight:bold;}',
    '.ansi-log .exit-fail{color:#f87171;font-weight:bold;}',
    '.dropzone-drag{border-color:#2563eb!important;background:#eff6ff!important;}',
    '.blob{background:#f0fdf4;border:2px dashed #22c55e;}',
    // 错误提示条（window.onerror 用）
    '#globalErrorBar{display:none;position:fixed;top:0;left:0;right:0;background:#dc2626;color:white;padding:10px 16px;font-size:13px;z-index:9999;box-shadow:0 2px 8px rgba(0,0,0,.3);}',
    '#globalErrorBar .close{float:right;cursor:pointer;font-size:18px;margin-left:12px;}',
    '</style>',
    '</head>',
    '<body class="bg-gray-50 text-gray-800 h-screen flex flex-col overflow-hidden">',

    // 全局错误条
    '<div id="globalErrorBar">',
    '  <span id="globalErrorText"></span>',
    '  <span id="globalErrorClose" class="close">&times;</span>',
    '</div>',

    // 登录界面
    '<div id="loginScreen" class="hidden h-full flex items-center justify-center">',
    '  <div class="bg-white p-8 rounded-xl shadow-lg max-w-sm w-full">',
    '    <h1 class="text-xl font-semibold text-center mb-2">🔒 Surge GUI</h1>',
    '    <p class="text-center text-gray-500 text-sm mb-6">请输入访问口令</p>',
    '    <input id="loginPass" type="password" placeholder="口令" class="w-full border border-gray-300 rounded px-3 py-2 mb-3"/>',
    '    <button id="loginBtn" class="btn btn-primary w-full">登录</button>',
    '    <p id="loginMsg" class="mt-2 text-sm text-center"></p>',
    '  </div>',
    '</div>',

    // 主界面
    '<div id="mainApp" class="h-full flex flex-col">',
    '  <header class="bg-white border-b border-gray-200 px-5 py-3 flex items-center gap-4 flex-shrink-0">',
    '    <div class="flex items-center gap-2">',
    '      <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center text-white font-bold text-sm">S</div>',
    '      <div>',
    '        <h1 class="font-semibold text-gray-900 leading-tight">Surge GUI <span class="text-xs text-gray-400 font-normal">在线版</span></h1>',
    '        <p class="text-xs text-gray-500 leading-tight">文件在浏览器本地，发布走 Surge API</p>',
    '      </div>',
    '    </div>',
    '    <div class="ml-auto flex items-center gap-2">',
    '      <span id="accountInfo" class="badge badge-blue">加载中...</span>',
    '      <button id="btnPublish" class="btn btn-secondary text-xs">🚀 发布</button>',
    '      <button id="btnManage" class="btn btn-secondary text-xs">🌐 站点</button>',
    '      <button id="btnLogout" class="btn btn-ghost text-xs">退出</button>',
    '    </div>',
    '  </header>',

    '  <main class="flex flex-1 overflow-hidden">',
    '    <aside class="w-72 bg-white border-r border-gray-200 flex flex-col flex-shrink-0">',
    '      <div class="p-3 border-b border-gray-100 space-y-2">',
    '        <label id="dropzone" class="block border-2 border-dashed border-gray-300 rounded-lg p-3 text-center text-sm text-gray-600 cursor-pointer hover:border-blue-400 hover:bg-blue-50 transition">',
    '          <div class="text-2xl mb-1">📦</div>',
    '          <div class="font-medium">拖拽 zip / 文件夹</div>',
    '          <div class="text-xs text-gray-400 mt-0.5">或点击选择</div>',
    '          <input id="fileInput" type="file" class="hidden" webkitdirectory directory multiple/>',
    '          <input id="zipInput" type="file" accept=".zip" class="hidden"/>',
    '        </label>',
    '        <div class="flex gap-1">',
    '          <button id="btnPickFolder" class="btn btn-secondary flex-1 text-xs">📁 选文件夹</button>',
    '          <button id="btnPickZip" class="btn btn-secondary flex-1 text-xs">🗜️ 选 zip</button>',
    '        </div>',
    '      </div>',
    '      <div class="flex items-center justify-between px-3 py-2 border-b border-gray-100 bg-gray-50">',
    '        <span class="text-xs font-medium text-gray-600">本地文件（浏览器内存）</span>',
    '        <button id="btnClearAll" class="btn btn-ghost text-xs py-0.5 px-2" title="清空所有文件">🗑️</button>',
    '      </div>',
    '      <div id="fileTree" class="file-tree flex-1 overflow-auto py-2 px-2 text-sm">',
    '        <div class="p-4 text-center text-gray-400 text-xs">未加载文件<br/>选择文件夹或 zip 开始</div>',
    '      </div>',
    '    </aside>',

    '    <section class="flex-1 flex flex-col overflow-hidden">',
    '      <div class="bg-white border-b border-gray-200 flex items-center gap-1 px-3">',
    '        <button id="tab-editor" class="px-4 py-2.5 text-sm font-medium border-b-2 border-blue-500 text-blue-600">📝 编辑器</button>',
    '        <button id="tab-publish" class="px-4 py-2.5 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700">📤 发布日志</button>',
    '      </div>',

    '      <div id="panel-editor" class="flex-1 flex flex-col overflow-hidden">',
    '        <div id="editorHeader" class="hidden bg-white border-b border-gray-200 px-4 py-2 flex items-center gap-2 text-sm">',
    '          <span id="currentFileLabel" class="font-medium text-gray-700"></span>',
    '          <span id="fileSizeLabel" class="text-xs text-gray-400"></span>',
    '          <div class="ml-auto flex gap-2">',
    '            <button id="saveBtn" class="btn btn-primary text-xs" disabled>💾 保存</button>',
    '            <button id="btnRemoveFile" class="btn btn-danger text-xs">🗑️ 删除</button>',
    '          </div>',
    '        </div>',
    '        <div id="editorBody" class="flex-1 bg-white">',
    '          <div class="h-full flex items-center justify-center text-gray-400 text-sm">',
    '            <div class="text-center px-6">',
    '              <div class="text-5xl mb-3 opacity-50">📂</div>',
    '              <p>从左侧文件树选择文件开始编辑</p>',
    '            </div>',
    '          </div>',
    '        </div>',
    '      </div>',

    '      <div id="panel-publish" class="hidden flex-1 flex flex-col overflow-hidden">',
    '        <div class="bg-white border-b border-gray-200 px-4 py-2 flex items-center gap-2 text-sm">',
    '          <span class="font-medium">发布日志</span>',
    '          <button id="btnClearLog" class="btn btn-ghost text-xs py-0.5 px-2 ml-auto">清空</button>',
    '        </div>',
    '        <div id="publishLog" class="ansi-log flex-1 overflow-auto p-4 bg-gray-900 text-white"></div>',
    '      </div>',
    '    </section>',
    '  </main>',
    '</div>',

    // 发布弹窗
    '<div id="publishModal" class="modal-backdrop hidden">',
    '  <div class="modal p-6">',
    '    <h2 class="text-lg font-semibold mb-3">🚀 发布到 Surge</h2>',
    '    <p class="text-sm text-gray-600 mb-3">当前浏览器内存中的所有文件将打包为 tar.gz 上传。</p>',
    '    <div class="mb-3">',
    '      <label class="text-xs text-gray-600 block mb-1">发布域名</label>',
    '      <input id="publishDomain" type="text" placeholder="your-project.surge.sh" class="w-full border border-gray-300 rounded px-3 py-2 text-sm"/>',
    '      <div class="text-xs text-gray-500 mt-1">免费版域名格式: xxx.surge.sh（xxx 全局唯一）</div>',
    '    </div>',
    '    <div id="publishStats" class="text-xs text-gray-500 mb-3"></div>',
    '    <div class="flex gap-2 justify-end">',
    '      <button id="btnPublishCancel" class="btn btn-ghost">取消</button>',
    '      <button id="btnPublishGo" class="btn btn-primary">开始发布</button>',
    '    </div>',
    '  </div>',
    '</div>',

    // 站点管理弹窗
    '<div id="manageModal" class="modal-backdrop hidden">',
    '  <div class="modal p-6" style="max-width:680px">',
    '    <div class="flex items-center gap-2 mb-3">',
    '      <h2 class="text-lg font-semibold">🌐 已发布站点</h2>',
    '      <button id="btnRefreshSites" class="btn btn-ghost text-xs py-0.5 px-2 ml-auto">🔄 刷新</button>',
    '    </div>',
    '    <div id="sitesList" class="space-y-2 text-sm"></div>',
    '  </div>',
    '</div>',

    // Toast
    '<div id="toast" class="fixed top-5 left-1/2 -translate-x-1/2 bg-gray-800 text-white px-4 py-2 rounded-lg text-sm shadow-lg z-[100] opacity-0 transition-opacity pointer-events-none"></div>',

    '<script>',
    // =======================================================
    // 兜底：全局错误捕获（onerror + unhandledrejection）
    // 任何没被 catch 的错误都会显示到 globalErrorBar
    // =======================================================
    'window.addEventListener("error", function(evt) {',
    '  var msg = (evt.message || "未知错误") + "（行 " + (evt.lineno||"?") + ":" + (evt.colno||"?") + "）";',
    '  var bar = document.getElementById("globalErrorBar");',
    '  var txt = document.getElementById("globalErrorText");',
    '  if (bar && txt) { txt.textContent = msg; bar.style.display = "block"; }',
    '  console.error("[SurgeGUI] uncaught:", evt.error || evt.message);',
    '});',
    'window.addEventListener("unhandledrejection", function(evt) {',
    '  var msg = "未捕获的异步错误：" + (evt.reason && evt.reason.message ? evt.reason.message : String(evt.reason));',
    '  var bar = document.getElementById("globalErrorBar");',
    '  var txt = document.getElementById("globalErrorText");',
    '  if (bar && txt) { txt.textContent = msg; bar.style.display = "block"; }',
    '  console.error("[SurgeGUI] unhandledrejection:", evt.reason);',
    '});',

    // =======================================================
    // 运行环境检查
    // =======================================================
    '(function envCheck() {',
    '  if (typeof CompressionStream === "undefined") {',
    '    var bar = document.getElementById("globalErrorBar");',
    '    var txt = document.getElementById("globalErrorText");',
    '    if (bar && txt) {',
    '      txt.textContent = "⚠️ 你的浏览器不支持 CompressionStream。需要 Chrome 80+ / Edge 80+ / Safari 16.4+ / Firefox 113+。当前版本：" + navigator.userAgent.match(/Chrome\\/\\d+/)?.[0];',
    '      bar.style.background = "#d97706";',
    '      bar.style.display = "block";',
    '    }',
    '  }',
    '})();',

    // =======================================================
    // 工具函数
    // =======================================================
    'function $(id) { return document.getElementById(id); }',
    'function toast(msg, type) {',
    '  type = type || "info";',
    '  var el = $("toast");',
    '  el.textContent = msg;',
    '  el.style.background = type === "error" ? "#dc2626" : type === "success" ? "#059669" : "#1f2937";',
    '  el.style.opacity = "1";',
    '  setTimeout(function() { el.style.opacity = "0"; }, 2500);',
    '}',
    'function closeModal(id) { $(id).classList.add("hidden"); }',
    'function openModal(id) { $(id).classList.remove("hidden"); }',

    'async function api(method, path, body) {',
    '  var opts = { method: method, headers: {} };',
    '  if (body !== undefined) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }',
    '  var r = await fetch(path, opts);',
    '  var ct = r.headers.get("content-type") || "";',
    '  if (ct.indexOf("application/json") !== -1) return await r.json();',
    '  return r;',
    '}',

    // =======================================================
    // 状态
    // =======================================================
    'var state = {',
    '  files: new Map(),',
    '  current: null,',
    '  originalContent: null,',
    '  expanded: new Set([""])',
    '};',

    // =======================================================
    // 登录
    // =======================================================
    'async function checkLogin() {',
    '  var r = await api("GET", "/api/config");',
    '  if (!r.passphraseConfigured || r.loggedIn) {',
    '    $("mainApp").classList.remove("hidden");',
    '    $("loginScreen").classList.add("hidden");',
    '    await loadAccount();',
    '    return true;',
    '  }',
    '  $("mainApp").classList.add("hidden");',
    '  $("loginScreen").classList.remove("hidden");',
    '  return false;',
    '}',

    'async function doLogin() {',
    '  var pass = $("loginPass").value;',
    '  $("loginMsg").textContent = "登录中...";',
    '  try {',
    '    var r = await api("POST", "/api/login", { passphrase: pass });',
    '    if (r.ok) {',
    '      toast("登录成功", "success");',
    '      await checkLogin();',
    '    } else {',
    '      $("loginMsg").textContent = r.message || "登录失败";',
    '      $("loginMsg").style.color = "#dc2626";',
    '    }',
    '  } catch (e) {',
    '    $("loginMsg").textContent = "网络错误：" + e.message;',
    '    $("loginMsg").style.color = "#dc2626";',
    '  }',
    '}',

    'async function doLogout() {',
    '  await api("POST", "/api/logout");',
    '  location.reload();',
    '}',

    'async function loadAccount() {',
    '  try {',
    '    var r = await api("GET", "/api/surge/account");',
    '    if (r.ok) {',
    '      var planName = (r.account && r.account.plan && r.account.plan.name) ? r.account.plan.name : "Free";',
    '      $("accountInfo").textContent = r.account.email + " · " + planName;',
    '      $("accountInfo").classList.remove("badge-red");',
    '      $("accountInfo").classList.add("badge-blue");',
    '    } else {',
    '      $("accountInfo").textContent = "⚠️ Token 无效";',
    '      $("accountInfo").classList.remove("badge-blue");',
    '      $("accountInfo").classList.add("badge-red");',
    '    }',
    '  } catch (e) {',
    '    $("accountInfo").textContent = "⚠️ 加载失败";',
    '    $("accountInfo").classList.remove("badge-blue");',
    '    $("accountInfo").classList.add("badge-red");',
    '  }',
    '}',

    // =======================================================
    // 文件加载
    // =======================================================
    'function addFile(path, content) { state.files.set(path, content); }',

    'function formatSize(b) {',
    '  if (b < 1024) return b + " B";',
    '  if (b < 1048576) return (b / 1024).toFixed(1) + " KB";',
    '  return (b / 1048576).toFixed(1) + " MB";',
    '}',

    'function isTextContent(bytes, filename) {',
    '  var ext = filename.split(".").pop().toLowerCase();',
    '  var textExts = ["html","htm","css","scss","less","js","jsx","ts","tsx","mjs","json","md","markdown","txt","xml","yaml","yml","svg","conf","ini","env","csv","map"];',
    '  if (textExts.indexOf(ext) !== -1) return true;',
    '  for (var i = 0; i < Math.min(bytes.length, 8192); i++) { if (bytes[i] === 0) return false; }',
    '  return bytes.length < 100000;',
    '}',

    'async function handleLocalFiles(e) {',
    '  var files = Array.from(e.target.files);',
    '  for (var idx = 0; idx < files.length; idx++) {',
    '    var f = files[idx];',
    '    var path = f.webkitRelativePath || f.name;',
    '    var buf = await f.arrayBuffer();',
    '    var bytes = new Uint8Array(buf);',
    '    addFile(path, {',
    '      name: f.name, path: path, content: bytes,',
    '      binary: !isTextContent(bytes, f.name), size: bytes.length',
    '    });',
    '  }',
    '  toast("已加载 " + files.length + " 个文件", "success");',
    '  renderTree();',
    '  e.target.value = "";',
    '}',

    'async function handleZipFile(e) {',
    '  var file = e.target.files[0];',
    '  if (!file) return;',
    '  var buf = await file.arrayBuffer();',
    '  var zip = await JSZip.loadAsync(buf);',
    '  var count = 0;',
    '  var entries = Object.entries(zip.files);',
    '  for (var ei = 0; ei < entries.length; ei++) {',
    '    var path = entries[ei][0];',
    '    var entry = entries[ei][1];',
    '    if (entry.dir) continue;',
    '    var bytes = await entry.async("uint8array");',
    '    addFile(path, {',
    '      name: path.split("/").pop(), path: path, content: bytes,',
    '      binary: !isTextContent(bytes, path.split("/").pop()), size: bytes.length',
    '    });',
    '    count++;',
    '  }',
    '  toast("解压 " + count + " 个文件", "success");',
    '  renderTree();',
    '  e.target.value = "";',
    '}',

    'function clearAllFiles() {',
    '  if (!confirm("清空所有文件？")) return;',
    '  state.files.clear();',
    '  state.current = null;',
    '  state.originalContent = null;',
    '  $("editorHeader").classList.add("hidden");',
    '  renderTree();',
    '}',

    // =======================================================
    // 文件树
    // =======================================================
    'function renderTree() {',
    '  var container = $("fileTree");',
    '  var root = {};',
    '  var files = Array.from(state.files.entries());',
    '  for (var i = 0; i < files.length; i++) {',
    '    var path = files[i][0];',
    '    var f = files[i][1];',
    '    var parts = path.split("/");',
    '    var node = root;',
    '    for (var p = 0; p < parts.length - 1; p++) {',
    '      if (!node[parts[p]]) node[parts[p]] = { __dir: true };',
    '      node = node[parts[p]];',
    '    }',
    '    node[parts[parts.length - 1]] = f;',
    '  }',
    '  container.innerHTML = "";',
    '  if (state.files.size === 0) {',
    '    container.innerHTML = "<div class=\\"p-4 text-center text-gray-400 text-xs\\">未加载文件<br/>选择文件夹或 zip 开始</div>";',
    '    return;',
    '  }',
    '  var keys = Object.keys(root).sort();',
    '  for (var k = 0; k < keys.length; k++) {',
    '    var key = keys[k];',
    '    container.appendChild(renderNode(key, root[key], !!root[key].__dir));',
    '  }',
    '}',

    'function renderNode(name, data, isDir) {',
    '  var div = document.createElement("div");',
    '  div.className = "node-wrapper";',
    '  var row = document.createElement("div");',
    '  row.className = "node";',
    '  row.dataset.path = name;',
    '  var caret = document.createElement("span");',
    '  caret.className = "caret " + (isDir ? "closed" : "empty");',
    '  row.appendChild(caret);',
    '  var icon = document.createElement("span");',
    '  icon.className = "text-xs";',
    '  icon.textContent = isDir ? "📁" : getFileIcon(name);',
    '  row.appendChild(icon);',
    '  var label = document.createElement("span");',
    '  label.className = "truncate";',
    '  label.textContent = name;',
    '  row.appendChild(label);',
    '  row.addEventListener("click", function() {',
    '    if (isDir) {',
    '      var children = div.querySelector(".children");',
    '      if (children.classList.contains("hidden")) {',
    '        children.classList.remove("hidden");',
    '        caret.className = "caret open";',
    '        state.expanded.add(name);',
    '      } else {',
    '        children.classList.add("hidden");',
    '        caret.className = "caret closed";',
    '        state.expanded.delete(name);',
    '      }',
    '    } else {',
    '      openFile(data);',
    '    }',
    '  });',
    '  div.appendChild(row);',
    '  if (isDir) {',
    '    var children = document.createElement("div");',
    '    children.className = "children hidden";',
    '    var sortedKeys = Object.keys(data).filter(function(k) { return k !== "__dir"; }).sort(function(a, b) {',
    '      var ad = data[a].__dir ? 1 : 0;',
    '      var bd = data[b].__dir ? 1 : 0;',
    '      if (ad !== bd) return bd - ad;',
    '      return a.localeCompare(b);',
    '    });',
    '    for (var i = 0; i < sortedKeys.length; i++) {',
    '      children.appendChild(renderNode(sortedKeys[i], data[sortedKeys[i]], !!data[sortedKeys[i]].__dir));',
    '    }',
    '    div.appendChild(children);',
    '  }',
    '  return div;',
    '}',

    'function getFileIcon(name) {',
    '  var ext = name.split(".").pop().toLowerCase();',
    '  var m = { html: "🌐", css: "🎨", js: "📜", ts: "📜", json: "🗂️", md: "📝", txt: "📝", svg: "🖼️", png: "🖼️", jpg: "🖼️", jpeg: "🖼️", gif: "🖼️", webp: "🖼️", ico: "🖼️", yml: "⚙️", yaml: "⚙️", xml: "📰" };',
    '  return m[ext] || "📄";',
    '}',

    // =======================================================
    // 编辑器
    // =======================================================
    'function arrayToText(bytes) { return new TextDecoder("utf-8").decode(bytes); }',
    'function textToArray(str) { return new TextEncoder("utf-8").encode(str); }',

    'function openFile(data) {',
    '  state.current = { path: data.path, binary: data.binary, content: data.content };',
    '  state.originalContent = data.binary ? null : data.content;',
    '  $("editorHeader").classList.remove("hidden");',
    '  $("currentFileLabel").textContent = data.path;',
    '  $("fileSizeLabel").textContent = formatSize(data.size);',
    '  var saveBtn = $("saveBtn");',
    '  saveBtn.disabled = data.binary;',
    '  saveBtn.textContent = data.binary ? "二进制文件" : "已保存";',
    '  var body = $("editorBody");',
    '  if (data.binary) {',
    '    body.innerHTML = "<div class=\\"h-full flex items-center justify-center text-gray-400 text-sm\\"><div class=\\"text-center\\"><div class=\\"text-5xl mb-3 opacity-50\\">💾</div><p>二进制文件</p><p class=\\"text-xs mt-2\\">" + formatSize(data.size) + "</p></div></div>";',
    '  } else {',
    '    body.innerHTML = "<textarea id=\\"ta\\" class=\\"editor-textarea w-full h-full border-0 outline-none resize-none p-4\\" spellcheck=\\"false\\"></textarea>";',
    '    var ta = $("ta");',
    '    ta.value = arrayToText(data.content);',
    '    state.current.content = ta.value;',
    '    ta.addEventListener("input", function() {',
    '      state.current.content = ta.value;',
    '      updateSaveBtn();',
    '    });',
    '  }',
    '}',

    'function updateSaveBtn() {',
    '  if (!state.current) return;',
    '  var saveBtn = $("saveBtn");',
    '  if (state.current.binary) { saveBtn.disabled = true; saveBtn.textContent = "二进制文件"; return; }',
    '  var changed = state.current.content !== arrayToText(state.originalContent);',
    '  saveBtn.disabled = !changed;',
    '  saveBtn.textContent = changed ? "💾 保存（Ctrl+S）" : "已保存";',
    '}',

    'function saveCurrentFile() {',
    '  if (!state.current || state.current.binary) return;',
    '  var f = state.files.get(state.current.path);',
    '  f.content = textToArray(state.current.content);',
    '  state.current.originalContent = f.content;',
    '  updateSaveBtn();',
    '  toast("已保存到浏览器内存", "success");',
    '}',

    'function removeCurrentFile() {',
    '  if (!state.current) return;',
    '  if (!confirm("从浏览器中删除此文件？")) return;',
    '  state.files.delete(state.current.path);',
    '  state.current = null;',
    '  state.originalContent = null;',
    '  $("editorHeader").classList.add("hidden");',
    '  renderTree();',
    '}',

    // =======================================================
    // Tar.gz 构建（浏览器端：USTAR + CompressionStream gzip）
    // =======================================================
    'function toOctal(num, width) {',
    '  var str = num.toString(8);',
    '  var bytes = new TextEncoder().encode(str);',
    '  var result = new Uint8Array(width + 1);',
    '  result.set(bytes, width - bytes.length);',
    '  result[result.length - 2] = 0;',
    '  result[result.length - 1] = 0x20;',
    '  return result;',
    '}',

    'function buildTarHeader(name, size) {',
    '  var header = new Uint8Array(512);',
    '  var nameBytes = new TextEncoder().encode(name);',
    '  if (nameBytes.length <= 100) {',
    '    header.set(nameBytes, 0);',
    '  } else {',
    '    header.set(nameBytes.subarray(0, 100), 0);',
    '  }',
    '  header.set(toOctal(0o644, 7), 100);',
    '  header.set(toOctal(0, 7), 108);',
    '  header.set(toOctal(0, 7), 116);',
    '  header.set(toOctal(size, 11), 124);',
    '  header.set(toOctal(Math.floor(Date.now() / 1000), 11), 136);',
    '  header.set(new Uint8Array(8), 148);',
    '  header[156] = 0x30;',
    '  header.set(new TextEncoder().encode("ustar"), 257); header[261] = 0;',
    '  header.set(new TextEncoder().encode("00"), 263);',
    '  var checksum = 0;',
    '  for (var i = 0; i < 512; i++) checksum += header[i];',
    '  var checkStr = toOctal(checksum, 6);',
    '  header.set(checkStr, 148);',
    '  header[148 + checkStr.length] = 0;',
    '  header[148 + checkStr.length + 1] = 0x20;',
    '  return header;',
    '}',

    'async function buildTarGz(files) {',
    '  var blocks = [];',
    '  for (var i = 0; i < files.length; i++) {',
    '    var file = files[i];',
    '    var header = buildTarHeader(file.path, file.content.length);',
    '    blocks.push(header);',
    '    blocks.push(file.content);',
    '    var remainder = file.content.length % 512;',
    '    if (remainder > 0) blocks.push(new Uint8Array(512 - remainder));',
    '  }',
    '  blocks.push(new Uint8Array(1024));',
    '  var totalLen = 0;',
    '  for (var j = 0; j < blocks.length; j++) totalLen += blocks[j].length;',
    '  var tar = new Uint8Array(totalLen);',
    '  var offset = 0;',
    '  for (var k = 0; k < blocks.length; k++) { tar.set(blocks[k], offset); offset += blocks[k].length; }',
    '  var cs = new CompressionStream("gzip");',
    '  var writer = cs.writable.getWriter();',
    '  var reader = cs.readable.getReader();',
    '  writer.write(tar);',
    '  writer.close();',
    '  var chunks = [];',
    '  while (true) {',
    '    var r = await reader.read();',
    '    if (r.done) break;',
    '    chunks.push(r.value);',
    '  }',
    '  var total = 0;',
    '  for (var c = 0; c < chunks.length; c++) total += chunks[c].length;',
    '  var gz = new Uint8Array(total);',
    '  var off = 0;',
    '  for (var d = 0; d < chunks.length; d++) { gz.set(chunks[d], off); off += chunks[d].length; }',
    '  return gz;',
    '}',

    // =======================================================
    // 发布
    // =======================================================
    'function showPublishModal() {',
    '  if (state.files.size === 0) { toast("请先加载文件", "error"); return; }',
    '  openModal("publishModal");',
    '  var totalSize = 0;',
    '  var values = Array.from(state.files.values());',
    '  for (var i = 0; i < values.length; i++) totalSize += values[i].size;',
    '  $("publishStats").textContent = state.files.size + " 个文件，总大小 " + formatSize(totalSize);',
    '}',

    'function showManageModal() { openModal("manageModal"); loadSites(); }',

    'function appendLog(cls, text) {',
    '  var el = $("publishLog");',
    '  var d = document.createElement("div");',
    '  d.className = cls;',
    '  d.textContent = text;',
    '  el.appendChild(d);',
    '  el.scrollTop = el.scrollHeight;',
    '}',

    'function handleSurgeLine(obj) {',
    '  var t = obj.type || "";',
    '  if (t === "progress") {',
    '    var pct = obj.total ? Math.round(obj.written / obj.total * 100) : 0;',
    '    appendLog("stdout", "[" + (obj.id || "?") + "] " + pct + "% (" + obj.written + "/" + obj.total + ")");',
    '  } else if (t === "info") {',
    '    appendLog("exit-ok", "\\n✅ 发布成功！");',
    '    if (obj.urls) appendLog("exit-ok", "可访问: " + obj.urls.join(", "));',
    '  } else if (t === "cert") {',
    '    appendLog("stdout", "🔐 证书: " + (obj.data && obj.data.issuer ? obj.data.issuer : "?"));',
    '  } else if (t === "error") {',
    '    appendLog("exit-fail", "❌ 错误: " + (obj.error && obj.error.message ? obj.error.message : JSON.stringify(obj)));',
    '  } else if (t === "ratelimited") {',
    '    appendLog("exit-fail", "⏱️ 限流: " + JSON.stringify(obj));',
    '  } else if (t === "forbidden") {',
    '    appendLog("exit-fail", "🚫 禁止: " + JSON.stringify(obj));',
    '  } else if (t === "collect") {',
    '    appendLog("stderr", "💳 需要订阅: " + (obj.plan && obj.plan.name ? obj.plan.name : "?"));',
    '  } else if (t === "msg") {',
    '    var isErr = obj.payload && obj.payload.status === "error";',
    '    appendLog(isErr ? "stderr" : "stdout", obj.payload ? obj.payload.msg : JSON.stringify(obj));',
    '  } else {',
    '    appendLog("stdout", JSON.stringify(obj));',
    '  }',
    '}',

    'async function startPublish() {',
    '  var domain = $("publishDomain").value.trim();',
    '  if (!domain) { toast("请输入域名", "error"); return; }',
    '  closeModal("publishModal");',
    '  switchTab("publish");',
    '  $("publishLog").textContent = "";',
    '  appendLog("info", "打包 " + state.files.size + " 个文件为 tar.gz...");',
    '  var fileArr = Array.from(state.files.values()).sort(function(a, b) { return a.path.localeCompare(b.path); });',
    '  var totalSize = 0;',
    '  for (var i = 0; i < fileArr.length; i++) totalSize += fileArr[i].size;',

    '  var tarGz;',
    '  try {',
    '    tarGz = await buildTarGz(fileArr);',
    '  } catch (e) {',
    '    appendLog("stderr", "构建 tar.gz 失败: " + e.message);',
    '    console.error(e);',
    '    return;',
    '  }',
    '  appendLog("info", "tar.gz 大小 " + formatSize(tarGz.length) + "，上传到 " + domain + "...");',

    '  var resp;',
    '  try {',
    '    resp = await fetch("/api/surge/publish?domain=" + encodeURIComponent(domain), {',
    '      method: "POST",',
    '      headers: {',
    '        "Content-Type": "application/gzip",',
    '        "x-project-size": String(totalSize),',
    '        "x-file-count": String(fileArr.length),',
    '        "x-client-version": "surge-gui-worker-v2"',
    '      },',
    '      body: tarGz',
    '    });',
    '  } catch (e) {',
    '    appendLog("stderr", "网络错误: " + e.message);',
    '    return;',
    '  }',

    '  if (!resp.ok || !resp.body) {',
    '    var ct = resp.headers.get("content-type") || "";',
    '    if (ct.indexOf("application/json") !== -1) {',
    '      var errData = await resp.json();',
    '      appendLog("exit-fail", "❌ 发布失败 (" + resp.status + "): " + (errData.message || JSON.stringify(errData)));',
    '    } else {',
    '      appendLog("exit-fail", "❌ 发布失败，HTTP " + resp.status);',
    '    }',
    '    return;',
    '  }',

    '  var reader = resp.body.getReader();',
    '  var decoder = new TextDecoder();',
    '  var buf = "";',
    '  while (true) {',
    '    var r = await reader.read();',
    '    if (r.done) break;',
    '    buf += decoder.decode(r.value, { stream: true });',
    '    var nlIdx;',
    '    while ((nlIdx = buf.indexOf("\\n")) !== -1) {',
    '      var line = buf.substring(0, nlIdx);',
    '      buf = buf.substring(nlIdx + 1);',
    '      if (!line.trim()) continue;',
    '      var obj;',
    '      try { obj = JSON.parse(line); } catch (e) { continue; }',
    '      handleSurgeLine(obj);',
    '    }',
    '  }',
    '}',

    // =======================================================
    // 站点管理
    // =======================================================
    'async function loadSites() {',
    '  $("sitesList").innerHTML = "<div class=\\"text-center text-gray-400 py-4\\">加载中...</div>";',
    '  var r;',
    '  try {',
    '    r = await api("GET", "/api/surge/list");',
    '  } catch (e) {',
    '    $("sitesList").innerHTML = "<div class=\\"text-red-500 text-sm\\">❌ 网络错误</div>";',
    '    return;',
    '  }',
    '  var list;',
    '  if (Array.isArray(r)) list = r;',
    '  else if (r.projects) list = r.projects;',
    '  else if (r.list) list = r.list;',
    '  else if (r.data) list = r.data;',
    '  else list = [];',
    '  if (!list || list.length === 0) {',
    '    $("sitesList").innerHTML = "<div class=\\"text-center text-gray-400 py-4\\">暂无站点</div>";',
    '    return;',
    '  }',
    '  var html = "";',
    '  for (var i = 0; i < list.length; i++) {',
    '    var p = list[i];',
    '    var domain = p.domain;',
    '    html += "<div class=\\"flex items-center gap-2 p-2 rounded border border-gray-200 hover:bg-gray-50\\">";',
    '    html += "  <span class=\\"text-sm font-mono flex-1\\">🌐 " + domain + "</span>";',
    '    html += "  <span class=\\"text-xs text-gray-500\\">" + (p.timeAgoInWords || "") + "</span>";',
    '    html += "  <a href=\\"https://" + domain + "\\" target=\\"_blank\\" class=\\"btn btn-secondary text-xs py-1 px-2\\">访问</a>";',
    '    html += "  <button data-domain=\\"" + domain.replace(/"/g, "&quot;") + "\\" class=\\"btn-teardown btn btn-danger text-xs py-1 px-2\\">下线</button>";',
    '    html += "</div>";',
    '  }',
    '  $("sitesList").innerHTML = html;',
    '  // 给新渲染的下线按钮绑事件',
    '  var btns = document.querySelectorAll(".btn-teardown");',
    '  for (var b = 0; b < btns.length; b++) {',
    '    btns[b].addEventListener("click", function() {',
    '      teardownSite(this.getAttribute("data-domain"));',
    '    });',
    '  }',
    '}',

    'async function teardownSite(domain) {',
    '  var msg = "⚠️ 下线 " + domain + " ？\\n\\n域名将不再指向你的站点，此操作不可撤销。确定吗？";',
    '  if (!confirm(msg)) return;',
    '  try {',
    '    var r = await api("POST", "/api/surge/teardown?domain=" + encodeURIComponent(domain));',
    '    toast(r.ok ? "已下线" : ("下线失败: " + (r.message || "")), r.ok ? "success" : "error");',
    '    if (r.ok) await loadSites();',
    '  } catch (e) {',
    '    toast("下线失败: " + e.message, "error");',
    '  }',
    '}',

    // =======================================================
    // Tab 切换
    // =======================================================
    'function switchTab(name) {',
    '  var isEditor = name === "editor";',
    '  $("panel-editor").classList.toggle("hidden", !isEditor);',
    '  $("panel-publish").classList.toggle("hidden", isEditor);',
    '  var tabs = ["tab-editor", "tab-publish"];',
    '  for (var i = 0; i < tabs.length; i++) {',
    '    var isActive = (tabs[i] === "tab-editor") === isEditor;',
    '    $(tabs[i]).className = isActive',
    '      ? "px-4 py-2.5 text-sm font-medium border-b-2 border-blue-500 text-blue-600"',
    '      : "px-4 py-2.5 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700";',
    '  }',
    '}',

    // =======================================================
    // DOMContentLoaded：统一 addEventListener 绑定所有事件
    // =======================================================
    'document.addEventListener("DOMContentLoaded", function() {',

    '  // 关闭全局错误条',
    '  var gec = $("globalErrorClose");',
    '  if (gec) gec.addEventListener("click", function() { $("globalErrorBar").style.display = "none"; });',

    '  // 登录相关',
    '  var loginPass = $("loginPass");',
    '  if (loginPass) loginPass.addEventListener("keydown", function(e) { if (e.key === "Enter") doLogin(); });',
    '  var loginBtn = $("loginBtn");',
    '  if (loginBtn) loginBtn.addEventListener("click", doLogin);',

    '  // header 按钮',
    '  if ($("btnPublish")) $("btnPublish").addEventListener("click", showPublishModal);',
    '  if ($("btnManage")) $("btnManage").addEventListener("click", showManageModal);',
    '  if ($("btnLogout")) $("btnLogout").addEventListener("click", doLogout);',

    '  // 文件选择',
    '  if ($("btnPickFolder")) $("btnPickFolder").addEventListener("click", function() { $("fileInput").click(); });',
    '  if ($("btnPickZip")) $("btnPickZip").addEventListener("click", function() { $("zipInput").click(); });',
    '  if ($("fileInput")) $("fileInput").addEventListener("change", handleLocalFiles);',
    '  if ($("zipInput")) $("zipInput").addEventListener("change", handleZipFile);',
    '  if ($("btnClearAll")) $("btnClearAll").addEventListener("click", clearAllFiles);',

    '  // Tabs',
    '  if ($("tab-editor")) $("tab-editor").addEventListener("click", function() { switchTab("editor"); });',
    '  if ($("tab-publish")) $("tab-publish").addEventListener("click", function() { switchTab("publish"); });',

    '  // 编辑器按钮',
    '  if ($("saveBtn")) $("saveBtn").addEventListener("click", saveCurrentFile);',
    '  if ($("btnRemoveFile")) $("btnRemoveFile").addEventListener("click", removeCurrentFile);',

    '  // 发布日志清空',
    '  if ($("btnClearLog")) $("btnClearLog").addEventListener("click", function() { $("publishLog").textContent = ""; });',

    '  // 发布弹窗',
    '  if ($("publishModal")) $("publishModal").addEventListener("click", function(e) { if (e.target === this) closeModal("publishModal"); });',
    '  if ($("btnPublishCancel")) $("btnPublishCancel").addEventListener("click", function() { closeModal("publishModal"); });',
    '  if ($("btnPublishGo")) $("btnPublishGo").addEventListener("click", startPublish);',

    '  // 站点弹窗',
    '  if ($("manageModal")) $("manageModal").addEventListener("click", function(e) { if (e.target === this) closeModal("manageModal"); });',
    '  if ($("btnRefreshSites")) $("btnRefreshSites").addEventListener("click", loadSites);',

    '  // Ctrl+S 保存',
    '  document.addEventListener("keydown", function(e) {',
    '    if ((e.ctrlKey || e.metaKey) && e.key === "s" && state.current && !state.current.binary) {',
    '      e.preventDefault();',
    '      saveCurrentFile();',
    '    }',
    '  });',

    '  // 拖拽支持',
    '  var bodyEl = document.body;',
    '  bodyEl.addEventListener("dragenter", function(e) { if (e.dataTransfer && Array.from(e.dataTransfer.types).indexOf("Files") !== -1) bodyEl.classList.add("dropzone-drag"); });',
    '  bodyEl.addEventListener("dragleave", function() { bodyEl.classList.remove("dropzone-drag"); });',
    '  bodyEl.addEventListener("drop", function(e) { bodyEl.classList.remove("dropzone-drag"); e.preventDefault(); });',
    '  var dropzone = $("dropzone");',
    '  if (dropzone) {',
    '    dropzone.addEventListener("dragover", function(e) { e.preventDefault(); dropzone.classList.add("dropzone-drag"); });',
    '    dropzone.addEventListener("dragleave", function() { dropzone.classList.remove("dropzone-drag"); });',
    '    dropzone.addEventListener("drop", async function(e) {',
    '      e.preventDefault();',
    '      dropzone.classList.remove("dropzone-drag");',
    '      var items = e.dataTransfer.items;',
    '      if (!items) return;',
    '      var files = [];',
    '      for (var it = 0; it < items.length; it++) { if (items[it].kind === "file") files.push(items[it].getAsFile()); }',
    '      var zipFile = null;',
    '      for (var zf = 0; zf < files.length; zf++) {',
    '        if (files[zf].name.toLowerCase().endsWith(".zip")) { zipFile = files[zf]; break; }',
    '      }',
    '      if (zipFile) {',
    '        var bytes = new Uint8Array(await zipFile.arrayBuffer());',
    '        var zip = await JSZip.loadAsync(bytes);',
    '        var count = 0;',
    '        var entries = Object.entries(zip.files);',
    '        for (var ei = 0; ei < entries.length; ei++) {',
    '          var zpath = entries[ei][0];',
    '          var zentry = entries[ei][1];',
    '          if (zentry.dir) continue;',
    '          var b = await zentry.async("uint8array");',
    '          var fname = zpath.split("/").pop();',
    '          addFile(zpath, {',
    '            name: fname, path: zpath, content: b,',
    '            binary: !isTextContent(b, fname), size: b.length',
    '          });',
    '          count++;',
    '        }',
    '        toast("解压 " + count + " 个文件", "success");',
    '        renderTree();',
    '        return;',
    '      }',
    '      for (var i = 0; i < files.length; i++) {',
    '        var fpath = files[i].webkitRelativePath || files[i].name;',
    '        if (!fpath) continue;',
    '        var fbytes = new Uint8Array(await files[i].arrayBuffer());',
    '        addFile(fpath, {',
    '          name: files[i].name, path: fpath, content: fbytes,',
    '          binary: !isTextContent(fbytes, files[i].name), size: fbytes.length',
    '        });',
    '      }',
    '      toast("加载 " + files.length + " 个文件", "success");',
    '      renderTree();',
    '    });',
    '  }',

    '  // 启动：检查登录状态',
    '  checkLogin();',
    '});',
    '</script>',
    '</body>',
    '</html>'
  ].join('\n');
}
