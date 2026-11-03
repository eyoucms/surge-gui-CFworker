// Surge GUI - Cloudflare Worker 版
// 单文件 Worker：前端页面 + Surge API 代理
// 部署：wrangler deploy 或 Cloudflare Dashboard 粘贴
//
// Secrets (在 Cloudflare Dashboard / wrangler.toml 配置):
//   SURGE_TOKEN  - Surge API Token
//   PASSPHRASE   - 访问口令（防止 URL 泄露后别人能操作账号）
//   (可选) SESSION_SECRET - 32+ 字符随机串，用于签名 Cookie
//
// 本地开发：wrangler dev
// 没有 wrangler 时直接把本文件粘贴到 Cloudflare Dashboard 的 Workers 编辑器也能跑

const SURGE_API_BASE = 'https://surge.surge.sh';
const VERSION = '1.0.0-worker';
const SESSION_COOKIE = 'surge_gui_session';

// ============================================================
// 工具函数
// ============================================================

function base64Encode(str) {
  // Worker 环境里 btoa 只接受 Latin-1；token 是 ASCII 所以没问题
  return btoa(unescape(encodeURIComponent(str)));
}

function surgeAuthHeader(token) {
  return 'Basic ' + base64Encode('token:' + token);
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store'
    }
  });
}

function textResponse(text, status = 200, headers = {}) {
  return new Response(text, { status, headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', ...headers } });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ ok: false, message }, status);
}

function getCookie(request, name) {
  const cookies = request.headers.get('cookie') || '';
  const match = cookies.match(new RegExp('(?:^|; )' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '=([^;]*)'));
  return match ? decodeURIComponent(match[1]) : null;
}

function setSessionCookie(passphrase, sessionSecret) {
  // 签名: base64(salt.timestamp) + "." + HMAC
  const timestamp = Date.now();
  const salt = Math.random().toString(36).slice(2);
  const payload = salt + '.' + timestamp + '.' + passphrase;
  let mac;
  if (sessionSecret) {
    // 没有 Web Crypto HMAC 的 fallback（Worker 里其实有）
    mac = simpleHash(payload + '|' + sessionSecret);
  } else {
    mac = simpleHash(payload);
  }
  const value = btoa(unescape(encodeURIComponent(payload + '|' + mac)));
  return `${SESSION_COOKIE}=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800`;
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

// 简单的 FNV-1a 哈希，够用做会话签名（Worker 环境下避免额外依赖）
function simpleHash(str) {
  let h = 2166136261;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(16);
}

// 检查是否已登录（passphrase 正确）
function requireAuth(request, env) {
  if (!env.PASSPHRASE) return true; // 没设口令就不强制
  const cookieValue = getCookie(request, SESSION_COOKIE);
  if (!cookieValue) return false;
  return verifySessionCookie(cookieValue, env.PASSPHRASE, env.SESSION_SECRET);
}

// ============================================================
// 主请求处理器
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
      // 无需鉴权的路由
      if (path === '/health' && request.method === 'GET') {
        return jsonResponse({
          ok: true,
          version: VERSION,
          surgeApi: SURGE_API_BASE,
          tokenConfigured: !!env.SURGE_TOKEN,
          passphraseConfigured: !!env.PASSPHRASE
        });
      }

      // 登录：提交 passphrase，返回 session cookie
      if (path === '/api/login' && request.method === 'POST') {
        const body = await readJson(request);
        const passphrase = body.passphrase || '';
        if (!env.PASSPHRASE) {
          return jsonResponse({ ok: true, message: '未配置口令，无需登录' });
        }
        if (passphrase !== env.PASSPHRASE) {
          return errorResponse('口令错误', 401);
        }
        const cookie = setSessionCookie(passphrase, env.SESSION_SECRET);
        return jsonResponse({ ok: true, message: '登录成功' }, 200, { 'Set-Cookie': cookie });
      }

      // 登出
      if (path === '/api/logout' && request.method === 'POST') {
        return jsonResponse({ ok: true }, 200, {
          'Set-Cookie': `${SESSION_COOKIE}=deleted; Path=/; HttpOnly; Max-Age=0`
        });
      }

      // 检查登录状态（不返回 token）
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

      // 其余路由都要鉴权
      if (!requireAuth(request, env) && env.PASSPHRASE) {
        return errorResponse('请先登录', 401);
      }

      // Surge API 代理路由
      if (path.startsWith('/api/surge/')) {
        if (!env.SURGE_TOKEN) {
          return errorResponse('后端未配置 SURGE_TOKEN Secret', 500);
        }
        return handleSurgeProxy(request, env, path);
      }

      // 默认：返回前端页面
      return new Response(serveHTML(), {
        headers: {
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-cache'
        }
      });

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
  const token = env.SURGE_TOKEN;
  const auth = surgeAuthHeader(token);

  // GET /api/surge/list → GET https://surge.surge.sh/list
  if (path === '/api/surge/list' && request.method === 'GET') {
    const resp = await fetch(SURGE_API_BASE + '/list', {
      method: 'GET',
      headers: { 'Authorization': auth }
    });
    const data = await resp.json();
    return new Response(JSON.stringify(data), {
      status: resp.status,
      headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' }
    });
  }

  // POST /api/surge/account → GET /account (前端想知道是否 token 有效)
  if (path === '/api/surge/account' && request.method === 'GET') {
    const resp = await fetch(SURGE_API_BASE + '/account', {
      method: 'GET',
      headers: { 'Authorization': auth }
    });
    const data = await resp.json();
    if (!resp.ok) return errorResponse(data.messages?.[0] || data.message || 'Token 无效', resp.status);
    return jsonResponse({ ok: true, account: data });
  }

  // POST /api/surge/publish → PUT /:domain (流式)
  if (path === '/api/surge/publish' && request.method === 'POST') {
    const domain = new URL(request.url).searchParams.get('domain');
    if (!domain) return errorResponse('缺少 domain 参数');

    // 前端以 multipart/form-data 或直接 tar.gz body 发送
    // 我们接受直接 body（前端构建好 tar.gz 后 POST）
    const contentType = request.headers.get('content-type') || '';

    let tarBody;
    if (contentType.includes('multipart/form-data')) {
      // 简单解析 multipart，只取第一个文件 part
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

    const surgeUrl = `${SURGE_API_BASE}/${encodeURIComponent(domain)}`;
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

    // 透传 ndjson 流
    return new Response(fetchResp.body, {
      status: fetchResp.status,
      headers: {
        'Content-Type': 'application/x-ndjson; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Accel-Buffering': 'no'
      }
    });
  }

  // POST /api/surge/teardown → DELETE /:domain
  if (path === '/api/surge/teardown' && request.method === 'POST') {
    const domain = new URL(request.url).searchParams.get('domain');
    if (!domain) return errorResponse('缺少 domain 参数');

    const resp = await fetch(`${SURGE_API_BASE}/${encodeURIComponent(domain)}`, {
      method: 'DELETE',
      headers: { 'Authorization': auth }
    });
    const text = await resp.text();
    // 尝试 JSON，不行就纯文本
    let data;
    try { data = JSON.parse(text); } catch { data = { msg: text }; }
    return new Response(JSON.stringify({ ok: resp.ok, ...data }), {
      status: resp.ok ? 200 : resp.status,
      headers: { 'Content-Type': 'application/json; charset=utf-8' }
    });
  }

  // 状态检查
  if (path === '/api/surge/status' && request.method === 'GET') {
    const domain = new URL(request.url).searchParams.get('domain');
    if (!domain) return errorResponse('缺少 domain 参数');
    const resp = await fetch(`${SURGE_API_BASE}/${encodeURIComponent(domain)}/status`, {
      method: 'GET',
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

async function readJson(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

// ============================================================
// 前端页面（内联，避免额外部署静态文件）
// ============================================================

function serveHTML() {
  // 前端和本地版基本一致，但加了登录检查 + 浏览器端 tar.gz 构建
  return [
    "<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\"/>\n<meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\"/>\n<title>Surge GUI - 在线版</title>\n<script src=\"https://cdn.tailwindcss.com\"></script>\n<script src=\"https://cdn.jsdelivr.net/npm/jszip@3.10.1/dist/jszip.min.js\"></script>\n<style>\nbody{font-family:-apple-system,\"PingFang SC\",\"Microsoft YaHei\",sans-serif;}\n.btn{padding:6px 12px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer;transition:all .15s;border:1px solid transparent;}\n.btn-primary{background:#2563eb;color:white;}.btn-primary:hover{background:#1d4ed8;}.btn-primary:disabled{background:#93c5fd;}\n.btn-secondary{background:#f3f4f6;color:#374151;border-color:#e5e7eb;}.btn-secondary:hover{background:#e5e7eb;}\n.btn-danger{background:#dc2626;color:white;}.btn-danger:hover{background:#b91c1c;}\n.btn-ghost{background:transparent;color:#6b7280;}.btn-ghost:hover{background:#f3f4f6;color:#374151;}\n.modal-backdrop{position:fixed;inset:0;background:rgba(0,0,0,.4);display:flex;align-items:center;justify-content:center;z-index:50;}\n.modal{background:white;border-radius:10px;box-shadow:0 20px 60px rgba(0,0,0,.2);max-width:520px;width:92%;max-height:85vh;overflow:auto;}\n.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:500;}\n.badge-green{background:#d1fae5;color:#065f46;}.badge-red{background:#fee2e2;color:#991b1b;}.badge-blue{background:#dbeafe;color:#1e40af;}\n.file-tree .node{cursor:pointer;padding:2px 4px;border-radius:3px;display:flex;align-items:center;gap:4px;font-size:13px;}\n.file-tree .node:hover{background:#eef2ff;}.file-tree .node.active{background:#dbeafe;}\n.file-tree .children{padding-left:16px;}\n.file-tree .caret{width:12px;display:inline-block;text-align:center;color:#6b7280;font-size:9px;}\n.file-tree .caret.open::before{content:\"▼\";}\n.file-tree .caret.closed::before{content:\"▶\";}\n.file-tree .caret.empty::before{content:\"·\";color:#d1d5db;}\n.editor-textarea{font-family:Consolas,Monaco,Menlo,monospace;font-size:13px;line-height:1.5;tab-size:2;}\n.ansi-log{font-family:Consolas,Monaco,monospace;font-size:12px;white-space:pre-wrap;word-break:break-all;}\n.ansi-log .stdout{color:#e5e7eb;}\n.ansi-log .stderr{color:#fca5a5;}\n.ansi-log .info{color:#60a5fa;font-weight:bold;}\n.ansi-log .exit-ok{color:#34d399;font-weight:bold;}\n.ansi-log .exit-fail{color:#f87171;font-weight:bold;}\n.dropzone-drag{border-color:#2563eb!important;background:#eff6ff!important;}\n.blob{background:#f0fdf4;border:2px dashed #22c55e;}\n</style>\n</head>\n<body class=\"bg-gray-50 text-gray-800 h-screen flex flex-col overflow-hidden\">\n\n<!-- 登录界面 -->\n<div id=\"loginScreen\" class=\"hidden h-full flex items-center justify-center\">\n  <div class=\"bg-white p-8 rounded-xl shadow-lg max-w-sm w-full\">\n    <h1 class=\"text-xl font-semibold text-center mb-2\">🔒 Surge GUI</h1>\n    <p class=\"text-center text-gray-500 text-sm mb-6\">请输入访问口令</p>\n    <input id=\"loginPass\" type=\"password\" placeholder=\"口令\" class=\"w-full border border-gray-300 rounded px-3 py-2 mb-3\" onkeydown=\"if(event.key==='Enter')doLogin()\"/>\n    <button class=\"btn btn-primary w-full\" onclick=\"doLogin()\">登录</button>\n    <p id=\"loginMsg\" class=\"mt-2 text-sm text-center\"></p>\n  </div>\n</div>\n\n<!-- 主界面 -->\n<div id=\"mainApp\" class=\"h-full flex flex-col\">\n  <header class=\"bg-white border-b border-gray-200 px-5 py-3 flex items-center gap-4 flex-shrink-0\">\n    <div class=\"flex items-center gap-2\">\n      <div class=\"w-8 h-8 bg-gradient-to-br from-blue-500 to-purple-600 rounded-lg flex items-center justify-center text-white font-bold text-sm\">S</div>\n      <div>\n        <h1 class=\"font-semibold text-gray-900 leading-tight\">Surge GUI <span class=\"text-xs text-gray-400 font-normal\">在线版</span></h1>\n        <p class=\"text-xs text-gray-500 leading-tight\">文件在浏览器本地，发布走 Surge API</p>\n      </div>\n    </div>\n    <div class=\"ml-auto flex items-center gap-2\">\n      <span id=\"accountInfo\" class=\"badge badge-blue\">加载中...</span>\n      <button class=\"btn btn-secondary text-xs\" onclick=\"showPublishModal()\">🚀 发布</button>\n      <button class=\"btn btn-secondary text-xs\" onclick=\"showManageModal()\">🌐 站点</button>\n      <button class=\"btn btn-ghost text-xs\" onclick=\"doLogout()\">退出</button>\n    </div>\n  </header>\n\n  <main class=\"flex flex-1 overflow-hidden\">\n    <aside class=\"w-72 bg-white border-r border-gray-200 flex flex-col flex-shrink-0\">\n      <div class=\"p-3 border-b border-gray-100 space-y-2\">\n        <label id=\"dropzone\" class=\"block border-2 border-dashed border-gray-300 rounded-lg p-3 text-center text-sm text-gray-600 cursor-pointer hover:border-blue-400 hover:bg-blue-50 transition\">\n          <div class=\"text-2xl mb-1\">📦</div>\n          <div class=\"font-medium\">拖拽 zip / 文件夹</div>\n          <div class=\"text-xs text-gray-400 mt-0.5\">或点击选择</div>\n          <input id=\"fileInput\" type=\"file\" class=\"hidden\" webkitdirectory directory multiple onchange=\"handleLocalFiles(event)\" />\n          <input id=\"zipInput\" type=\"file\" accept=\".zip\" class=\"hidden\" onchange=\"handleZipFile(event)\" />\n        </label>\n        <div class=\"flex gap-1\">\n          <button class=\"btn btn-secondary flex-1 text-xs\" onclick=\"document.getElementById('fileInput').click()\">📁 选文件夹</button>\n          <button class=\"btn btn-secondary flex-1 text-xs\" onclick=\"document.getElementById('zipInput').click()\">🗜️ 选 zip</button>\n        </div>\n      </div>\n      <div class=\"flex items-center justify-between px-3 py-2 border-b border-gray-100 bg-gray-50\">\n        <span class=\"text-xs font-medium text-gray-600\">本地文件（浏览器内存）</span>\n        <button class=\"btn btn-ghost text-xs py-0.5 px-2\" onclick=\"clearAllFiles()\" title=\"清空所有文件\">🗑️</button>\n      </div>\n      <div id=\"fileTree\" class=\"file-tree flex-1 overflow-auto py-2 px-2 text-sm\">\n        <div class=\"p-4 text-center text-gray-400 text-xs\">未加载文件<br/>选择文件夹或 zip 开始</div>\n      </div>\n    </aside>\n\n    <section class=\"flex-1 flex flex-col overflow-hidden\">\n      <div class=\"bg-white border-b border-gray-200 flex items-center gap-1 px-3\">\n        <button id=\"tab-editor\" class=\"px-4 py-2.5 text-sm font-medium border-b-2 border-blue-500 text-blue-600\" onclick=\"switchTab('editor')\">📝 编辑器</button>\n        <button id=\"tab-publish\" class=\"px-4 py-2.5 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700\" onclick=\"switchTab('publish')\">📤 发布日志</button>\n      </div>\n\n      <div id=\"panel-editor\" class=\"flex-1 flex flex-col overflow-hidden\">\n        <div id=\"editorHeader\" class=\"hidden bg-white border-b border-gray-200 px-4 py-2 flex items-center gap-2 text-sm\">\n          <span id=\"currentFileLabel\" class=\"font-medium text-gray-700\"></span>\n          <span id=\"fileSizeLabel\" class=\"text-xs text-gray-400\"></span>\n          <div class=\"ml-auto flex gap-2\">\n            <button id=\"saveBtn\" class=\"btn btn-primary text-xs\" disabled onclick=\"saveCurrentFile()\">💾 保存</button>\n            <button class=\"btn btn-danger text-xs\" onclick=\"removeCurrentFile()\">🗑️ 删除</button>\n          </div>\n        </div>\n        <div id=\"editorBody\" class=\"flex-1 bg-white\">\n          <div class=\"h-full flex items-center justify-center text-gray-400 text-sm\">\n            <div class=\"text-center px-6\">\n              <div class=\"text-5xl mb-3 opacity-50\">📂</div>\n              <p>从左侧文件树选择文件开始编辑</p>\n            </div>\n          </div>\n        </div>\n      </div>\n\n      <div id=\"panel-publish\" class=\"hidden flex-1 flex flex-col overflow-hidden\">\n        <div class=\"bg-white border-b border-gray-200 px-4 py-2 flex items-center gap-2 text-sm\">\n          <span class=\"font-medium\">发布日志</span>\n          <button class=\"btn btn-ghost text-xs py-0.5 px-2 ml-auto\" onclick=\"$('publishLog').textContent=''\">清空</button>\n        </div>\n        <div id=\"publishLog\" class=\"ansi-log flex-1 overflow-auto p-4 bg-gray-900 text-white\"></div>\n      </div>\n    </section>\n  </main>\n</div>\n\n<!-- 发布弹窗 -->\n<div id=\"publishModal\" class=\"modal-backdrop hidden\" onclick=\"if(event.target===this)closeModal('publishModal')\">\n  <div class=\"modal p-6\">\n    <h2 class=\"text-lg font-semibold mb-3\">🚀 发布到 Surge</h2>\n    <p class=\"text-sm text-gray-600 mb-3\">当前浏览器内存中的所有文件将打包为 tar.gz 上传。</p>\n    <div class=\"mb-3\">\n      <label class=\"text-xs text-gray-600 block mb-1\">发布域名</label>\n      <input id=\"publishDomain\" type=\"text\" placeholder=\"your-project.surge.sh\" class=\"w-full border border-gray-300 rounded px-3 py-2 text-sm\"/>\n      <div class=\"text-xs text-gray-500 mt-1\">免费版域名格式: xxx.surge.sh（xxx 全局唯一）</div>\n    </div>\n    <div id=\"publishStats\" class=\"text-xs text-gray-500 mb-3\"></div>\n    <div class=\"flex gap-2 justify-end\">\n      <button class=\"btn btn-ghost\" onclick=\"closeModal('publishModal')\">取消</button>\n      <button class=\"btn btn-primary\" onclick=\"startPublish()\">开始发布</button>\n    </div>\n  </div>\n</div>\n\n<!-- 站点管理弹窗 -->\n<div id=\"manageModal\" class=\"modal-backdrop hidden\" onclick=\"if(event.target===this)closeModal('manageModal')\">\n  <div class=\"modal p-6\" style=\"max-width:680px\">\n    <div class=\"flex items-center gap-2 mb-3\">\n      <h2 class=\"text-lg font-semibold\">🌐 已发布站点</h2>\n      <button class=\"btn btn-ghost text-xs py-0.5 px-2 ml-auto\" onclick=\"loadSites()\">🔄 刷新</button>\n    </div>\n    <div id=\"sitesList\" class=\"space-y-2 text-sm\"></div>\n  </div>\n</div>\n\n<!-- Toast -->\n<div id=\"toast\" class=\"fixed top-5 left-1/2 -translate-x-1/2 bg-gray-800 text-white px-4 py-2 rounded-lg text-sm shadow-lg z-[100] opacity-0 transition-opacity pointer-events-none\"></div>\n\n<script>\n// ===== 状态 =====\nconst state = {\n  files: new Map(), // path → { name, path, content: Uint8Array, binary, size }\n  current: null,    // {path, content, originalContent, binary}\n  expanded: new Set([''])\n};\n\nfunction $(id){return document.getElementById(id);}\nfunction toast(msg,type='info'){const el=$('toast');el.textContent=msg;el.style.background=type==='error'?'#dc2626':type==='success'?'#059669':'#1f2937';el.style.opacity='1';setTimeout(()=>el.style.opacity='0',2500);}\nfunction closeModal(id){$(id).classList.add('hidden');}\nfunction openModal(id){$(id).classList.remove('hidden');}\n\nasync function api(method,path,body){const opts={method,headers:{}};if(body!==undefined){opts.headers['Content-Type']='application/json';opts.body=JSON.stringify(body);}const r=await fetch(path,opts);const ct=r.headers.get('content-type')||'';if(ct.includes('application/json'))return await r.json();return r;}\n\n// ===== 登录 =====\nasync function checkLogin(){\n  const r=await api('GET','/api/config');\n  if(!r.passphraseConfigured||r.loggedIn){\n    $('mainApp').classList.remove('hidden');\n    $('loginScreen').classList.add('hidden');\n    loadAccount();\n    return true;\n  }\n  $('mainApp').classList.add('hidden');\n  $('loginScreen').classList.remove('hidden');\n  return false;\n}\n\nasync function doLogin(){\n  const pass=$('loginPass').value;\n  $('loginMsg').textContent='登录中...';\n  const r=await api('POST','/api/login',{passphrase:pass});\n  if(r.ok){toast('登录成功','success');checkLogin();}\n  else{$('loginMsg').textContent=r.message;$('loginMsg').style.color='#dc2626';}\n}\n\nasync function doLogout(){await api('POST','/api/logout');location.reload();}\n\nasync function loadAccount(){\n  const r=await api('GET','/api/surge/account');\n  if(r.ok){$('accountInfo').textContent=r.account.email+' · '+r.account.plan?.name||'Free';}\n  else{$('accountInfo').textContent='⚠️ Token 无效';}\n}\n\n// ===== 文件加载 =====\nfunction addFile(path, content) {\n  // path 是相对路径如 \"index.html\" 或 \"assets/logo.png\"\n  state.files.set(path, content);\n}\n\nfunction formatSize(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(1)+' MB';}\nfunction isTextContent(bytes, filename){\n  const ext=filename.split('.').pop().toLowerCase();\n  const textExts=new Set(['html','htm','css','scss','less','js','jsx','ts','tsx','mjs','json','md','markdown','txt','xml','yaml','yml','svg','conf','ini','env','csv','map']);\n  if(textExts.has(ext))return true;\n  // 检测 null 字节\n  for(let i=0;i<Math.min(bytes.length,8192);i++){if(bytes[i]===0)return false;}\n  return bytes.length<100000;\n}\n\nasync function handleLocalFiles(e){\n  const files=Array.from(e.target.files);\n  for(const f of files){\n    // webkitRelativePath: \"folder/subdir/file.txt\"\n    const path=f.webkitRelativePath||f.name;\n    const buf=await f.arrayBuffer();\n    const bytes=new Uint8Array(buf);\n    addFile(path,{name:f.name,path,content:bytes,binary:!isTextContent(bytes,f.name),size:bytes.length});\n  }\n  toast(`已加载 ${files.length} 个文件`,'success');\n  renderTree();\n  e.target.value='';\n}\n\nasync function handleZipFile(e){\n  const file=e.target.files[0];if(!file)return;\n  const buf=await file.arrayBuffer();\n  const zip=await JSZip.loadAsync(buf);\n  let count=0;\n  for(const [path,entry] of Object.entries(zip.files)){\n    if(entry.dir)continue;\n    const bytes=await entry.async('uint8array');\n    addFile(path,{name:path.split('/').pop(),path,content:bytes,binary:!isTextContent(bytes,path.split('/').pop()),size:bytes.length});\n    count++;\n  }\n  toast(`解压 ${count} 个文件`,'success');\n  renderTree();\n  e.target.value='';\n}\n\nfunction clearAllFiles(){\n  if(!confirm('清空所有文件？'))return;\n  state.files.clear();state.current=null;state.originalContent=null;\n  $('editorHeader').classList.add('hidden');\n  renderTree();\n}\n\n// ===== 文件树 =====\nfunction renderTree(){\n  const container=$('fileTree');\n  const root={};\n  for(const [path,f] of state.files){\n    const parts=path.split('/');\n    let node=root;\n    for(const p of parts.slice(0,-1)){\n      if(!node[p])node[p]={__dir:true};\n      node=node[p];\n    }\n    node[parts[parts.length-1]]=f;\n  }\n  container.innerHTML='';\n  if(state.files.size===0){\n    container.innerHTML='<div class=\"p-4 text-center text-gray-400 text-xs\">未加载文件<br/>选择文件夹或 zip 开始</div>';\n    return;\n  }\n  for(const k of Object.keys(root).sort()){\n    container.appendChild(renderNode(k, root[k], root[k].__dir?'':false));\n  }\n}\n\nfunction renderNode(name, data, isDir){\n  const div=document.createElement('div');\n  div.className='node-wrapper';\n  const row=document.createElement('div');row.className='node';\n  const fullPath=state.expanded.has('')&&isDir?name:name;\n  row.dataset.path=name;\n\n  const caret=document.createElement('span');caret.className='caret '+(isDir?'closed':'empty');\n  row.appendChild(caret);\n\n  const icon=document.createElement('span');icon.className='text-xs';\n  icon.textContent=isDir?'📁':getFileIcon(name);\n  row.appendChild(icon);\n\n  const label=document.createElement('span');label.className='truncate';label.textContent=name;\n  row.appendChild(label);\n\n  row.onclick=()=>{\n    if(isDir){\n      const children=div.querySelector('.children');\n      if(children.classList.contains('hidden')){children.classList.remove('hidden');caret.className='caret open';state.expanded.add(name);}\n      else{children.classList.add('hidden');caret.className='caret closed';state.expanded.delete(name);}\n    }else{openFile(data);}\n  };\n  div.appendChild(row);\n\n  if(isDir){\n    const children=document.createElement('div');children.className='children hidden';\n    const sortedKeys=Object.keys(data).filter(k=>k!=='__dir').sort((a,b)=>{\n      const ad=data[a].__dir?1:0,bd=data[b].__dir?1:0;\n      if(ad!==bd)return bd-ad;return a.localeCompare(b);\n    });\n    for(const k of sortedKeys){\n      children.appendChild(renderNode(k, data[k], data[k].__dir));\n    }\n    div.appendChild(children);\n  }\n  return div;\n}\n\nfunction getFileIcon(name){\n  const ext=name.split('.').pop().toLowerCase();\n  const m={html:'🌐',css:'🎨',js:'📜',ts:'📜',json:'🗂️',md:'📝',txt:'📝',svg:'🖼️',png:'🖼️',jpg:'🖼️',jpeg:'🖼️',gif:'🖼️',webp:'🖼️',ico:'🖼️',yml:'⚙️',yaml:'⚙️',xml:'📰'};\n  return m[ext]||'📄';\n}\n\n// ===== 编辑器 =====\nfunction openFile(data){\n  state.current={path:data.path,binary:data.binary,content:data.content};\n  state.originalContent=data.binary?null:data.content;\n\n  $('editorHeader').classList.remove('hidden');\n  $('currentFileLabel').textContent=data.path;\n  $('fileSizeLabel').textContent=formatSize(data.size);\n  $('saveBtn').disabled=data.binary;\n  $('saveBtn').textContent='已加载（无需保存）';\n\n  const body=$('editorBody');\n  if(data.binary){\n    body.innerHTML='<div class=\"h-full flex items-center justify-center text-gray-400 text-sm\"><div class=\"text-center\"><div class=\"text-5xl mb-3 opacity-50\">💾</div><p>二进制文件</p><p class=\"text-xs mt-2\">'+formatSize(data.size)+'</p></div></div>';\n  }else{\n    body.innerHTML='<textarea id=\"ta\" class=\"editor-textarea w-full h-full border-0 outline-none resize-none p-4\" spellcheck=\"false\"></textarea>';\n    $('ta').value=arrayToText(data.content);\n    state.current.content=$('ta').value;\n    $('ta').oninput=()=>{state.current.content=$('ta').value;updateSaveBtn();};\n  }\n}\n\nfunction arrayToText(bytes){return new TextDecoder('utf-8').decode(bytes);}\nfunction textToArray(str){return new TextEncoder('utf-8').encode(str);}\n\nfunction updateSaveBtn(){\n  if(!state.current)return;\n  if(state.current.binary){$('saveBtn').disabled=true;return;}\n  const changed=state.current.content!==arrayToText(state.originalContent);\n  $('saveBtn').disabled=!changed;\n  $('saveBtn').textContent=changed?'💾 保存（Ctrl+S）':'已保存';\n}\n\nfunction saveCurrentFile(){\n  if(!state.current||state.current.binary)return;\n  const f=state.files.get(state.current.path);\n  f.content=textToArray(state.current.content);\n  state.current.originalContent=f.content;\n  updateSaveBtn();\n  toast('已保存到浏览器内存','success');\n}\n\nfunction removeCurrentFile(){\n  if(!state.current)return;\n  if(!confirm('从浏览器中删除此文件？'))return;\n  state.files.delete(state.current.path);\n  state.current=null;state.originalContent=null;\n  $('editorHeader').classList.add('hidden');\n  renderTree();\n}\n\n// Ctrl+S 快捷键\ndocument.addEventListener('keydown',e=>{if((e.ctrlKey||e.metaKey)&&e.key==='s'&&state.current&&!state.current.binary){e.preventDefault();saveCurrentFile();}});\n\n// ===== Tar.gz 构建（浏览器端） =====\n// 使用 USTAR tar 格式 + CompressionStream gzip\nasync function buildTarGz(files){\n  const blocks=[];\n  for(const [path,file] of files){\n    const content=file.content;\n    const header=buildTarHeader(path,content.length);\n    blocks.push(header);\n    blocks.push(content);\n    // 填充到 512 倍数\n    const remainder=content.length%512;\n    if(remainder>0){\n      const pad=new Uint8Array(512-remainder);\n      blocks.push(pad);\n    }\n  }\n  // 结尾两个零块\n  blocks.push(new Uint8Array(1024));\n  const tar=new Uint8Array(blocks.reduce((s,b)=>s+b.length,0));\n  let offset=0;\n  for(const b of blocks){tar.set(b,offset);offset+=b.length;}\n  // Gzip 压缩\n  const cs=new CompressionStream('gzip');\n  const writer=cs.writable.getWriter();\n  const reader=cs.readable.getReader();\n  writer.write(tar);\n  writer.close();\n  const chunks=[];\n  while(true){\n    const {done,value}=await reader.read();\n    if(done)break;\n    chunks.push(value);\n  }\n  // 合并\n  let total=0;for(const c of chunks)total+=c.length;\n  const gz=new Uint8Array(total);offset=0;\n  for(const c of chunks){gz.set(c,offset);offset+=c.length;}\n  return gz;\n}\n\n// USTAR header (512 bytes)\nfunction buildTarHeader(name, size){\n  const header=new Uint8Array(512);\n  const dv=new DataView(header.buffer);\n\n  // 文件名（前 100 字节）\n  const nameBytes=new TextEncoder().encode(name);\n  // 处理长路径：USTAR 标准不支持 >100 字节，这里简单截断\n  if(nameBytes.length<=100){\n    header.set(nameBytes,0);\n  }else{\n    // 用 GNU 长链接扩展会复杂，这里前 100 字节截断，实际很少超过\n    header.set(nameBytes.subarray(0,100),0);\n  }\n\n  // mode (8 bytes)\n  const mode=toOctal(0o644,7);header.set(mode,100);\n  // uid\n  const uid=toOctal(0,7);header.set(uid,108);\n  // gid\n  const gid=toOctal(0,7);header.set(gid,116);\n  // size (12 bytes)\n  const sizeStr=toOctal(size,11);header.set(sizeStr,124);\n  // mtime (12 bytes)\n  const mtime=toOctal(Math.floor(Date.now()/1000),11);header.set(mtime,136);\n  // checksum 占位（8 bytes）\n  header.set(new Uint8Array(8),148);\n  // typeflag = '0' 普通文件\n  header[156]=0x30; // '0'\n  // magic \"ustar\\0\" (6 bytes)\n  header.set(new TextEncoder().encode('ustar'),257);header[261]=0;\n  // version \"00\" (2 bytes)\n  header.set(new TextEncoder().encode('00'),263);\n\n  // 计算 checksum\n  let checksum=0;\n  for(let i=0;i<512;i++)checksum+=header[i];\n  const checkStr=toOctal(checksum,6);\n  // checksum 后补 null 和空格\n  header.set(checkStr,148);\n  header[148+checkStr.length]=0;\n  header[148+checkStr.length+1]=0x20; // space\n\n  return header;\n}\n\nfunction toOctal(num, width){\n  let str=num.toString(8);\n  const bytes=new TextEncoder().encode(str);\n  const result=new Uint8Array(width+1); // +1 for null terminator\n  result.set(bytes,width-bytes.length);\n  result[result.length-2]=0;result[result.length-1]=0x20; // null + space (tar checksum format)\n  return result;\n}\n\n// ===== 发布 =====\nfunction showPublishModal(){\n  if(state.files.size===0){toast('请先加载文件','error');return;}\n  openModal('publishModal');\n  $('publishStats').textContent=`${state.files.size} 个文件，总大小 ${formatSize([...state.files.values()].reduce((s,f)=>s+f.size,0))}`;\n}\n\nasync function startPublish(){\n  const domain=$('publishDomain').value.trim();\n  if(!domain){toast('请输入域名','error');return;}\n  closeModal('publishModal');\n  switchTab('publish');\n  const logEl=$('publishLog');logEl.textContent='';\n\n  appendLog('info',`打包 ${state.files.size} 个文件为 tar.gz...`);\n\n  // 构建 tar.gz\n  const fileArr=[...state.files.values()].sort((a,b)=>a.path.localeCompare(b.path));\n  const totalSize=fileArr.reduce((s,f)=>s+f.size,0);\n\n  let tarGz;\n  try{tarGz=await buildTarGz(fileArr);}\n  catch(e){appendLog('stderr','构建 tar.gz 失败: '+e.message);return;}\n\n  appendLog('info',`tar.gz 大小 ${formatSize(tarGz.length)}，上传到 ${domain}...`);\n\n  // 发送给 Worker\n  const resp=await fetch('/api/surge/publish?domain='+encodeURIComponent(domain),{\n    method:'POST',\n    headers:{\n      'Content-Type':'application/gzip',\n      'x-project-size':String(totalSize),\n      'x-file-count':String(fileArr.length),\n      'x-client-version':'surge-gui-worker-v1'\n    },\n    body:tarGz\n  });\n\n  if(!resp.ok||!resp.body){\n    appendLog('stderr','上传失败 '+resp.status);return;\n  }\n\n  // 流式处理 ndjson\n  const reader=resp.body.getReader();\n  const decoder=new TextDecoder();\n  let buf='';\n\n  while(true){\n    const {done,value}=await reader.read();\n    if(done)break;\n    buf+=decoder.decode(value,{stream:true});\n    // 按行拆分\n    let nlIdx;\n    while((nlIdx=buf.indexOf('\\n'))!==-1){\n      const line=buf.substring(0,nlIdx);buf=buf.substring(nlIdx+1);\n      if(!line.trim())continue;\n      let obj;try{obj=JSON.parse(line);}catch{continue;}\n      handleSurgeLine(obj);\n    }\n  }\n}\n\nfunction handleSurgeLine(obj){\n  const t=obj.type||'';\n  if(t==='progress'){\n    const pct=obj.total?Math.round(obj.written/obj.total*100):0;\n    appendLog('stdout',`[${obj.id||'?'}] ${pct}% (${obj.written}/${obj.total})`);\n  }else if(t==='info'){\n    appendLog('exit-ok','\\n✅ 发布成功！');\n    if(obj.urls)appendLog('exit-ok','可访问: '+obj.urls.join(', '));\n  }else if(t==='cert'){\n    appendLog('stdout',`🔐 证书: ${obj.data?.issuer||'?'}`);\n  }else if(t==='error'){\n    appendLog('exit-fail','❌ 错误: '+(obj.error?.message||JSON.stringify(obj)));\n  }else if(t==='ratelimited'){\n    appendLog('exit-fail','⏱️ 限流: '+obj);\n  }else if(t==='forbidden'){\n    appendLog('exit-fail','🚫 禁止: '+obj);\n  }else if(t==='collect'){\n    appendLog('stderr',`💳 需要订阅: ${obj.plan?.name||'?'}`);\n  }else if(t==='msg'){\n    appendLog(obj.payload?.status==='error'?'stderr':'stdout',obj.payload?.msg||'');\n  }else{\n    appendLog('stdout',JSON.stringify(obj));\n  }\n}\n\nfunction appendLog(cls,text){const el=$('publishLog');const d=document.createElement('div');d.className=cls;d.textContent=text;el.appendChild(d);el.scrollTop=el.scrollHeight;}\n\n// ===== 站点管理 =====\nfunction showManageModal(){openModal('manageModal');loadSites();}\n\nasync function loadSites(){\n  $('sitesList').innerHTML='<div class=\"text-center text-gray-400 py-4\">加载中...</div>';\n  const r=await api('GET','/api/surge/list');\n  if(!r.ok&&!Array.isArray(r)){\n    $('sitesList').innerHTML='<div class=\"text-red-500 text-sm\">❌ 获取失败</div>';return;\n  }\n  const list=Array.isArray(r)?r:(r.projects||r.list||r.data||[]);\n  if(!list.length){$('sitesList').innerHTML='<div class=\"text-center text-gray-400 py-4\">暂无站点</div>';return;}\n  $('sitesList').innerHTML=list.map(p=>`\n    <div class=\"flex items-center gap-2 p-2 rounded border border-gray-200 hover:bg-gray-50\">\n      <span class=\"text-sm font-mono flex-1\">🌐 ${p.domain}</span>\n      <span class=\"text-xs text-gray-500\">${p.timeAgoInWords||''}</span>\n      <a href=\"https://${p.domain}\" target=\"_blank\" class=\"btn btn-secondary text-xs py-1 px-2\">访问</a>\n      <button class=\"btn btn-danger text-xs py-1 px-2\" onclick=\"teardownSite('${p.domain}')\">下线</button>\n    </div>\n  `).join('');\n}\n\nasync function teardownSite(domain){\n  if(!confirm(\\`⚠️ 下线 ${domain} ？\\n\\n域名将不再指向你的站点，此操作不可撤销。确定吗？\\`))return;\n  const r=await api('POST','/api/surge/teardown?domain='+encodeURIComponent(domain));\n  toast(r.ok?'已下线':'下线失败',r.ok?'success':'error');\n  if(r.ok)loadSites();\n}\n\n// ===== Tab 切换 =====\nfunction switchTab(name){\n  const editor=name==='editor';\n  $('panel-editor').classList.toggle('hidden',!editor);\n  $('panel-publish').classList.toggle('hidden',editor);\n  const tabs=['tab-editor','tab-publish'];\n  tabs.forEach(t=>{const isActive=(t==='tab-editor')===editor;$(t).className=isActive?'px-4 py-2.5 text-sm font-medium border-b-2 border-blue-500 text-blue-600':'px-4 py-2.5 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700';});\n}\n\n// ===== 启动 =====\ncheckLogin();\n\n// 拖拽支持\ndocument.addEventListener('dragenter',e=>{if(e.dataTransfer&&[...e.dataTransfer.types].includes('Files'))document.body.classList.add('dropzone-drag');});\ndocument.addEventListener('dragleave',()=>document.body.classList.remove('dropzone-drag'));\ndocument.addEventListener('drop',e=>{document.body.classList.remove('dropzone-drag');e.preventDefault();});\n$('dropzone').addEventListener('dragover',e=>{e.preventDefault();$('dropzone').classList.add('dropzone-drag');});\n$('dropzone').addEventListener('dragleave',()=>$('dropzone').classList.remove('dropzone-drag'));\n$('dropzone').addEventListener('drop',async e=>{\n  e.preventDefault();$('dropzone').classList.remove('dropzone-drag');\n  const items=e.dataTransfer.items;\n  if(!items)return;\n  const files=[];\n  for(const it of items){if(it.kind==='file')files.push(it.getAsFile());}\n  // 检查是否 zip\n  const zipFile=files.find(f=>f.name.toLowerCase().endsWith('.zip'));\n  if(zipFile){\n    const bytes=new Uint8Array(await zipFile.arrayBuffer());\n    const zip=await JSZip.loadAsync(bytes);\n    let count=0;\n    for(const [path,entry] of Object.entries(zip.files)){\n      if(entry.dir)continue;\n      const b=await entry.async('uint8array');\n      addFile(path,{name:path.split('/').pop(),path,content:b,binary:!isTextContent(b,path.split('/').pop()),size:b.length});\n      count++;\n    }\n    toast(`解压 ${count} 个文件`,'success');renderTree();return;\n  }\n  // 文件夹或散文件\n  for(const f of files){\n    const path=f.webkitRelativePath||f.name;\n    if(!path)continue;\n    const bytes=new Uint8Array(await f.arrayBuffer());\n    addFile(path,{name:f.name,path,content:bytes,binary:!isTextContent(bytes,f.name),size:bytes.length});\n  }\n  toast(`加载 ${files.length} 个文件`,'success');renderTree();\n});\n</script>\n</body>\n</html>"
  ].join('');
}