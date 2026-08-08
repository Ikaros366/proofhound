// ProofHound M5b 控制台：fetch 封装 + DOM 工具（零依赖，原生 ES2020+）。
//
// 安全纪律（与本控制台全局约定）：
// - 本前端只是 M5a API 的消费者：零业务逻辑、零命令构造；
// - 任何后端数据/用户输入只允许经 textContent 进入 DOM（禁 HTML 字符串注入），
//   本文件的 el() 是唯一造节点入口；
// - 不使用任何 Web 存储（localStorage/sessionStorage/cookie 读写均无）。

export async function api(path, { method = 'GET', body } = {}) {
  const opts = { method, headers: {} };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const resp = await fetch(path, opts);
  const ct = resp.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await resp.json() : await resp.text();
  if (!resp.ok) {
    const detail = data && data.detail;
    // 两种错误形态：自定义 ApiError 为 {error, message}；FastAPI 请求校验
    // （如 cookie 格式 422）为 [{msg, loc, ...}] 数组——数组形态逐条取 msg，
    // 去掉 Pydantic 的 "Value error, " 前缀，让用户看到真正原因
    let msg = detail && detail.message;
    if (!msg && Array.isArray(detail)) {
      msg = detail
        .map((d) => d && typeof d.msg === 'string' ? d.msg.replace(/^Value error,\s*/, '') : '')
        .filter(Boolean)
        .join('；');
    }
    const err = new Error(msg || `HTTP ${resp.status}`);
    err.status = resp.status;
    err.code = detail && detail.error;
    throw err;
  }
  return data;
}

// 造节点：文本一律走 textContent（XSS 防线，本控制台不做 HTML 字符串拼接渲染）
export function el(tag, cls, text) {
  const node = document.createElement(tag);
  if (cls) node.className = cls;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

export function errorBox(err) {
  const msg = err && err.message ? err.message : String(err);
  const box = el('div', 'error-box', msg);
  if (err && err.code) box.dataset.code = err.code;
  return box;
}

// ISO(UTC) → 'MM-dd HH:mm:ss' 本地时间
export function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  const p = (n) => String(n).padStart(2, '0');
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function shortSha(sha) {
  return sha ? String(sha).slice(0, 12) : '—';
}
