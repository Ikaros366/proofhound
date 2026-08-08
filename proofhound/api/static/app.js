// ProofHound M5b 控制台主逻辑（零依赖，原生 ES2020+，无构建链）。
//
// 安全纪律（红线自查依据）：
// - 本前端只是 M5a API 的消费者：零业务逻辑、零命令构造——风险等级、闸门
//   矩阵、状态机状态、findings 全部来自后端响应，前端不做任何裁定；
// - 任何后端数据/用户输入只经 textContent 进入 DOM（见 api.js el()），
//   全文无 HTML 字符串拼接渲染——安全工具自己的 XSS 不能先出事；
// - cookie 只在创建表单提交时流向 POST /api/engagements：不缓存、不回显、
//   不写任何 Web 存储，提交后立即清空输入框。
import { api, el, errorBox, fmtTime, shortSha } from '/static/api.js';

const POLL_MS = 2500; // 轮询间隔；页面不可见时暂停（document.hidden 检查）
const AUDIT_TAIL = 150;
const EVIDENCE_LINE_CAP = 20000; // 证据文件渲染行数软上限（防巨文件卡死）

// 自治模式展示文案（与后端 AutonomyMode 同源；裁定/审计一律在后端，
// MODE_STRICTNESS 仅用于决定切换时是否弹 operator 确认框）
const MODES = [
  { value: 'supervised', label: '监督', desc: 'L1/L2 动作逐条人工确认' },
  { value: 'semi_auto', label: '半自动（默认）', desc: 'L0/L1 自动执行，L2 利用验证需确认' },
  { value: 'unattended', label: '无人值守', desc: '全自动；启动即视为签署本次授权' },
];
const MODE_STRICTNESS = { supervised: 0, semi_auto: 1, unattended: 2 };
const MODE_LABEL = Object.fromEntries(MODES.map((m) => [m.value, m.label]));

const STATE_LABEL = {
  created: '已创建', scanning: '扫描中', triaging: '分诊中', verifying: '验证中',
  confirming: '待确认', done: '完成', failed: '失败',
};
const FINDING_STATE_LABEL = {
  signal: 'Signal', hypothesis: 'Hypothesis', reproduced: 'Reproduced',
  confirmed: 'Confirmed', rejected: 'Rejected',
};
const SEVERITY_LABEL = { critical: '严重', high: '高', medium: '中', low: '低', info: '提示' };
const FINDING_STATE_ORDER = { confirmed: 0, reproduced: 1, hypothesis: 2, signal: 3, rejected: 4 };
const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const FALLBACK_TEMPLATES = ['default_template.docx', 'custom_enterprise_template.docx'];

let poller = null;
let confirmTimeoutSec = 300; // 启动时从 /api/health 取真实值，取不到回退 300

// ---- 轮询引擎：2.5s 间隔，页面不可见暂停，切视图即停 ----

function stopPoller() {
  if (poller) { poller.stop(); poller = null; }
}

function startPoller(fn) {
  stopPoller();
  let stopped = false;
  let timer = null;
  let inFlight = false;
  const tick = async () => {
    if (stopped) return;
    if (document.hidden) { schedule(); return; } // 不可见时暂停
    if (!inFlight) {
      inFlight = true;
      try { await fn(); } catch (err) { console.error('轮询失败', err); }
      inFlight = false;
    }
    schedule();
  };
  const schedule = () => { if (!stopped) timer = setTimeout(tick, POLL_MS); };
  poller = { stop() { stopped = true; if (timer) clearTimeout(timer); } };
  tick();
}

// ---- 路由（hash）----

function route() {
  stopPoller();
  const hash = location.hash || '#/';
  const view = document.getElementById('view');
  view.replaceChildren();
  document.querySelectorAll('#sidenav a').forEach((a) => {
    const nav = a.dataset.nav;
    const active = nav === 'list'
      ? hash === '#/' || hash.startsWith('#/engagement/')
      : hash === `#/${nav}`;
    a.classList.toggle('active', active);
  });
  const m = hash.match(/^#\/engagement\/([A-Za-z0-9-]+)$/);
  if (m) renderDetail(view, m[1]);
  else if (hash === '#/health') renderHealth(view);
  else if (hash === '#/skills') renderSkills(view);
  else if (hash === '#/scopes') renderScopes(view);
  else renderList(view);
}

// ---- ① 任务列表 / 创建 ----

function renderList(view) {
  const errSlot = el('div');

  // -- 创建表单 --
  const formPanel = el('div', 'panel');
  formPanel.appendChild(el('h3', null, '创建任务'));
  const grid = el('div', 'create-grid');

  const targetInput = el('input');
  targetInput.type = 'text';
  targetInput.placeholder = '目标 URL / IP / 域名（须在 scope 授权内）';
  grid.appendChild(field('目标 target', targetInput));

  const budgetInput = el('input');
  budgetInput.type = 'number';
  budgetInput.min = '0';
  budgetInput.placeholder = '留空 = 不限；0 = 拒绝一切 LLM 调用';
  grid.appendChild(field('token 预算（可选）', budgetInput));

  const scopeSelect = el('select');
  scopeSelect.multiple = true;
  scopeSelect.size = 3;
  grid.appendChild(field('scope 授权文件（多选；数据源为「授权」视图的 scopes/ 目录）', scopeSelect, 'full'));
  // 下拉数据源：GET /api/scopes（进视图拉一次；无效文件不列为可选项）
  api('/api/scopes').then((data) => {
    const scopes = (data.scopes || []).filter((s) => s.valid !== false);
    scopeSelect.replaceChildren();
    scopes.forEach((s) => {
      const opt = el('option', null, s.name);
      opt.value = s.name;
      scopeSelect.appendChild(opt);
    });
    if (!scopes.length) {
      const opt = el('option', null, '（无可用 scope，请先在「授权」视图新建）');
      opt.disabled = true;
      scopeSelect.appendChild(opt);
    }
  }).catch(() => { /* 拉取失败留空：提交时后端照常校验（422/403） */ });

  const cookieInput = el('input');
  cookieInput.type = 'password';
  cookieInput.autocomplete = 'off';
  cookieInput.placeholder = 'k=v; k=v（可选预置会话；提交后界面不再出现）';
  grid.appendChild(field('会话 Cookie（可选）', cookieInput, 'full'));

  // 报告 extras（可选，写 engagement.json 透传进模板；自定义企业模板封面三件套）
  const extrasInputs = [
    ['company_name', '单位名称（可选）', '报告 extras：company_name'],
    ['system_name', '系统名称（可选）', '报告 extras：system_name'],
    ['report_date', '报告日期（可选）', '报告 extras：如 2026年8月'],
  ].map(([key, label, placeholder]) => {
    const input = el('input');
    input.type = 'text';
    input.placeholder = placeholder;
    grid.appendChild(field(label, input));
    return [key, input];
  });

  const modeRow = el('div', 'mode-cards');
  let selectedMode = 'semi_auto';
  const modeCards = MODES.map((m) => {
    const card = el('div', 'mode-card' + (m.value === selectedMode ? ' selected' : ''));
    card.appendChild(el('div', 'mode-name', m.label));
    card.appendChild(el('div', 'mode-desc', m.desc));
    card.addEventListener('click', () => {
      selectedMode = m.value;
      modeCards.forEach((c) => c.classList.toggle('selected', c === card));
    });
    modeRow.appendChild(card);
    return card;
  });
  const modeWrap = el('div', 'full');
  modeWrap.appendChild(el('span', null, '自主模式'));
  modeWrap.classList.add('field');
  modeWrap.appendChild(modeRow);
  grid.appendChild(modeWrap);

  const runCheck = el('input');
  runCheck.type = 'checkbox';
  runCheck.checked = true;
  const runLabel = el('label', 'field full');
  runLabel.appendChild(runCheck);
  runLabel.appendChild(document.createTextNode(' 创建后立即启动'));
  grid.appendChild(runLabel);

  formPanel.appendChild(grid);
  const submitBtn = el('button', 'primary', '创建任务');
  formPanel.appendChild(submitBtn);
  formPanel.appendChild(errSlot);

  // -- 列表 --
  const listPanel = el('div', 'panel');
  listPanel.appendChild(el('h3', null, '任务列表'));
  const listBody = el('div', null, '加载中…');
  listPanel.appendChild(listBody);

  view.append(formPanel, listPanel);

  submitBtn.addEventListener('click', async () => {
    errSlot.replaceChildren();
    const body = {
      target: targetInput.value.trim(),
      // 选中名映射为 scopes/ 下路径（API 契约不变）
      scope_paths: Array.from(scopeSelect.selectedOptions).map((o) => `scopes/${o.value}`),
      autonomy_mode: selectedMode,
    };
    if (!body.scope_paths.length) {
      errSlot.replaceChildren(el('div', 'error-box', '请至少选择一个 scope 授权文件（可在「授权」视图新建）'));
      return;
    }
    const cookie = cookieInput.value;
    if (cookie.trim()) body.cookie = cookie;
    const extras = {};
    extrasInputs.forEach(([key, input]) => {
      if (input.value.trim()) extras[key] = input.value.trim();
    });
    if (Object.keys(extras).length) body.extras = extras;
    if (budgetInput.value.trim() !== '') body.budget = Number(budgetInput.value);
    // cookie 纪律：提交后立即清空，不缓存、不回显、不写任何存储
    cookieInput.value = '';
    submitBtn.disabled = true;
    try {
      const eng = await api('/api/engagements', { method: 'POST', body });
      if (runCheck.checked) {
        try {
          await api(`/api/engagements/${eng.id}/run`, { method: 'POST' });
        } catch (runErr) {
          window.alert(`已创建，但启动失败：${runErr.message}`);
        }
      }
      location.hash = `#/engagement/${eng.id}`;
    } catch (err) {
      errSlot.replaceChildren(errorBox(err));
    } finally {
      submitBtn.disabled = false;
    }
  });

  async function refresh() {
    const data = await api('/api/engagements');
    const engagements = data.engagements || [];
    // token 用量列表端点不含：逐行补拉详情（本地少量 engagement，可接受）
    const details = await Promise.all(
      engagements.map((e) => api(`/api/engagements/${e.id}`).catch(() => null))
    );
    const tokensById = {};
    details.forEach((d) => { if (d) tokensById[d.id] = d.tokens_used; });

    if (!engagements.length) {
      listBody.replaceChildren(el('div', 'hint', '暂无任务，先在上方创建。'));
      return;
    }
    const table = el('table', 'data');
    const head = el('tr');
    ['ID', '目标', '状态', '自主模式', 'Findings 确/假/拒', 'Tokens', '创建时间'].forEach((h) =>
      head.appendChild(el('th', null, h))
    );
    table.appendChild(el('thead')).appendChild(head);
    const tbody = el('tbody');
    engagements.slice().reverse().forEach((e) => {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', e.id.replace(/^eng-/, '').slice(0, 20)));
      const targetTd = el('td', null, e.target);
      targetTd.style.wordBreak = 'break-all';
      tr.appendChild(targetTd);
      tr.appendChild(badgeCell(`badge state-${e.state}`, STATE_LABEL[e.state] || e.state));
      tr.appendChild(el('td', null, MODE_LABEL[e.autonomy_mode] || e.autonomy_mode));
      const f = e.findings || {};
      const fTd = el('td');
      fTd.appendChild(el('span', 'badge decision-auto', String(f.confirmed ?? 0)));
      fTd.appendChild(document.createTextNode(' / '));
      fTd.appendChild(el('span', 'badge decision-confirm', String(f.hypothesis ?? 0)));
      fTd.appendChild(document.createTextNode(' / '));
      fTd.appendChild(el('span', 'badge decision-forbidden', String(f.rejected ?? 0)));
      tr.appendChild(fTd);
      tr.appendChild(el('td', 'mono', tokensById[e.id] ?? '…'));
      tr.appendChild(el('td', null, fmtTime(e.created_at)));
      tr.addEventListener('click', () => { location.hash = `#/engagement/${e.id}`; });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listBody.replaceChildren(table);
  }

  startPoller(async () => {
    try { await refresh(); } catch (err) {
      listBody.replaceChildren(errorBox(err));
    }
  });
}

function field(label, input, extraCls) {
  const wrap = el('label', 'field' + (extraCls ? ' ' + extraCls : ''));
  wrap.appendChild(el('span', null, label));
  wrap.appendChild(input);
  return wrap;
}

function badgeCell(cls, text) {
  const td = el('td');
  td.appendChild(el('span', cls, text));
  return td;
}

// ---- ② 任务详情 ----

function renderDetail(view, engId) {
  const st = {
    lastDetail: null,
    statusSig: null,
    confsSig: null,
    findingsSig: null,
    auditTotal: -1,
    loosen: null,           // {mode, operator, note} 放宽切换表单
    confInputs: {},         // cid -> {operator, note}（轮询重建时保留输入）
    deciding: false,
    expanded: null,         // 展开证据包的 finding id
    evidence: {},           // fid -> {data?, error?}
    files: {},              // `${fid}/${file}` -> {text, truncated} | {error}
    selected: null,         // {fid, file, anchor}
    scrollKey: null,
    building: false,
    reportResult: null,
    updateReportBtn: null,
  };

  const backLink = el('a', 'back-link', '← 返回任务列表');
  backLink.href = '#/';
  const title = el('h2', null, engId);
  const errSlot = el('div');
  const statusPanel = el('div', 'panel');
  const statusBar = el('div', 'statusbar');
  const loosenSlot = el('div');
  statusPanel.append(statusBar, loosenSlot);
  const confPanel = el('div', 'panel');
  confPanel.id = 'conf-panel';
  const findingsPanel = el('div', 'panel');
  const reportPanel = el('div', 'panel');
  const auditPanel = el('div', 'panel');
  view.append(backLink, title, errSlot, statusPanel, confPanel, findingsPanel, reportPanel, auditPanel);

  setupReportPanel(reportPanel, engId, st);

  async function refresh() {
    const [detail, confs, findings, audit] = await Promise.all([
      api(`/api/engagements/${engId}`),
      api(`/api/engagements/${engId}/confirmations`),
      api(`/api/engagements/${engId}/findings`),
      api(`/api/engagements/${engId}/audit?tail=${AUDIT_TAIL}`),
    ]);
    errSlot.replaceChildren();
    st.lastDetail = detail;
    title.textContent = detail.target;
    updateStatusBar(detail);
    updateConfirmations(confs.confirmations || []);
    updateFindings(findings.findings || []);
    updateAudit(audit);
  }

  // -- 顶部状态条（签名不变则不重建，避免打断放宽切换表单）--
  function updateStatusBar(detail) {
    const sig = JSON.stringify([
      detail.state, detail.autonomy_mode, detail.tokens_used,
      detail.budget, detail.running, detail.pending_confirmations,
    ]);
    if (sig !== st.statusSig) {
      st.statusSig = sig;
      statusBar.replaceChildren();
      statusBar.appendChild(el('span', `badge big-state state-${detail.state}`,
        STATE_LABEL[detail.state] || detail.state));
      statusBar.appendChild(statusItem('ID', detail.id));
      statusBar.appendChild(statusItem('Tokens',
        `${detail.tokens_used} / ${detail.budget === null ? '不限' : detail.budget}`));
      if (detail.pending_confirmations > 0) {
        statusBar.appendChild(statusItem('待确认', `${detail.pending_confirmations} 项`));
      }
      if (detail.running) statusBar.appendChild(el('span', 'hint', '执行线程运行中'));

      const switcher = el('span', 'mode-switch');
      switcher.appendChild(el('span', 'hint', '自主模式:'));
      MODES.forEach((m) => {
        const btn = el('button', m.value === detail.autonomy_mode ? 'active' : '', m.label);
        btn.addEventListener('click', () => onModeClick(m.value));
        switcher.appendChild(btn);
      });
      statusBar.appendChild(switcher);

      if (detail.state === 'created') {
        const runBtn = el('button', 'primary', '启动');
        runBtn.addEventListener('click', async () => {
          runBtn.disabled = true;
          try { await api(`/api/engagements/${engId}/run`, { method: 'POST' }); await refresh(); }
          catch (err) { errSlot.replaceChildren(errorBox(err)); runBtn.disabled = false; }
        });
        statusBar.appendChild(runBtn);
      }
    }
    if (st.updateReportBtn) st.updateReportBtn();
  }

  function statusItem(k, v) {
    const span = el('span', 'status-item');
    span.appendChild(document.createTextNode(`${k} `));
    span.appendChild(el('b', null, v));
    return span;
  }

  // 放宽切换弹确认框（收紧直接切换）；裁定与审计在后端
  function onModeClick(mode) {
    const cur = st.lastDetail.autonomy_mode;
    if (mode === cur) return;
    if (MODE_STRICTNESS[mode] > MODE_STRICTNESS[cur]) {
      st.loosen = { mode, operator: '', note: '' };
      renderLoosenForm();
    } else {
      doSwitch(mode, null, '');
    }
  }

  function renderLoosenForm() {
    loosenSlot.replaceChildren();
    const box = el('div', 'loosen-form');
    box.appendChild(el('div', 'warn',
      `放宽自治模式（${MODE_LABEL[st.lastDetail.autonomy_mode]} → ${MODE_LABEL[st.loosen.mode]}）` +
      '需要显式 operator 确认，切换将写审计 autonomy_mode_changed。'));
    const row = el('div', 'row');
    const opInput = el('input');
    opInput.type = 'text';
    opInput.placeholder = 'operator（必填，审计落款）';
    const noteInput = el('input');
    noteInput.type = 'text';
    noteInput.placeholder = '备注（可选）';
    opInput.addEventListener('input', () => { st.loosen.operator = opInput.value; confirmBtn.disabled = !opInput.value.trim(); });
    noteInput.addEventListener('input', () => { st.loosen.note = noteInput.value; });
    row.append(opInput, noteInput);
    const confirmBtn = el('button', 'primary', '确认切换');
    confirmBtn.disabled = true;
    const cancelBtn = el('button', '', '取消');
    cancelBtn.addEventListener('click', () => { st.loosen = null; loosenSlot.replaceChildren(); });
    confirmBtn.addEventListener('click', async () => {
      confirmBtn.disabled = true;
      await doSwitch(st.loosen.mode, st.loosen.operator.trim(), st.loosen.note.trim());
    });
    const btnRow = el('div', 'row');
    btnRow.append(confirmBtn, cancelBtn);
    box.append(row, btnRow);
    loosenSlot.appendChild(box);
    opInput.focus();
  }

  async function doSwitch(mode, operator, note) {
    try {
      const body = operator ? { mode, operator, note } : { mode };
      await api(`/api/engagements/${engId}/autonomy`, { method: 'POST', body });
      st.loosen = null;
      loosenSlot.replaceChildren();
      await refresh();
    } catch (err) {
      errSlot.replaceChildren(errorBox(err));
    }
  }

  // -- 确认队列面板（视觉优先级最高；cid 集合不变则不重建，倒计时每次更新）--
  function updateConfirmations(confs) {
    if (confPanel.childElementCount === 0) confPanel.appendChild(el('h3', null, '确认队列'));
    const sig = confs.map((c) => c.cid).join('|');
    if (sig !== st.confsSig) {
      st.confsSig = sig;
      [...confPanel.querySelectorAll('.conf-card, .conf-empty')].forEach((n) => n.remove());
      confPanel.classList.toggle('has-pending', confs.length > 0);
      if (!confs.length) {
        confPanel.appendChild(el('div', 'hint conf-empty', '无待确认动作。'));
      }
      confs.forEach((c) => confPanel.appendChild(confCard(c)));
    }
    confs.forEach((c) => {
      const span = confPanel.querySelector(`[data-countdown="${c.cid}"]`);
      if (span) {
        const { text, urgent } = countdownText(c.created_at);
        span.textContent = text;
        span.classList.toggle('urgent', urgent);
      }
    });
  }

  function countdownText(createdAt) {
    const deadline = Date.parse(createdAt) + confirmTimeoutSec * 1000;
    const left = Math.round((deadline - Date.now()) / 1000);
    if (Number.isNaN(left)) return { text: '', urgent: false };
    if (left <= 0) return { text: '已超时，系统将默认拒绝', urgent: true };
    const m = Math.floor(left / 60);
    const s = String(left % 60).padStart(2, '0');
    return { text: `剩余 ${m}:${s}`, urgent: left < 60 };
  }

  function confCard(c) {
    const card = el('div', 'conf-card');
    const head = el('div', 'conf-head');
    head.appendChild(el('span', `badge risk-${c.risk_level}`, c.risk_level));
    head.appendChild(el('span', 'mono', c.action));
    head.appendChild(el('span', 'hint', c.cid));
    head.appendChild(el('span', 'conf-countdown', ''));
    head.lastChild.dataset.countdown = c.cid;
    card.appendChild(head);
    card.appendChild(el('div', 'conf-summary', c.summary));
    const meta = [];
    if (c.target) meta.push(`target: ${c.target}`);
    if (c.finding_id) meta.push(`finding: ${c.finding_id}`);
    card.appendChild(el('div', 'conf-meta', meta.join(' · ')));

    if (!st.confInputs[c.cid]) st.confInputs[c.cid] = { operator: '', note: '' };
    const inputs = st.confInputs[c.cid];
    const actions = el('div', 'conf-actions');
    const opInput = el('input');
    opInput.type = 'text';
    opInput.placeholder = 'operator（必填）';
    opInput.value = inputs.operator;
    opInput.addEventListener('input', () => { inputs.operator = opInput.value; });
    const noteInput = el('input');
    noteInput.type = 'text';
    noteInput.placeholder = '备注（可选，进审计）';
    noteInput.value = inputs.note;
    noteInput.addEventListener('input', () => { inputs.note = noteInput.value; });
    const opWrap = el('label'); opWrap.appendChild(el('span', null, 'operator')); opWrap.appendChild(opInput);
    const noteWrap = el('label'); noteWrap.appendChild(el('span', null, '备注')); noteWrap.appendChild(noteInput);
    const approveBtn = el('button', 'success', '批准');
    const rejectBtn = el('button', 'danger', '拒绝');
    approveBtn.addEventListener('click', () => decide(c.cid, true, card));
    rejectBtn.addEventListener('click', () => decide(c.cid, false, card));
    actions.append(opWrap, noteWrap, approveBtn, rejectBtn);
    card.appendChild(actions);
    return card;
  }

  async function decide(cid, approved, card) {
    const inputs = st.confInputs[cid] || { operator: '', note: '' };
    if (!inputs.operator.trim()) {
      card.appendChild(el('div', 'error-box', 'operator 必填（审计落款）'));
      return;
    }
    if (st.deciding) return;
    st.deciding = true;
    try {
      await api(`/api/confirmations/${cid}/${approved ? 'approve' : 'reject'}`, {
        method: 'POST',
        body: { operator: inputs.operator.trim(), note: inputs.note.trim() },
      });
      delete st.confInputs[cid];
      await refresh();
    } catch (err) {
      card.appendChild(errorBox(err));
    } finally {
      st.deciding = false;
    }
  }

  // -- Findings 看板 --
  function updateFindings(findings) {
    st.lastFindings = findings;
    renderFindings();
  }

  function renderFindings() {
    const findings = st.lastFindings || [];
    const sig = JSON.stringify([
      findings.map((f) => [f.id, f.state, f.updated_at]),
      st.expanded,
      Object.keys(st.evidence), Object.keys(st.files), st.selected,
    ]);
    if (sig === st.findingsSig) return;
    st.findingsSig = sig;
    findingsPanel.replaceChildren();
    findingsPanel.appendChild(el('h3', null, `Findings（${findings.length}）`));
    if (!findings.length) {
      findingsPanel.appendChild(el('div', 'hint', '尚无 Finding（triage 产出后在此呈现，含 rejected）。'));
      return;
    }
    const sorted = findings.slice().sort((a, b) =>
      (FINDING_STATE_ORDER[a.state] ?? 9) - (FINDING_STATE_ORDER[b.state] ?? 9) ||
      (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) ||
      a.id.localeCompare(b.id)
    );
    sorted.forEach((f) => findingsPanel.appendChild(findingCard(f)));
  }

  function findingCard(f) {
    const card = el('div', 'finding-card' + (f.state === 'rejected' ? ' rejected' : ''));
    const head = el('div', 'finding-head');
    head.appendChild(el('span', `badge fs-${f.state}`, FINDING_STATE_LABEL[f.state] || f.state));
    head.appendChild(el('span', `badge sev-${f.severity}`, SEVERITY_LABEL[f.severity] || f.severity));
    head.appendChild(el('span', 'finding-title', f.title || `${f.vuln_type} @ ${f.param || f.asset}`));
    const toggle = el('button', '', st.expanded === f.id ? '收起证据包' : '证据包');
    toggle.addEventListener('click', () => {
      st.expanded = st.expanded === f.id ? null : f.id;
      if (st.expanded && !st.evidence[f.id]) loadEvidence(f.id);
      renderFindings();
    });
    head.appendChild(toggle);
    card.appendChild(head);

    const meta = el('div', 'finding-meta');
    meta.appendChild(kv('资产', f.asset));
    if (f.param) meta.appendChild(kv('参数', f.param));
    meta.appendChild(kv('类型', f.vuln_type));
    meta.appendChild(kv('置信度', f.confidence));
    if (f.preconditions && f.preconditions.length) meta.appendChild(kv('前置条件', f.preconditions.join('；')));
    card.appendChild(meta);
    if (f.evidence_kinds && f.evidence_kinds.length) {
      const tags = el('div');
      f.evidence_kinds.forEach((k) => tags.appendChild(el('span', 'tag', k)));
      card.appendChild(tags);
    }
    if (f.verification) {
      card.appendChild(el('div', 'finding-verify',
        `验证: ${f.verification.method} · ${f.verification.verified_by || '—'} · ${fmtTime(f.verification.verified_at)}`));
    }
    if (f.verifier) {
      card.appendChild(el('div', 'finding-verifier',
        `Verifier ${f.verifier.model}: ${f.verifier.verdict} — ${f.verifier.reason || ''}`));
    }
    if (f.state === 'rejected' && f.rejection_reason) {
      card.appendChild(el('div', 'finding-reject', `归因: ${f.rejection_reason}`));
    }
    if (st.expanded === f.id) card.appendChild(evidenceContainer(f.id));
    return card;
  }

  function kv(k, v) {
    const span = el('span');
    span.appendChild(el('span', 'k', `${k} `));
    span.appendChild(document.createTextNode(v));
    span.appendChild(document.createTextNode('　'));
    return span;
  }

  // -- 证据包查看器（"出处可调出"的 Web 呈现；不轮询，展开取一次 + 手动刷新）--
  async function loadEvidence(fid) {
    try {
      const data = await api(`/api/engagements/${engId}/findings/${fid}/evidence`);
      st.evidence[fid] = { data };
    } catch (err) {
      st.evidence[fid] = { error: err };
    }
    renderFindings();
  }

  async function loadEvidenceFile(fid, file) {
    const key = `${fid}/${file}`;
    try {
      const resp = await fetch(
        `/api/engagements/${engId}/findings/${fid}/evidence/${encodeURIComponent(file)}`
      );
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
      const text = await resp.text();
      st.files[key] = { text, truncated: resp.headers.get('x-proofhound-truncated') === 'true' };
    } catch (err) {
      st.files[key] = { error: err };
    }
    renderFindings();
  }

  function evidenceContainer(fid) {
    const wrap = el('div', 'evidence');
    const head = el('div', 'conf-head');
    head.appendChild(el('b', null, '证据包'));
    const refreshBtn = el('button', '', '刷新');
    refreshBtn.addEventListener('click', () => {
      delete st.evidence[fid];
      Object.keys(st.files).filter((k) => k.startsWith(`${fid}/`)).forEach((k) => delete st.files[k]);
      loadEvidence(fid);
    });
    head.appendChild(refreshBtn);
    wrap.appendChild(head);

    const ev = st.evidence[fid];
    if (!ev) { wrap.appendChild(el('div', 'hint', '加载中…')); return wrap; }
    if (ev.error) { wrap.appendChild(errorBox(ev.error)); return wrap; }
    if (!ev.data.assembled) { wrap.appendChild(el('div', 'hint', '证据包尚未组装。')); return wrap; }

    const table = el('table', 'data');
    const headRow = el('tr');
    ['证据文件', 'sha256', '出处 source_ref', '锚点'].forEach((h) => headRow.appendChild(el('th', null, h)));
    table.appendChild(el('thead')).appendChild(headRow);
    const tbody = el('tbody');
    ev.data.items.forEach((item) => {
      const tr = el('tr');
      const fileTd = el('td');
      if (item.file) {
        const btn = el('button', 'linkish mono', item.file);
        btn.addEventListener('click', () => {
          st.selected = { fid, file: item.file, anchor: item.line_anchor };
          const key = `${fid}/${item.file}`;
          if (!st.files[key]) loadEvidenceFile(fid, item.file);
          renderFindings();
        });
        fileTd.appendChild(btn);
      } else {
        fileTd.appendChild(el('span', 'badge decision-forbidden', '缺失'));
      }
      tr.appendChild(fileTd);
      const shaTd = el('td', 'mono', shortSha(item.sha256));
      if (item.sha256) shaTd.title = item.sha256;
      tr.appendChild(shaTd);
      const refTd = el('td', 'mono', item.source_ref || '—');
      refTd.style.wordBreak = 'break-all';
      tr.appendChild(refTd);
      tr.appendChild(el('td', 'mono', item.line_anchor ? `L${item.line_anchor}` : '—'));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    wrap.appendChild(table);

    if (st.selected && st.selected.fid === fid) wrap.appendChild(evidenceContent(fid));
    return wrap;
  }

  function evidenceContent(fid) {
    const sel = st.selected;
    const key = `${fid}/${sel.file}`;
    const entry = st.files[key];
    if (!entry) return el('div', 'hint', '加载文件…');
    if (entry.error) return errorBox(entry.error);

    const wrap = el('div', 'ev-content');
    const banner = el('div', 'ev-banner',
      `${sel.file}` +
      (sel.anchor ? ` · 锚点 L${sel.anchor}` : '') +
      (entry.truncated ? ' · ⚠ 文件超过 2 MiB，已截断（完整文件见证据包目录）' : ''));
    wrap.appendChild(banner);

    const allLines = entry.text.split('\n');
    const capped = allLines.length > EVIDENCE_LINE_CAP;
    const lines = capped ? allLines.slice(0, EVIDENCE_LINE_CAP) : allLines;
    if (capped) {
      wrap.appendChild(el('div', 'ev-banner',
        `仅渲染前 ${EVIDENCE_LINE_CAP} 行（共 ${allLines.length} 行）`));
    }
    const linesBox = el('div', 'ev-lines');
    let anchorRow = null;
    lines.forEach((line, i) => {
      const row = el('div', 'ev-line');
      row.appendChild(el('span', 'ln', String(i + 1)));
      row.appendChild(el('span', 'lc', line));
      if (sel.anchor && i + 1 === sel.anchor) {
        row.classList.add('anchor');
        anchorRow = row;
      }
      linesBox.appendChild(row);
    });
    wrap.appendChild(linesBox);
    const scrollKey = `${key}#${sel.anchor || 0}`;
    if (anchorRow && st.scrollKey !== scrollKey) {
      st.scrollKey = scrollKey;
      setTimeout(() => anchorRow.scrollIntoView({ block: 'center' }), 0);
    }
    return wrap;
  }

  // -- 审计流（tail 轮询，total 不变则跳过重绘）--
  function updateAudit(audit) {
    if (audit.total === st.auditTotal) return;
    st.auditTotal = audit.total;
    auditPanel.replaceChildren();
    auditPanel.appendChild(el('h3', null, `审计流（最近 ${audit.events.length} / 共 ${audit.total} 条）`));
    const stream = el('div', 'audit-stream');
    audit.events.slice().reverse().forEach((e) => {
      const row = el('div', 'audit-row');
      row.appendChild(el('span', 'audit-time', fmtTime(e.ts)));
      row.appendChild(el('span', `audit-event ev-color-${e.event}`, e.event));
      row.appendChild(el('span', 'audit-detail', summarizeEvent(e)));
      stream.appendChild(row);
    });
    auditPanel.appendChild(stream);
  }

  startPoller(async () => {
    try { await refresh(); }
    catch (err) { errSlot.replaceChildren(errorBox(err)); }
  });
}

// 审计事件单行摘要（全部走 textContent；命令为后端脱敏后文本）
function summarizeEvent(e) {
  switch (e.event) {
    case 'command_executed':
      return `$ ${e.command} ⇒ exit ${e.exit_code} · stdout ${shortSha(e.stdout_sha256)}`;
    case 'command_rejected':
      return `✗ ${e.command} · ${(e.violations || []).join('; ')}`;
    case 'llm_call':
      return `${e.tier || ''} ${e.model || ''} · tokens ${e.prompt_tokens ?? '?'}+${e.completion_tokens ?? '?'}${e.estimated ? '（估算）' : ''}`;
    case 'finding_state':
      return `${e.finding_id} ${e.from} → ${e.to} · ${e.actor}${e.reason ? ' · ' + e.reason : ''}`;
    case 'engagement_state':
      return `${e.from} → ${e.to}${e.reason ? ' · ' + e.reason : ''}`;
    case 'action_confirmation_requested':
      return `${e.action}（${e.risk_level}）${e.summary ? ' · ' + e.summary : ''}`;
    case 'action_approved':
    case 'action_rejected':
      return `${e.action} · operator=${e.operator}${e.note ? ' · ' + e.note : ''}`;
    case 'action_resumed':
      return `${e.action} · 复用既有批准裁定`;
    case 'autonomy_mode_changed':
      return `${e.from} → ${e.to} · operator=${e.operator || '—'}`;
    case 'scope_recheck':
      return `target=${e.target} allowed=${e.allowed}`;
    case 'llm_budget_exceeded':
    case 'budget_exceeded':
      return `用量 ${e.used ?? '—'} / 上限 ${e.limit ?? '—'}`;
    case 'report_built':
      return `template=${e.template} narrative=${e.narrative}`;
    case 'engagement_created':
      return `target=${e.target} mode=${e.autonomy_mode} budget=${e.budget === null ? '不限' : e.budget}`;
    default: {
      const parts = Object.entries(e)
        .filter(([k, v]) => k !== 'ts' && k !== 'event' && ['string', 'number', 'boolean'].includes(typeof v))
        .map(([k, v]) => `${k}=${v}`);
      return parts.join(' ').slice(0, 300);
    }
  }
}

// -- 报告区 --
function setupReportPanel(panel, engId, st) {
  panel.appendChild(el('h3', null, '报告'));
  const row = el('div', 'conf-actions');
  const tplSelect = el('select');
  const tplWrap = el('label');
  tplWrap.appendChild(el('span', null, '模板'));
  tplWrap.appendChild(tplSelect);
  const narrativeCheck = el('input');
  narrativeCheck.type = 'checkbox';
  const narrativeWrap = el('label');
  narrativeWrap.appendChild(narrativeCheck);
  narrativeWrap.appendChild(document.createTextNode(' 生成 LLM 叙述（T1，耗时较长）'));
  narrativeWrap.style.alignSelf = 'flex-end';
  const buildBtn = el('button', 'primary', '构建报告');
  row.append(tplWrap, narrativeWrap, buildBtn);
  panel.appendChild(row);
  const hintEl = el('div', 'hint');
  const resultSlot = el('div');
  panel.append(hintEl, resultSlot);

  // 模板下拉数据源为后端只读端点；端点异常时回退两份已知模板
  api('/api/templates')
    .then((data) => {
      const names = (data.templates && data.templates.length) ? data.templates : FALLBACK_TEMPLATES;
      tplSelect.replaceChildren();
      names.forEach((n) => {
        const opt = el('option', null, n);
        opt.value = n;
        tplSelect.appendChild(opt);
      });
    })
    .catch(() => {
      tplSelect.replaceChildren();
      FALLBACK_TEMPLATES.forEach((n) => {
        const opt = el('option', null, n);
        opt.value = n;
        tplSelect.appendChild(opt);
      });
    });

  function updateBtn() {
    const detail = st.lastDetail;
    const terminal = detail && (detail.state === 'done' || detail.state === 'failed');
    buildBtn.disabled = st.building || !terminal;
    buildBtn.textContent = st.building ? '构建中…（叙述可能需数十秒）' : '构建报告';
    hintEl.textContent = terminal
      ? '构建成功后提供下载链接；重复构建覆盖既有 report.docx。'
      : '任务到达 done/failed 终态后可构建报告。';
  }
  st.updateReportBtn = updateBtn;
  updateBtn();

  buildBtn.addEventListener('click', async () => {
    st.building = true;
    st.reportResult = null;
    updateBtn();
    resultSlot.replaceChildren(el('div', 'hint', '报告构建中，请勿重复点击…'));
    try {
      const result = await api(`/api/engagements/${engId}/report`, {
        method: 'POST',
        body: { template: tplSelect.value, narrative: narrativeCheck.checked },
      });
      st.reportResult = result;
      const s = result.summary || {};
      const box = el('div', 'ok-box',
        `构建成功：confirmed ${s.confirmed ?? 0} · conditional ${s.conditional ?? 0} · ` +
        `hypothesis ${s.hypothesis ?? 0} · rejected ${s.rejected ?? 0}`);
      const link = el('a', null, `下载 ${result.report || 'report.docx'}`);
      link.href = `/api/engagements/${engId}/report`;
      link.setAttribute('download', '');
      box.appendChild(document.createTextNode(' — '));
      box.appendChild(link);
      resultSlot.replaceChildren(box);
    } catch (err) {
      resultSlot.replaceChildren(errorBox(err));
    } finally {
      st.building = false;
      updateBtn();
    }
  });
}

// ---- ③ 健康页 ----

function renderHealth(view) {
  const panel = el('div', 'panel');
  panel.appendChild(el('h3', null, '服务健康'));
  const gridSlot = el('div');
  panel.appendChild(gridSlot);
  const gatePanel = el('div', 'panel');
  gatePanel.appendChild(el('h3', null, '自主模式闸门矩阵（后端裁定，前端只读展示）'));
  const gateSlot = el('div');
  gatePanel.appendChild(gateSlot);
  view.append(panel, gatePanel);

  async function refresh() {
    const h = await api('/api/health');
    confirmTimeoutSec = h.confirm_timeout || confirmTimeoutSec;
    const grid = el('div', 'health-grid');
    [['状态', h.status], ['服务', h.service], ['版本', h.version || '—'],
     ['确认超时', `${h.confirm_timeout ?? '—'} s`]].forEach(([k, v]) => {
      const item = el('span', 'status-item');
      item.appendChild(document.createTextNode(`${k} `));
      item.appendChild(el('b', null, String(v)));
      grid.appendChild(item);
    });
    gridSlot.replaceChildren(grid);

    const table = el('table', 'data gate-table');
    const head = el('tr');
    ['模式', 'L0 被动', 'L1 主动扫描', 'L2 利用验证'].forEach((t) => head.appendChild(el('th', null, t)));
    table.appendChild(el('thead')).appendChild(head);
    const tbody = el('tbody');
    MODES.forEach((m) => {
      const tr = el('tr');
      tr.appendChild(el('td', null, `${m.label}（${m.value}）`));
      ['L0', 'L1', 'L2'].forEach((level) => {
        const decision = (h.autonomy_gate[m.value] || {})[level] || 'forbidden';
        const td = el('td');
        td.appendChild(el('span', `badge decision-${decision}`, decision));
        tr.appendChild(td);
      });
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    gateSlot.replaceChildren(table);
  }

  startPoller(async () => {
    try { await refresh(); }
    catch (err) { gridSlot.replaceChildren(errorBox(err)); }
  });
}

// ---- ④ Skills 管理（M6a；纯 textarea 编辑，零编辑器库） ----

function renderSkills(view) {
  const listPanel = el('div', 'panel');
  listPanel.appendChild(el('h3', null, 'Skill 列表'));
  const listBody = el('div', null, '加载中…');
  listPanel.appendChild(listBody);

  const uploadPanel = el('div', 'panel');
  uploadPanel.appendChild(el('h3', null, '上传 Skill（zip ≤ 1MiB，单顶层目录含 SKILL.md）'));
  const uploadRow = el('div', 'conf-actions');
  const fileInput = el('input');
  fileInput.type = 'file';
  fileInput.accept = '.zip';
  const uploadBtn = el('button', 'primary', '上传');
  uploadBtn.disabled = true;
  fileInput.addEventListener('change', () => { uploadBtn.disabled = !fileInput.files.length; });
  uploadRow.append(fileInput, uploadBtn);
  const uploadSlot = el('div');
  uploadPanel.append(uploadRow, uploadSlot);

  const editorPanel = el('div', 'panel');
  editorPanel.appendChild(el('h3', null, '编辑器'));
  editorPanel.appendChild(el('div', 'hint', '点击列表行查看 / 编辑 SKILL.md 全文。'));

  view.append(listPanel, uploadPanel, editorPanel);

  async function refresh() {
    const data = await api('/api/skills');
    renderRows(data.skills || []);
  }

  function renderRows(skills) {
    if (!skills.length) {
      listBody.replaceChildren(el('div', 'hint', '暂无 skill。'));
      return;
    }
    const table = el('table', 'data');
    const head = el('tr');
    ['名称', '风险', '工具', '来源', '启用', 'sha256'].forEach((h) => head.appendChild(el('th', null, h)));
    table.appendChild(el('thead')).appendChild(head);
    const tbody = el('tbody');
    skills.forEach((s) => {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', s.name));
      tr.appendChild(badgeCell(`badge risk-${s.risk_level}`, s.risk_level));
      const toolsTd = el('td');
      (s.required_tools || []).forEach((t) => {
        const unknown = (s.unknown_tools || []).includes(t);
        const missing = (s.missing_tools || []).includes(t);
        const tag = el('span', unknown || missing ? 'tag warn' : 'tag', t);
        if (unknown) tag.title = '未知工具（无命令构造器）';
        else if (missing) tag.title = '工具未安装（tools.d 缺失）';
        toolsTd.appendChild(tag);
      });
      tr.appendChild(toolsTd);
      tr.appendChild(badgeCell(
        s.builtin ? 'badge decision-confirm' : 'badge decision-auto',
        s.builtin ? '内置' : '用户'
      ));
      tr.appendChild(el('td', null, s.enabled ? '是' : '否'));
      const shaTd = el('td', 'mono', shortSha(s.sha256));
      shaTd.title = s.sha256 || '';
      tr.appendChild(shaTd);
      tr.addEventListener('click', () => selectSkill(s.name));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listBody.replaceChildren(table);
  }

  async function selectSkill(name) {
    editorPanel.replaceChildren();
    editorPanel.appendChild(el('h3', null, `编辑 ${name}`));
    let detail;
    try { detail = await api(`/api/skills/${encodeURIComponent(name)}`); }
    catch (err) { editorPanel.appendChild(errorBox(err)); return; }
    if (detail.builtin) {
      editorPanel.appendChild(el('div', 'hint',
        '内置 skill 只读；保存将创建 workspace 副本（copy-on-edit），仓库文件不变。'));
    }
    const shaLine = el('div', 'hint', `sha256: ${detail.sha256}`);
    editorPanel.appendChild(shaLine);
    const ta = el('textarea', 'md-editor');
    ta.rows = 22;
    ta.value = detail.content;
    editorPanel.appendChild(ta);
    const slot = el('div');
    const btnRow = el('div', 'conf-actions');
    const saveBtn = el('button', 'primary', '保存');
    const delBtn = el('button', 'danger', '删除');
    delBtn.disabled = detail.builtin;
    if (detail.builtin) delBtn.title = '内置 skill 禁止删除（保存将创建副本）';
    saveBtn.addEventListener('click', async () => {
      saveBtn.disabled = true;
      slot.replaceChildren();
      try {
        const r = await api(`/api/skills/${encodeURIComponent(name)}`, {
          method: 'PUT', body: { content: ta.value },
        });
        shaLine.textContent = `sha256: ${r.sha256}`;
        detail.builtin = false;
        detail.sha256 = r.sha256;
        delBtn.disabled = false;
        delBtn.title = '';
        slot.replaceChildren(el('div', 'ok-box',
          `已保存（sha256 ${shortSha(r.sha256)}${r.copied_from_builtin ? '，已创建 workspace 副本' : ''}）`));
        await refresh();
      } catch (err) {
        slot.replaceChildren(errorBox(err)); // 校验错误原样展示
      } finally { saveBtn.disabled = false; }
    });
    delBtn.addEventListener('click', async () => {
      if (!window.confirm(`确认删除 skill？\nname: ${name}\nsha256: ${detail.sha256}`)) return;
      slot.replaceChildren();
      try {
        await api(`/api/skills/${encodeURIComponent(name)}`, { method: 'DELETE' });
        editorPanel.replaceChildren();
        editorPanel.appendChild(el('h3', null, '编辑器'));
        editorPanel.appendChild(el('div', 'ok-box', `已删除 ${name}`));
        await refresh();
      } catch (err) { slot.replaceChildren(errorBox(err)); }
    });
    btnRow.append(saveBtn, delBtn);
    editorPanel.append(btnRow, slot);
  }

  uploadBtn.addEventListener('click', async () => {
    const file = fileInput.files[0];
    if (!file) return;
    uploadBtn.disabled = true;
    uploadSlot.replaceChildren();
    try {
      const resp = await fetch('/api/skills', {
        method: 'POST',
        headers: { 'Content-Type': 'application/zip' },
        body: file,
      });
      const data = await resp.json().catch(() => ({}));
      if (!resp.ok) {
        const detail = data && data.detail;
        throw Object.assign(
          new Error((detail && detail.message) || `HTTP ${resp.status}`),
          { code: detail && detail.error }
        );
      }
      uploadSlot.replaceChildren(el('div', 'ok-box',
        `已导入 ${data.name}（sha256 ${shortSha(data.sha256)}）`));
      fileInput.value = '';
      await refresh();
    } catch (err) {
      uploadSlot.replaceChildren(errorBox(err));
    } finally { uploadBtn.disabled = !fileInput.files.length; }
  });

  refresh().catch((err) => listBody.replaceChildren(errorBox(err)));
}

// ---- ⑤ Scope 授权文件管理（M6a；同款纯 textarea 纪律） ----

function renderScopes(view) {
  const listPanel = el('div', 'panel');
  listPanel.appendChild(el('h3', null, 'Scope 授权文件（scopes/ 目录）'));
  const listBody = el('div', null, '加载中…');
  listPanel.appendChild(listBody);

  const createPanel = el('div', 'panel');
  createPanel.appendChild(el('h3', null, '新建 Scope'));
  const nameInput = el('input');
  nameInput.type = 'text';
  nameInput.placeholder = '文件名（如 dvwa.yaml；仅字母数字 _ . -）';
  createPanel.appendChild(field('文件名', nameInput));
  const createTa = el('textarea', 'md-editor');
  createTa.rows = 6;
  createTa.placeholder = 'networks: [127.0.0.0/8]\nports: [8080]';
  createPanel.appendChild(field('YAML 内容（允许键：domains / networks / ports）', createTa));
  const createBtn = el('button', 'primary', '新建');
  const createSlot = el('div');
  createPanel.append(createBtn, createSlot);

  const editorPanel = el('div', 'panel');
  editorPanel.appendChild(el('h3', null, '编辑器'));
  editorPanel.appendChild(el('div', 'hint', '点击列表行查看 / 编辑 scope 全文。'));

  view.append(listPanel, createPanel, editorPanel);

  async function refresh() {
    const data = await api('/api/scopes');
    renderRows(data.scopes || []);
  }

  function renderRows(scopes) {
    if (!scopes.length) {
      listBody.replaceChildren(el('div', 'hint', '暂无 scope，请在下方新建。'));
      return;
    }
    const table = el('table', 'data');
    const head = el('tr');
    ['名称', 'networks', 'ports', 'sha256'].forEach((h) => head.appendChild(el('th', null, h)));
    table.appendChild(el('thead')).appendChild(head);
    const tbody = el('tbody');
    scopes.forEach((s) => {
      const tr = el('tr');
      tr.appendChild(el('td', 'mono', s.name));
      if (s.valid === false) {
        tr.classList.add('invalid-row');
        const td = el('td', null, `无效文件：${s.error || ''}`);
        td.colSpan = 2;
        tr.appendChild(td);
      } else {
        tr.appendChild(el('td', 'mono', (s.networks || []).concat(s.domains || []).join(', ') || '—'));
        tr.appendChild(el('td', 'mono', (s.ports || []).join(', ') || '不限'));
      }
      const shaTd = el('td', 'mono', shortSha(s.sha256));
      shaTd.title = s.sha256 || '';
      tr.appendChild(shaTd);
      tr.addEventListener('click', () => selectScope(s.name));
      tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    listBody.replaceChildren(table);
  }

  async function selectScope(name) {
    editorPanel.replaceChildren();
    editorPanel.appendChild(el('h3', null, `编辑 ${name}`));
    let detail;
    try { detail = await api(`/api/scopes/${encodeURIComponent(name)}`); }
    catch (err) { editorPanel.appendChild(errorBox(err)); return; }
    const shaLine = el('div', 'hint', `sha256: ${detail.sha256}`);
    editorPanel.appendChild(shaLine);
    const ta = el('textarea', 'md-editor');
    ta.rows = 12;
    ta.value = detail.content;
    editorPanel.appendChild(ta);
    const slot = el('div');
    const btnRow = el('div', 'conf-actions');
    const saveBtn = el('button', 'primary', '保存');
    const delBtn = el('button', 'danger', '删除');
    saveBtn.addEventListener('click', async () => {
      saveBtn.disabled = true;
      slot.replaceChildren();
      try {
        const r = await api(`/api/scopes/${encodeURIComponent(name)}`, {
          method: 'PUT', body: { content: ta.value },
        });
        shaLine.textContent = `sha256: ${r.sha256}`;
        detail.sha256 = r.sha256;
        slot.replaceChildren(el('div', 'ok-box', `已保存（sha256 ${shortSha(r.sha256)}）`));
        await refresh();
      } catch (err) {
        slot.replaceChildren(errorBox(err)); // 校验错误原样展示
      } finally { saveBtn.disabled = false; }
    });
    delBtn.addEventListener('click', async () => {
      if (!window.confirm(`确认删除 scope 授权文件？\nname: ${name}\nsha256: ${detail.sha256}`)) return;
      slot.replaceChildren();
      try {
        await api(`/api/scopes/${encodeURIComponent(name)}`, { method: 'DELETE' });
        editorPanel.replaceChildren();
        editorPanel.appendChild(el('h3', null, '编辑器'));
        editorPanel.appendChild(el('div', 'ok-box', `已删除 ${name}`));
        await refresh();
      } catch (err) { slot.replaceChildren(errorBox(err)); }
    });
    btnRow.append(saveBtn, delBtn);
    editorPanel.append(btnRow, slot);
  }

  createBtn.addEventListener('click', async () => {
    createSlot.replaceChildren();
    createBtn.disabled = true;
    try {
      const r = await api('/api/scopes', {
        method: 'POST',
        body: { name: nameInput.value.trim(), content: createTa.value },
      });
      createSlot.replaceChildren(el('div', 'ok-box', `已创建 ${r.name}`));
      nameInput.value = '';
      createTa.value = '';
      await refresh();
    } catch (err) {
      createSlot.replaceChildren(errorBox(err)); // 校验错误原样展示
    } finally { createBtn.disabled = false; }
  });

  refresh().catch((err) => listBody.replaceChildren(errorBox(err)));
}

// ---- 启动 ----

window.addEventListener('hashchange', route);
(async () => {
  try {
    const h = await api('/api/health');
    confirmTimeoutSec = h.confirm_timeout || 300;
  } catch (err) { /* 健康检查失败不阻塞首屏，倒计时用回退值 */ }
  route();
})();
