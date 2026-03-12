const state = {
  token: localStorage.getItem('ndr_token') || '',
  user: null,
  modules: [],
  roleTemplates: [],
  currentPage: 'overview',
  currentRoute: { page: 'overview' },
  selectedAlert: null,
  selectedRawAlert: null,
  selectedTicket: null,
  selectedProbe: null,
  selectedAlertIDs: new Set(),
  selectedTicketIDs: new Set(),
  alertPage: 1,
  ticketPage: 1,
  rawAlertPage: 1,
  alertPageSize: 10,
  ticketPageSize: 10,
  rawAlertPageSize: 20,
  exportRefreshTimer: null,
};

const STORAGE_KEYS = {
  alerts: 'ndr_alert_filters',
  rawAlerts: 'ndr_raw_alert_filters',
  tickets: 'ndr_ticket_filters',
  reports: 'ndr_report_filters',
  probes: 'ndr_probe_filters',
  queryStats: 'ndr_query_stats_filters',
};

const MODULES = [
  { id: 'overview', title: '总览', desc: '模块入口和整体视图', permission: null },
  { id: 'alerts', title: '告警中心', desc: '告警筛选、详情和处置', permission: 'alert.read' },
  { id: 'raw-alerts', title: '原始告警检索', desc: '查看未聚合的原始命中事件', permission: 'alert.read' },
  { id: 'flows', title: '流量检索', desc: '独立会话和流量元数据查询', permission: 'alert.read' },
  { id: 'exports', title: '导出中心', desc: '异步导出任务和下载', permission: 'alert.read' },
  { id: 'tickets', title: '工单中心', desc: '工单详情和状态流转', permission: 'ticket.read' },
  { id: 'assets', title: '资产中心', desc: '资产映射和重要度管理', permission: 'asset.read' },
  { id: 'intel', title: '情报中心', desc: 'IP 情报和命中标签管理', permission: 'intel.read' },
  { id: 'policies', title: '策略中心', desc: '抑制规则和风险评分策略', permission: 'policy.read' },
  { id: 'probes', title: '探针管理', desc: '探针、配置模板和规则版本', permission: 'probe.read' },
  { id: 'users', title: '用户管理', desc: '用户创建和角色绑定', permission: 'user.read' },
  { id: 'roles', title: '角色管理', desc: '角色和权限配置', permission: 'role.read' },
  { id: 'reports', title: '报表中心', desc: '趋势统计和 TOP 榜', permission: 'alert.read' },
  { id: 'notifications', title: '通知中心', desc: '通知通道配置和发送记录', permission: 'notify.read' },
  { id: 'query-stats', title: '查询统计', desc: '查询耗时和慢查询观察', permission: 'audit.read' },
  { id: 'audit', title: '审计日志', desc: '登录、处置、配置留痕', permission: 'audit.read' },
];

const ROLE_PROFILES = {
  admin: {
    label: '超级管理员',
    desc: '查看并管理全平台的所有模块、配置和运行状态。',
    modules: MODULES.map((module) => module.id),
    focus: [
      { module: 'probes', title: '探针运行', desc: '查看探针在线、下发和升级状态。', stat: 'probes_online' },
      { module: 'query-stats', title: '查询治理', desc: '关注慢查询、审计和导出行为。', stat: 'tickets_open' },
      { module: 'users', title: '账户权限', desc: '管理用户、角色和数据范围。', stat: 'alerts_closed' },
    ],
  },
  system_admin: {
    label: '系统管理员',
    desc: '负责探针、平台配置、升级、审计和系统运行治理。',
    modules: ['overview', 'probes', 'policies', 'notifications', 'users', 'roles', 'audit', 'query-stats', 'reports'],
    focus: [
      { module: 'probes', title: '探针状态', desc: '优先检查探针在线率、版本和下发结果。', stat: 'probes_online' },
      { module: 'audit', title: '操作审计', desc: '关注配置变更、升级回执和异常操作。', stat: 'alerts_closed' },
      { module: 'query-stats', title: '查询统计', desc: '排查慢查询和导出任务对平台的影响。', stat: 'tickets_open' },
    ],
  },
  security_operator: {
    label: '安全运营人员',
    desc: '负责日常告警确认、关闭、转工单和处置闭环。',
    modules: ['overview', 'alerts', 'raw-alerts', 'tickets', 'reports', 'exports', 'notifications'],
    focus: [
      { module: 'alerts', title: '待研判告警', desc: '先处理高风险、未关闭和重复命中告警。', stat: 'alerts_open' },
      { module: 'tickets', title: '待处理工单', desc: '跟进处置人、SLA 和关闭结果。', stat: 'tickets_open' },
      { module: 'reports', title: '态势报表', desc: '查看趋势和高频攻击来源。', stat: 'alerts_closed' },
    ],
  },
  security_analyst: {
    label: '安全分析人员',
    desc: '负责告警深度研判、流量分析、资产和情报联动。',
    modules: ['overview', 'alerts', 'raw-alerts', 'flows', 'assets', 'intel', 'reports', 'exports'],
    focus: [
      { module: 'alerts', title: '高风险告警', desc: '查看攻击名称、资产命中和协议上下文。', stat: 'alerts_open' },
      { module: 'flows', title: '流量回溯', desc: '分析同流量上下文和协议细节。', stat: 'flows_observed' },
      { module: 'intel', title: '情报联动', desc: '核对命中标签、来源和受影响资产。', stat: 'alerts_closed' },
    ],
  },
  auditor: {
    label: '审计人员',
    desc: '负责审计、查询统计和运营监督，不参与具体处置。',
    modules: ['overview', 'reports', 'audit', 'query-stats'],
    focus: [
      { module: 'audit', title: '审计留痕', desc: '查看登录、配置变更和批量处置操作。', stat: 'alerts_closed' },
      { module: 'query-stats', title: '查询行为', desc: '监督导出、慢查询和检索使用情况。', stat: 'tickets_open' },
      { module: 'reports', title: '结果监督', desc: '关注告警趋势、处置效率和平台状态。', stat: 'probes_online' },
    ],
  },
};

const $ = (id) => document.getElementById(id);
const tenantInput = $('tenant-filter');
const srcInput = $('src-filter');
const dstInput = $('dst-filter');
const signatureInput = $('signature-filter');
const assigneeInput = $('assignee-filter');
const severityInput = $('severity-filter');
const alertStatusInput = $('alert-status-filter');
const alertCategoryInput = $('alert-category-filter');
const alertProbeInput = $('alert-probe-filter');
const alertAttackResultInput = $('alert-attack-result-filter');
const alertProbeCountInput = $('alert-probe-count-filter');
const alertWindowInput = $('alert-window-filter');
const alertSinceInput = $('alert-since-filter');
const alertSortByInput = $('alert-sort-by');
const alertSortOrderInput = $('alert-sort-order');
const alertPageSizeInput = $('alert-page-size');
const alertsPageJumpInput = $('alerts-page-jump');
const alertsTotalInfo = $('alerts-total-info');
const rawAlertSrcInput = $('raw-alert-src-filter');
const rawAlertDstInput = $('raw-alert-dst-filter');
const rawAlertSignatureInput = $('raw-alert-signature-filter');
const rawAlertProbeInput = $('raw-alert-probe-filter');
const rawAlertSeverityInput = $('raw-alert-severity-filter');
const rawAlertAttackResultInput = $('raw-alert-attack-result-filter');
const rawAlertSinceInput = $('raw-alert-since-filter');
const rawAlertPageSizeInput = $('raw-alert-page-size');
const rawAlertsPageJumpInput = $('raw-alerts-page-jump');
const rawAlertsTotalInfo = $('raw-alerts-total-info');
const rawAlertDetailBadge = $('raw-alert-detail-badge');
const rawAlertDetailPanel = $('raw-alert-detail');
const backToAlertsBtn = $('back-to-alerts-btn');
const backToRawAlertsBtn = $('back-to-raw-alerts-btn');
const backToTicketsBtn = $('back-to-tickets-btn');
const backToProbesBtn = $('back-to-probes-btn');
const alertsSelectAllInput = $('alerts-select-all');
const ticketsSelectAllInput = $('tickets-select-all');
const flowSrcInput = $('flow-src-filter');
const flowDstInput = $('flow-dst-filter');
const flowProtoInput = $('flow-proto-filter');
const ticketStatusInput = $('ticket-status-filter');
const ticketSinceInput = $('ticket-since-filter');
const ticketSortByInput = $('ticket-sort-by');
const ticketSortOrderInput = $('ticket-sort-order');
const ticketPageSizeInput = $('ticket-page-size');
const ticketsPageJumpInput = $('tickets-page-jump');
const reportSinceInput = $('report-since-filter');
const probeMetricsSinceInput = $('probe-metrics-since-filter');
const probeMetricsLimitInput = $('probe-metrics-limit-filter');
const deploymentProbeInput = $('deployment-probe-filter');
const deploymentStatusInput = $('deployment-status-filter');
const deploymentSinceInput = $('deployment-since-filter');
const deploymentLimitInput = $('deployment-limit-filter');
const exportFormatInput = $('export-format-filter');
const queryStatsScopeInput = $('query-stats-scope-filter');
const notificationChannelForm = $('notification-channel-form');
const notificationTemplateForm = $('notification-template-form');
const organizationForm = $('organization-form');
const assetForm = $('asset-form');
const organizationParentSelect = $('organization-parent-select');
const assetOrgSelect = $('asset-org-select');
const userAssetScopeSelect = $('user-asset-scope');
const userOrgScopeSelect = $('user-org-scope');
const intelForm = $('intel-form');
const suppressionRuleForm = $('suppression-rule-form');
const riskPolicyForm = $('risk-policy-form');
const ticketAutomationPolicyForm = $('ticket-automation-policy-form');
const upgradePackageForm = $('upgrade-package-form');
const probeUpgradeForm = $('probe-upgrade-form');
const probeUpgradeBatchForm = $('probe-upgrade-batch-form');

$('login-form').addEventListener('submit', onLogin);
$('refresh-btn').addEventListener('click', refreshCurrentPage);
$('logout-btn').addEventListener('click', logout);
$('ack-alert-btn').addEventListener('click', () => updateSelectedAlert('ack'));
$('close-alert-btn').addEventListener('click', () => updateSelectedAlert('closed'));
$('ticket-progress-btn').addEventListener('click', () => updateSelectedTicket('in_progress'));
$('ticket-close-btn').addEventListener('click', () => updateSelectedTicket('closed'));
$('ticket-form').addEventListener('submit', createTicketFromAlert);
$('role-form').addEventListener('submit', createRole);
$('user-form').addEventListener('submit', createUser);
$('probe-config-form').addEventListener('submit', createProbeConfig);
$('rule-bundle-form').addEventListener('submit', createRuleBundle);
notificationChannelForm.addEventListener('submit', createNotificationChannel);
notificationTemplateForm.addEventListener('submit', createNotificationTemplate);
organizationForm.addEventListener('submit', createOrganization);
assetForm.addEventListener('submit', createAsset);
intelForm.addEventListener('submit', createThreatIntel);
suppressionRuleForm.addEventListener('submit', createSuppressionRule);
riskPolicyForm.addEventListener('submit', createRiskPolicy);
ticketAutomationPolicyForm.addEventListener('submit', createTicketAutomationPolicy);
upgradePackageForm.addEventListener('submit', createUpgradePackage);
probeUpgradeForm.addEventListener('submit', createProbeUpgradeTask);
probeUpgradeBatchForm.addEventListener('submit', createProbeUpgradeTasksBatch);
$('probe-binding-form').addEventListener('submit', applyProbeBinding);
$('probe-binding-batch-form').addEventListener('submit', applyProbeBindingBatch);
$('alerts-prev-btn').addEventListener('click', async () => changeAlertPage(-1));
$('alerts-next-btn').addEventListener('click', async () => changeAlertPage(1));
$('alerts-jump-btn').addEventListener('click', async () => jumpAlertPage());
$('raw-alerts-prev-btn').addEventListener('click', async () => changeRawAlertPage(-1));
$('raw-alerts-next-btn').addEventListener('click', async () => changeRawAlertPage(1));
$('raw-alerts-jump-btn').addEventListener('click', async () => jumpRawAlertPage());
$('tickets-prev-btn').addEventListener('click', async () => changeTicketPage(-1));
$('tickets-next-btn').addEventListener('click', async () => changeTicketPage(1));
$('tickets-jump-btn').addEventListener('click', async () => jumpTicketPage());
$('export-alerts-btn').addEventListener('click', async () => createAlertExportTask());
$('alert-batch-ack-btn').addEventListener('click', async () => batchUpdateAlerts('ack'));
$('alert-batch-close-btn').addEventListener('click', async () => batchUpdateAlerts('closed'));
$('alert-batch-ticket-btn').addEventListener('click', async () => batchCreateTicketsFromAlerts());
$('export-flows-btn').addEventListener('click', async () => createFlowExportTask());
$('export-alerts-page-btn').addEventListener('click', async () => createAlertExportTask());
$('export-flows-page-btn').addEventListener('click', async () => createFlowExportTask());
$('refresh-exports-btn').addEventListener('click', async () => loadExportTasks());
$('refresh-query-stats-btn').addEventListener('click', async () => loadQueryStats());
backToAlertsBtn.addEventListener('click', async () => {
  await navigate('alerts');
});
backToRawAlertsBtn.addEventListener('click', async () => {
  await navigate('raw-alerts');
});
backToTicketsBtn.addEventListener('click', async () => {
  await navigate('tickets');
});
backToProbesBtn.addEventListener('click', async () => {
  await navigate('probes');
});
alertsSelectAllInput.addEventListener('change', () => toggleSelectAllAlerts(alertsSelectAllInput.checked));
ticketsSelectAllInput.addEventListener('change', () => toggleSelectAllTickets(ticketsSelectAllInput.checked));
$('ticket-batch-progress-btn').addEventListener('click', async () => batchUpdateTickets('in_progress'));
$('ticket-batch-close-btn').addEventListener('click', async () => batchUpdateTickets('closed'));

window.addEventListener('hashchange', async () => {
  if (!state.user) return;
  await applyRouteFromLocation();
});

[srcInput, dstInput, signatureInput, assigneeInput, severityInput, alertStatusInput, alertCategoryInput, alertProbeInput, alertAttackResultInput, alertProbeCountInput, alertWindowInput, alertSinceInput, alertSortByInput, alertSortOrderInput, alertPageSizeInput]
  .forEach((input) => input.addEventListener('change', async () => resetAlertPageAndReload()));
[rawAlertSrcInput, rawAlertDstInput, rawAlertSignatureInput, rawAlertProbeInput, rawAlertSeverityInput, rawAlertAttackResultInput, rawAlertSinceInput, rawAlertPageSizeInput]
  .forEach((input) => input.addEventListener('change', async () => resetRawAlertPageAndReload()));
[ticketStatusInput, ticketSinceInput, ticketSortByInput, ticketSortOrderInput, ticketPageSizeInput]
  .forEach((input) => input.addEventListener('change', async () => resetTicketPageAndReload()));
reportSinceInput.addEventListener('change', async () => {
  persistReportFilters();
  if (state.currentPage === 'reports') {
    await loadReports();
  }
});
probeMetricsSinceInput.addEventListener('change', async () => {
  persistProbeFilters();
  if (state.currentPage === 'probe-detail' && state.selectedProbe?.probe?.id) {
    await navigate('probe-detail', { probeID: state.selectedProbe.probe.id });
  }
});
probeMetricsLimitInput.addEventListener('change', async () => {
  persistProbeFilters();
  if (state.currentPage === 'probe-detail' && state.selectedProbe?.probe?.id) {
    await navigate('probe-detail', { probeID: state.selectedProbe.probe.id });
  }
});
[deploymentProbeInput, deploymentStatusInput, deploymentSinceInput, deploymentLimitInput]
  .forEach((input) => input.addEventListener('change', async () => {
    persistProbeFilters();
    if (state.currentPage === 'probes' || state.currentPage === 'probe-detail') {
      await navigate(state.currentPage === 'probe-detail' ? 'probe-detail' : 'probes', {
        probeID: state.selectedProbe?.probe?.id,
      });
    }
  }));
queryStatsScopeInput.addEventListener('change', async () => {
  persistQueryStatsFilters();
  if (state.currentPage === 'query-stats') {
    await loadQueryStats();
  }
});

async function onLogin(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  const result = await request('/api/v1/auth/login', { method: 'POST', body: JSON.stringify(data) }, false);
  if (result.error) {
    $('login-error').textContent = result.error;
    return;
  }
  state.token = result.token;
  state.user = result.user;
  localStorage.setItem('ndr_token', state.token);
  afterLogin();
}

function logout() {
  stopExportAutoRefresh();
  state.token = '';
  state.user = null;
  state.modules = [];
  localStorage.removeItem('ndr_token');
  $('app-view').classList.add('hidden');
  $('login-view').classList.remove('hidden');
}

async function afterLogin() {
  restoreFilters();
  await loadRoleTemplates();
  tenantInput.value = state.user.tenant_id;
  state.alertPageSize = Number(alertPageSizeInput.value || 10);
  state.ticketPageSize = Number(ticketPageSizeInput.value || 10);
  state.modules = resolveModules(state.user.permissions || []);
  renderNavigation();
  renderOverviewCards();
  showApp();
  await applyRouteFromLocation(true);
}

function resolveModules(permissions) {
  const profile = resolveRoleProfile(state.user);
  const allowedByRole = new Set(profile.modules || MODULES.map((module) => module.id));
  return MODULES.filter((module) => {
    if (!allowedByRole.has(module.id)) {
      return false;
    }
    return !module.permission || permissions.includes('*') || permissions.includes(module.permission);
  });
}

function renderNavigation() {
  $('nav-menu').innerHTML = state.modules.map((module) => `
    <button class="nav-btn ${module.id === state.currentPage ? 'active' : ''}" data-page="${module.id}" title="${module.desc}">${module.title}</button>
  `).join('');
  document.querySelectorAll('.nav-btn').forEach((button) => {
    button.addEventListener('click', async () => {
      await navigate(button.dataset.page);
    });
  });
}

function renderOverviewCards() {
  $('overview-cards').innerHTML = state.modules.filter((module) => module.id !== 'overview').map((module) => `
    <button class="module-card" data-page="${module.id}" title="${module.desc}">
      <strong>${module.title}</strong>
      <span>${module.desc}</span>
    </button>
  `).join('');
  document.querySelectorAll('.module-card').forEach((button) => {
    button.addEventListener('click', async () => {
      await navigate(button.dataset.page);
    });
  });
}

function renderOverviewWorkbench(stats = {}, workbench = {}) {
  const profile = resolveRoleProfile(state.user);
  const roleTemplate = workbench.role_template || {};
  $('overview-role-label').textContent = `${roleTemplate.label || profile.label} · 首页按当前职责展示重点模块`;
  $('overview-role-banner').innerHTML = `
    <div>
      <strong>${roleTemplate.label || profile.label}</strong>
      <p>${roleTemplate.description || profile.desc || '按角色展示重点模块和监控指标。'}</p>
    </div>
    <span class="role-chip">${formatRoles(state.user?.roles).join(' / ')}</span>
  `;
  renderList('overview-recommended-list', workbench.recommended || [], (item) => item);
  $('overview-focus-cards').innerHTML = (profile.focus || []).map((item) => {
    const module = MODULES.find((entry) => entry.id === item.module);
    return `
      <button class="focus-card" data-page="${item.module}" title="${module?.desc || item.desc}">
        <span class="focus-label">${item.title || module?.title || item.module}</span>
        <strong>${formatOverviewStatValue(item.stat, stats)}</strong>
        <p>${item.desc}</p>
      </button>
    `;
  }).join('');
  document.querySelectorAll('.focus-card').forEach((button) => {
    button.addEventListener('click', async () => {
      await navigate(button.dataset.page);
    });
  });
  $('overview-stats').innerHTML = buildOverviewStats(profile, stats).map((item) => `
    <article class="card stat compact-stat">
      <span>${item.label}</span>
      <strong>${item.value}</strong>
    </article>
  `).join('');
}

async function navigate(page, options = {}) {
  const route = buildRoute(page, options);
  const currentHash = window.location.hash || '';
  if (currentHash !== route.hash) {
    if (options.replace) {
      window.location.replace(route.hash);
    } else {
      window.location.hash = route.hash;
    }
    return;
  }
  await applyRoute(route);
}

function buildRoute(page, options = {}) {
  const params = buildRouteParams(page, options);
  switch (page) {
    case 'alert-detail':
      return {
        page,
        alertID: options.alertID || state.selectedAlert?.alert?.id || '',
        hash: buildHash(`alerts/${encodeURIComponent(options.alertID || state.selectedAlert?.alert?.id || '')}`, params),
      };
    case 'ticket-detail':
      return {
        page,
        ticketID: options.ticketID || state.selectedTicket?.ticket?.id || '',
        hash: buildHash(`tickets/${encodeURIComponent(options.ticketID || state.selectedTicket?.ticket?.id || '')}`, params),
      };
    case 'raw-alert-detail':
      return {
        page,
        rawAlertID: options.rawAlertID || state.selectedRawAlert?.item?.id || '',
        hash: buildHash(`raw-alerts/${encodeURIComponent(options.rawAlertID || state.selectedRawAlert?.item?.id || '')}`, params),
      };
    case 'probe-detail':
      return {
        page,
        probeID: options.probeID || state.selectedProbe?.probe?.id || '',
        hash: buildHash(`probes/${encodeURIComponent(options.probeID || state.selectedProbe?.probe?.id || '')}`, params),
      };
    default:
      return {
        page,
        hash: buildHash(page, params),
      };
  }
}

function parseRouteFromLocation() {
  const raw = String(window.location.hash || '').replace(/^#/, '');
  const [pathPart, queryPart] = (raw || '/overview').split('?');
  const normalized = pathPart || '/overview';
  const parts = normalized.split('/').filter(Boolean);
  const params = new URLSearchParams(queryPart || '');
  if (!parts.length) {
    return { page: 'overview', hash: '#/overview', params };
  }
  if (parts[0] === 'alerts' && parts[1]) {
    return { page: 'alert-detail', alertID: decodeURIComponent(parts[1]), hash: buildHash(`alerts/${parts[1]}`, params), params };
  }
  if (parts[0] === 'raw-alerts' && parts[1]) {
    return { page: 'raw-alert-detail', rawAlertID: decodeURIComponent(parts[1]), hash: buildHash(`raw-alerts/${parts[1]}`, params), params };
  }
  if (parts[0] === 'tickets' && parts[1]) {
    return { page: 'ticket-detail', ticketID: decodeURIComponent(parts[1]), hash: buildHash(`tickets/${parts[1]}`, params), params };
  }
  if (parts[0] === 'probes' && parts[1]) {
    return { page: 'probe-detail', probeID: decodeURIComponent(parts[1]), hash: buildHash(`probes/${parts[1]}`, params), params };
  }
  return { page: parts[0], hash: buildHash(parts[0], params), params };
}

async function applyRouteFromLocation(fallbackToDefault = false) {
  let route = parseRouteFromLocation();
  const allowedPages = new Set(state.modules.map((module) => module.id));
  const detailBasePage = route.page === 'alert-detail'
    ? 'alerts'
    : route.page === 'raw-alert-detail'
      ? 'raw-alerts'
    : route.page === 'ticket-detail'
      ? 'tickets'
      : route.page === 'probe-detail'
        ? 'probes'
        : route.page;
  if (!allowedPages.has(detailBasePage)) {
    route = { page: state.modules[0]?.id || 'overview', hash: `#/${state.modules[0]?.id || 'overview'}` };
  }
  if (fallbackToDefault && (!window.location.hash || window.location.hash === '#')) {
    await navigate(route.page, { alertID: route.alertID, replace: true });
    return;
  }
  await applyRoute(route);
}

async function applyRoute(route) {
  stopExportAutoRefresh();
  state.currentRoute = route;
  state.currentPage = route.page;
  applyRouteState(route);
  const current = MODULES.find((item) => item.id === route.page);
  const pageTitle = route.page === 'alert-detail'
    ? '告警详情'
    : route.page === 'raw-alert-detail'
      ? '原始告警详情'
    : route.page === 'ticket-detail'
      ? '工单详情'
      : route.page === 'probe-detail'
        ? '探针详情'
        : (current?.title || '总览');
  $('page-title').textContent = pageTitle;
  document.querySelectorAll('.page').forEach((pageEl) => pageEl.classList.add('hidden'));
  if (route.page === 'probes') {
    const listPage = $('page-probes');
    const managePage = $('page-probes-manage');
    if (listPage) listPage.classList.remove('hidden');
    if (managePage) managePage.classList.remove('hidden');
  } else {
    const target = $(`page-${route.page}`);
    if (target) target.classList.remove('hidden');
  }
  document.querySelectorAll('.nav-btn').forEach((button) => {
    const activeBase = route.page === 'alert-detail'
      ? 'alerts'
      : route.page === 'raw-alert-detail'
        ? 'raw-alerts'
      : route.page === 'ticket-detail'
        ? 'tickets'
        : route.page === 'probe-detail'
          ? 'probes'
          : route.page;
    button.classList.toggle('active', button.dataset.page === activeBase);
  });
  if (route.page === 'exports') {
    startExportAutoRefresh();
  }
  await refreshCurrentPage();
}

function buildHash(path, params) {
  const query = params instanceof URLSearchParams ? params.toString() : new URLSearchParams(params || {}).toString();
  return `#/${path}${query ? `?${query}` : ''}`;
}

function buildRouteParams(page, options = {}) {
  const params = new URLSearchParams();
  switch (page) {
    case 'alerts':
    case 'alert-detail':
      appendIfValue(params, 'src', srcInput.value);
      appendIfValue(params, 'dst', dstInput.value);
      appendIfValue(params, 'signature', signatureInput.value);
      appendIfValue(params, 'assignee', assigneeInput.value);
      appendIfValue(params, 'severity', severityInput.value);
      appendIfValue(params, 'status', alertStatusInput.value);
      appendIfValue(params, 'attack_result', alertAttackResultInput.value);
      appendIfValue(params, 'category', alertCategoryInput.value);
      appendIfValue(params, 'probe', alertProbeInput.value);
      appendIfValue(params, 'min_probe_count', alertProbeCountInput.value);
      appendIfValue(params, 'min_window_mins', alertWindowInput.value);
      appendIfValue(params, 'since', alertSinceInput.value);
      appendIfValue(params, 'sort_by', alertSortByInput.value);
      appendIfValue(params, 'sort_order', alertSortOrderInput.value);
      appendIfValue(params, 'page', String(options.page || state.alertPage || 1));
      appendIfValue(params, 'page_size', String(options.pageSize || state.alertPageSize || 10));
      break;
    case 'tickets':
    case 'ticket-detail':
      appendIfValue(params, 'status', ticketStatusInput.value);
      appendIfValue(params, 'since', ticketSinceInput.value);
      appendIfValue(params, 'sort_by', ticketSortByInput.value);
      appendIfValue(params, 'sort_order', ticketSortOrderInput.value);
      appendIfValue(params, 'page', String(options.page || state.ticketPage || 1));
      appendIfValue(params, 'page_size', String(options.pageSize || state.ticketPageSize || 10));
      break;
    case 'raw-alerts':
    case 'raw-alert-detail':
      appendIfValue(params, 'src', rawAlertSrcInput.value);
      appendIfValue(params, 'dst', rawAlertDstInput.value);
      appendIfValue(params, 'signature', rawAlertSignatureInput.value);
      appendIfValue(params, 'probe', rawAlertProbeInput.value);
      appendIfValue(params, 'severity', rawAlertSeverityInput.value);
      appendIfValue(params, 'attack_result', rawAlertAttackResultInput.value);
      appendIfValue(params, 'since', rawAlertSinceInput.value);
      appendIfValue(params, 'page', String(options.page || state.rawAlertPage || 1));
      appendIfValue(params, 'page_size', String(options.pageSize || state.rawAlertPageSize || 20));
      break;
    case 'probes':
    case 'probe-detail':
      appendIfValue(params, 'metrics_since', probeMetricsSinceInput.value);
      appendIfValue(params, 'metrics_limit', probeMetricsLimitInput.value);
      appendIfValue(params, 'deployment_probe', deploymentProbeInput.value);
      appendIfValue(params, 'deployment_status', deploymentStatusInput.value);
      appendIfValue(params, 'deployment_since', deploymentSinceInput.value);
      appendIfValue(params, 'deployment_limit', deploymentLimitInput.value);
      break;
    default:
      break;
  }
  return params;
}

function appendIfValue(params, key, value) {
  if (value !== undefined && value !== null && String(value).trim() !== '') {
    params.set(key, String(value));
  }
}

function applyRouteState(route) {
  const params = route.params;
  if (!(params instanceof URLSearchParams)) {
    return;
  }
  switch (route.page) {
    case 'alerts':
    case 'alert-detail':
      srcInput.value = params.get('src') || srcInput.value || '';
      dstInput.value = params.get('dst') || dstInput.value || '';
      signatureInput.value = params.get('signature') || signatureInput.value || '';
      assigneeInput.value = params.get('assignee') || assigneeInput.value || '';
      severityInput.value = params.get('severity') || severityInput.value || '';
      alertStatusInput.value = params.get('status') || alertStatusInput.value || '';
      alertAttackResultInput.value = params.get('attack_result') || alertAttackResultInput.value || '';
      alertCategoryInput.value = params.get('category') || alertCategoryInput.value || '';
      alertProbeInput.value = params.get('probe') || alertProbeInput.value || '';
      alertProbeCountInput.value = params.get('min_probe_count') || alertProbeCountInput.value || '';
      alertWindowInput.value = params.get('min_window_mins') || alertWindowInput.value || '';
      alertSinceInput.value = params.get('since') || alertSinceInput.value || '';
      alertSortByInput.value = params.get('sort_by') || alertSortByInput.value || 'last_seen_at';
      alertSortOrderInput.value = params.get('sort_order') || alertSortOrderInput.value || 'desc';
      alertPageSizeInput.value = params.get('page_size') || alertPageSizeInput.value || '10';
      state.alertPageSize = Number(alertPageSizeInput.value || 10);
      state.alertPage = Math.max(1, Number(params.get('page') || state.alertPage || 1));
      break;
    case 'tickets':
    case 'ticket-detail':
      ticketStatusInput.value = params.get('status') || ticketStatusInput.value || '';
      ticketSinceInput.value = params.get('since') || ticketSinceInput.value || '';
      ticketSortByInput.value = params.get('sort_by') || ticketSortByInput.value || 'created_at';
      ticketSortOrderInput.value = params.get('sort_order') || ticketSortOrderInput.value || 'desc';
      ticketPageSizeInput.value = params.get('page_size') || ticketPageSizeInput.value || '10';
      state.ticketPageSize = Number(ticketPageSizeInput.value || 10);
      state.ticketPage = Math.max(1, Number(params.get('page') || state.ticketPage || 1));
      break;
    case 'raw-alerts':
    case 'raw-alert-detail':
      rawAlertSrcInput.value = params.get('src') || rawAlertSrcInput.value || '';
      rawAlertDstInput.value = params.get('dst') || rawAlertDstInput.value || '';
      rawAlertSignatureInput.value = params.get('signature') || rawAlertSignatureInput.value || '';
      rawAlertProbeInput.value = params.get('probe') || rawAlertProbeInput.value || '';
      rawAlertSeverityInput.value = params.get('severity') || rawAlertSeverityInput.value || '';
      rawAlertAttackResultInput.value = params.get('attack_result') || rawAlertAttackResultInput.value || '';
      rawAlertSinceInput.value = params.get('since') || rawAlertSinceInput.value || '';
      rawAlertPageSizeInput.value = params.get('page_size') || rawAlertPageSizeInput.value || '20';
      state.rawAlertPageSize = Number(rawAlertPageSizeInput.value || 20);
      state.rawAlertPage = Math.max(1, Number(params.get('page') || state.rawAlertPage || 1));
      break;
    case 'probes':
    case 'probe-detail':
      probeMetricsSinceInput.value = params.get('metrics_since') || probeMetricsSinceInput.value || '';
      probeMetricsLimitInput.value = params.get('metrics_limit') || probeMetricsLimitInput.value || '20';
      deploymentProbeInput.value = params.get('deployment_probe') || deploymentProbeInput.value || '';
      deploymentStatusInput.value = params.get('deployment_status') || deploymentStatusInput.value || '';
      deploymentSinceInput.value = params.get('deployment_since') || deploymentSinceInput.value || '';
      deploymentLimitInput.value = params.get('deployment_limit') || deploymentLimitInput.value || '20';
      break;
    default:
      break;
  }
}

async function refreshCurrentPage() {
  await loadOverviewStats();
  switch (state.currentPage) {
    case 'alerts':
      await loadAlerts();
      break;
    case 'alert-detail':
      if (state.currentRoute?.alertID) {
        await showAlertDetail(state.currentRoute.alertID, false);
      } else if (state.selectedAlert?.alert?.id) {
        await showAlertDetail(state.selectedAlert.alert.id, false);
      }
      break;
    case 'raw-alert-detail':
      if (state.currentRoute?.rawAlertID) {
        await showRawAlertDetail(state.currentRoute.rawAlertID, false);
      } else if (state.selectedRawAlert?.item?.id) {
        await showRawAlertDetail(state.selectedRawAlert.item.id, false);
      }
      break;
    case 'ticket-detail':
      if (state.currentRoute?.ticketID) {
        await showTicketDetail(state.currentRoute.ticketID, false);
      } else if (state.selectedTicket?.ticket?.id) {
        await showTicketDetail(state.selectedTicket.ticket.id, false);
      }
      break;
    case 'probe-detail':
      if (state.currentRoute?.probeID) {
        await showProbeDetail(state.currentRoute.probeID, false);
      } else if (state.selectedProbe?.probe?.id) {
        await showProbeDetail(state.selectedProbe.probe.id, false);
      }
      break;
    case 'flows':
      await loadFlows();
      break;
    case 'raw-alerts':
      await loadRawAlerts();
      break;
    case 'tickets':
      await loadTickets();
      break;
    case 'assets':
      await loadAssets();
      break;
    case 'intel':
      await loadThreatIntel();
      break;
    case 'policies':
      await loadSuppressionRules();
      await loadRiskPolicies();
      await loadTicketAutomationPolicies();
      break;
    case 'notifications':
      await loadNotificationChannels();
      await loadNotificationTemplates();
      await loadNotificationRecords();
      break;
    case 'exports':
      await loadExportTasks();
      break;
    case 'probes':
      await loadProbes();
      await loadUpgradePackages();
      await loadProbeConfigs();
      await loadRuleBundles();
      await loadProbeUpgradeTasks();
      await loadProbeBindings();
      await loadDeployments();
      break;
    case 'users':
      await loadUsers();
      break;
    case 'roles':
      await loadRoles();
      break;
    case 'reports':
      await loadReports();
      break;
    case 'query-stats':
      await loadQueryStats();
      break;
    case 'audit':
      await loadAudit();
      break;
    default:
      break;
  }
}

async function loadOverviewStats() {
  const tenant = tenantInput.value;
  const [stats, workbench] = await Promise.all([
    request(`/api/v1/dashboard/stats?tenant_id=${encodeURIComponent(tenant)}`),
    request('/api/v1/dashboard/workbench'),
  ]);
  renderOverviewWorkbench(stats || {}, workbench || {});
}

async function loadAlerts() {
  const params = new URLSearchParams({ tenant_id: tenantInput.value });
  if (srcInput.value) params.set('src_ip', srcInput.value);
  if (dstInput.value) params.set('dst_ip', dstInput.value);
  if (signatureInput.value) params.set('signature', signatureInput.value);
  if (assigneeInput.value) params.set('assignee', assigneeInput.value);
  if (severityInput.value) params.set('severity', severityInput.value);
  if (alertStatusInput.value) params.set('status', alertStatusInput.value);
  if (alertAttackResultInput.value) params.set('attack_result', alertAttackResultInput.value);
  if (alertProbeCountInput.value) params.set('min_probe_count', alertProbeCountInput.value);
  if (alertWindowInput.value) params.set('min_window_mins', alertWindowInput.value);
  if (alertSinceInput.value) params.set('since', new Date(alertSinceInput.value).toISOString());
  params.set('sort_by', alertSortByInput.value || 'last_seen_at');
  params.set('sort_order', alertSortOrderInput.value || 'desc');
  params.set('page', state.alertPage);
  params.set('page_size', state.alertPageSize);
  const response = await request(`/api/v1/alerts?${params.toString()}`);
  persistAlertFilters();
  const alerts = (response.items || []).filter((alert) => {
    const categoryMatch = !alertCategoryInput.value || String(alert.category || '').toLowerCase().includes(alertCategoryInput.value.trim().toLowerCase());
    const probeMatch = !alertProbeInput.value || (alert.probe_ids || []).some((probeID) => probeID.includes(alertProbeInput.value.trim()));
    return categoryMatch && probeMatch;
  });
  syncSelectedAlerts(alerts);
  $('alerts-body').innerHTML = alerts.map((alert) => `
    <tr data-alert-id="${alert.id}" class="alert-row">
      <td><input type="checkbox" class="alert-select" data-alert-id="${alert.id}" ${state.selectedAlertIDs.has(alert.id) ? 'checked' : ''} /></td>
      <td>
        <div class="cell-primary">${formatDateTime(alert.last_seen_at)}</div>
        <div class="cell-sub">${formatDateTime(alert.first_seen_at)}</div>
      </td>
      <td><span class="tag tag-warm">${alert.category || '未分类'}</span></td>
      <td>
        <div class="cell-primary">${alert.signature}</div>
        <div class="cell-sub">SID ${alert.signature_id || '-'} · 协议 ${alert.proto || '-'}</div>
      </td>
      <td><span class="severity-badge ${formatSeverityClass(alert.severity)}">${formatSeverity(alert.severity)}</span></td>
      <td>
        <div class="cell-primary">${alert.src_ip}</div>
        <div class="cell-sub">${formatProbeSummary(alert.probe_ids)} · 跨探针 ${alert.probe_count || (alert.probe_ids || []).length || 1}</div>
      </td>
      <td>
        <div class="cell-primary">${alert.dst_ip}:${alert.dst_port}</div>
        <div class="cell-sub">${alert.target_asset_name || '未识别资产'}</div>
      </td>
      <td>${alert.target_asset_name || '-'}</td>
      <td><span class="status-pill ${formatAttackResultClass(alert.attack_result)}">${formatAttackResult(alert.attack_result)}</span></td>
      <td><span class="status-pill ${formatStatusClass(alert.status)}">${formatAlertStatus(alert.status)}</span></td>
      <td>
        <div class="cell-primary">${alert.risk_score || 0}</div>
        <div class="cell-sub">窗口 ${alert.window_minutes || 0} 分钟</div>
      </td>
      <td>${alert.event_count || 0}</td>
    </tr>
  `).join('');
  document.querySelectorAll('.alert-row').forEach((row) => row.addEventListener('click', async (event) => {
    if (event.target instanceof HTMLInputElement && event.target.type === 'checkbox') {
      return;
    }
    await showAlertDetail(row.dataset.alertId);
  }));
  document.querySelectorAll('.alert-select').forEach((input) => input.addEventListener('click', (event) => event.stopPropagation()));
  document.querySelectorAll('.alert-select').forEach((input) => input.addEventListener('change', () => {
    const alertID = input.dataset.alertId;
    if (!alertID) return;
    if (input.checked) {
      state.selectedAlertIDs.add(alertID);
    } else {
      state.selectedAlertIDs.delete(alertID);
    }
    updateSelectAllState(alerts);
  }));
  updateSelectAllState(alerts);
  const total = response.total || 0;
  const pages = Math.max(1, Math.ceil(total / (response.page_size || state.alertPageSize)));
  $('alerts-page-info').textContent = `第 ${response.page || 1} 页 / 共 ${pages} 页`;
  const localFiltered = Boolean(alertCategoryInput.value || alertProbeInput.value);
  alertsTotalInfo.textContent = localFiltered ? `当前页筛选后 ${alerts.length} 条 / 服务端共 ${total} 条` : `共 ${total} 条告警`;
}

async function loadRawAlerts() {
  const params = new URLSearchParams({ tenant_id: tenantInput.value, page: state.rawAlertPage, page_size: state.rawAlertPageSize });
  if (rawAlertSrcInput.value) params.set('src_ip', rawAlertSrcInput.value);
  if (rawAlertDstInput.value) params.set('dst_ip', rawAlertDstInput.value);
  if (rawAlertSignatureInput.value) params.set('signature', rawAlertSignatureInput.value);
  if (rawAlertProbeInput.value) params.set('probe_id', rawAlertProbeInput.value);
  if (rawAlertSeverityInput.value) params.set('severity', rawAlertSeverityInput.value);
  if (rawAlertAttackResultInput.value) params.set('attack_result', rawAlertAttackResultInput.value);
  if (rawAlertSinceInput.value) params.set('since', new Date(rawAlertSinceInput.value).toISOString());
  const response = await request(`/api/v1/raw-alerts?${params.toString()}`);
  $('raw-alerts-body').innerHTML = (response.items || []).map((item) => `
    <tr data-raw-alert-id="${item.id}" class="raw-alert-row">
      <td>${formatDateTime(item.event_time)}</td>
      <td>
        <div class="cell-primary">${item.signature}</div>
        <div class="cell-sub">SID ${item.signature_id || '-'} · ${item.category || '未分类'}</div>
      </td>
      <td><span class="severity-badge ${formatSeverityClass(item.severity)}">${formatSeverity(item.severity)}</span></td>
      <td>${item.src_ip}:${item.src_port}</td>
      <td>${item.dst_ip}:${item.dst_port}</td>
      <td>${item.app_proto || item.proto || '-'}</td>
      <td>${item.probe_id}</td>
      <td><span class="status-pill ${formatAttackResultClass(item.attack_result)}">${formatAttackResult(item.attack_result)}</span></td>
    </tr>
  `).join('') || '<tr><td colspan="8">暂无数据</td></tr>';
  document.querySelectorAll('.raw-alert-row').forEach((row) => row.addEventListener('click', async () => {
    await showRawAlertDetail(row.dataset.rawAlertId);
  }));
  const total = response.total || 0;
  const pages = Math.max(1, Math.ceil(total / (response.page_size || state.rawAlertPageSize)));
  $('raw-alerts-page-info').textContent = `第 ${response.page || 1} 页 / 共 ${pages} 页`;
  rawAlertsTotalInfo.textContent = `共 ${total} 条原始告警`;
}

async function loadFlows() {
  const params = new URLSearchParams({ tenant_id: tenantInput.value });
  if (flowSrcInput.value) params.set('src_ip', flowSrcInput.value);
  if (flowDstInput.value) params.set('dst_ip', flowDstInput.value);
  if (flowProtoInput.value) params.set('app_proto', flowProtoInput.value);
  const flows = await request(`/api/v1/flows?${params.toString()}`);
  $('flows-body').innerHTML = (flows || []).map((flow) => `
    <tr>
      <td>${flow.flow_id}</td>
      <td>${flow.src_ip}:${flow.src_port}</td>
      <td>${flow.dst_ip}:${flow.dst_port}</td>
      <td>${flow.app_proto || flow.proto}</td>
      <td>${formatDateTime(flow.seen_at)}</td>
    </tr>
  `).join('');
}

async function loadTickets() {
  const params = new URLSearchParams({ tenant_id: tenantInput.value, page: state.ticketPage, page_size: state.ticketPageSize });
  if (ticketStatusInput.value) params.set('status', ticketStatusInput.value);
  if (ticketSinceInput.value) params.set('since', new Date(ticketSinceInput.value).toISOString());
  params.set('sort_by', ticketSortByInput.value || 'created_at');
  params.set('sort_order', ticketSortOrderInput.value || 'desc');
  const response = await request(`/api/v1/tickets?${params.toString()}`);
  persistTicketFilters();
  const tickets = response.items || [];
  syncSelectedTickets(tickets);
  $('tickets-body').innerHTML = tickets.map((ticket) => `
    <tr data-ticket-id="${ticket.id}" class="ticket-row">
      <td><input type="checkbox" class="ticket-select" data-ticket-id="${ticket.id}" ${state.selectedTicketIDs.has(ticket.id) ? 'checked' : ''} /></td>
      <td>${formatDateTime(ticket.created_at)}</td>
      <td>
        <div class="cell-primary">${ticket.title}</div>
        <div class="cell-sub">${ticket.id}</div>
      </td>
      <td><span class="status-pill ${formatStatusClass(ticket.status)}">${formatAlertStatus(ticket.status)}</span></td>
      <td><span class="severity-badge ${formatPriorityClass(ticket.priority)}">${formatTicketPriority(ticket.priority)}</span></td>
      <td>${ticket.assignee || '-'}</td>
      <td>
        <div class="cell-primary">${formatSLAStatus(ticket.sla_status)}</div>
        <div class="cell-sub">${ticket.sla_deadline ? formatDateTime(ticket.sla_deadline) : '-'}</div>
      </td>
      <td>${ticket.alert_id || '-'}</td>
    </tr>
  `).join('') || '<tr><td colspan="8">暂无数据</td></tr>';
  document.querySelectorAll('.ticket-row').forEach((row) => row.addEventListener('click', (event) => {
    if (event.target.closest('.ticket-select')) return;
    showTicketDetail(row.dataset.ticketId);
  }));
  document.querySelectorAll('.ticket-select').forEach((input) => {
    input.addEventListener('change', () => {
      const ticketID = input.dataset.ticketId;
      if (!ticketID) return;
      if (input.checked) {
        state.selectedTicketIDs.add(ticketID);
      } else {
        state.selectedTicketIDs.delete(ticketID);
      }
      updateSelectAllTicketsState(tickets);
    });
  });
  updateSelectAllTicketsState(tickets);
  $('tickets-page-info').textContent = `第 ${response.page || 1} 页 / 共 ${Math.max(1, Math.ceil((response.total || 0) / (response.page_size || state.ticketPageSize)))} 页`;
}

async function loadProbes() {
  const probes = await request(`/api/v1/probes?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  $('probes-body').innerHTML = (probes || []).map((item) => `
    <tr data-probe-id="${item.id}" class="probe-row">
      <td>
        <div class="cell-primary">${item.name}</div>
        <div class="cell-sub">${item.id}</div>
      </td>
      <td><span class="status-pill ${formatProbeStatusClass(item.status)}">${formatProbeStatus(item.status)}</span></td>
      <td>${item.probe_code}</td>
      <td>${formatDateTime(item.last_heartbeat_at)}</td>
      <td>${formatProbeRuntime(item)}</td>
      <td>${item.version || '-'}</td>
      <td>${item.applied_config_id || '-'}</td>
      <td>${item.applied_rule_id || '-'}</td>
      <td><span class="status-pill ${formatDeployStatusClass(item.last_deploy_status)}">${formatDeployStatus(item.last_deploy_status)}</span></td>
    </tr>
  `).join('') || '<tr><td colspan="9">暂无数据</td></tr>';
  document.querySelectorAll('.probe-row').forEach((row) => row.addEventListener('click', () => showProbeDetail(row.dataset.probeId)));
}

async function loadProbeConfigs() {
  const items = await request(`/api/v1/probe-configs?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('probe-configs-list', items, (item) => `${item.name} · filters: ${(item.filters || []).join(', ')} · outputs: ${(item.output_types || []).join(', ')}`);
}

async function loadRuleBundles() {
  const items = await request(`/api/v1/rule-bundles?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('rule-bundles-list', items, (item) => `${item.version} · ${item.enabled ? '启用' : '停用'} · ${item.description}`);
}

async function loadProbeBindings() {
  const items = await request(`/api/v1/probe-bindings?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('probe-bindings-list', items, (item) => `${item.probe_name} · 配置=${item.probe_config_id || '-'} · 规则=${item.rule_bundle_id || '-'} · ${formatDateTime(item.updated_at)}`);
}

async function loadUpgradePackages() {
  const items = await request(`/api/v1/upgrade-packages?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('upgrade-packages-list', items, (item) => {
    const download = item.package_url ? `<button type="button" class="ghost package-download-btn" data-package-id="${item.id}">下载</button>` : '-';
    return `${item.version} · ${item.enabled ? '启用' : '停用'} · 文件=${item.file_name || '-'} · 大小=${item.file_size || 0} · 校验=${item.checksum || '-'} · ${item.notes || '-'} · ${download}`;
  });
  document.querySelectorAll('.package-download-btn').forEach((button) => {
    button.addEventListener('click', async () => downloadUpgradePackage(button.dataset.packageId));
  });
}

async function loadProbeUpgradeTasks() {
  const items = await request(`/api/v1/probe-upgrades?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('probe-upgrade-tasks-list', items, (item) => `${formatDateTime(item.created_at)} · ${item.probe_name} · 升级包=${item.package_id || '-'} · ${formatUpgradeAction(item.action)} ${item.previous_version || '-'} -> ${item.target_version} · ${formatDeployStatus(item.status)} · 重试=${item.retry_count || 0}/${item.max_retries || 0} · ${item.message || '-'}`);
}

async function loadDeployments() {
  const params = new URLSearchParams({ tenant_id: tenantInput.value });
  if (deploymentProbeInput.value) params.set('probe_id', deploymentProbeInput.value);
  if (deploymentStatusInput.value) params.set('status', deploymentStatusInput.value);
  if (deploymentSinceInput.value) params.set('since', new Date(deploymentSinceInput.value).toISOString());
  params.set('limit', deploymentLimitInput.value || '20');
  const items = await request(`/api/v1/deployments?${params.toString()}`);
  persistProbeFilters();
  renderList('deployments-list', items, (item) => `${formatDateTime(item.created_at)} · ${item.probe_name} · ${formatDeployStatus(item.status)} · ${item.message}`);
}

async function loadAssets() {
  await loadOrganizations();
  const items = await request(`/api/v1/assets?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('assets-list', items, (item) => `${item.name} · ${item.ip} · 组织=${item.org_name || item.org_id || '未归属'} · 类型=${item.asset_type} · 重要度=${item.importance_level} · ${(item.tags || []).join(', ')}`);
  renderAssetScopeOptions(items);
}

async function loadOrganizations() {
  const items = await request(`/api/v1/organizations?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderOrganizationTree('organizations-list', items);
  renderOrganizationOptions(items);
}

function renderOrganizationOptions(items) {
  const options = ['<option value="">根组织</option>']
    .concat((items || []).map((item) => `<option value="${escapeHTML(item.id)}">${escapeHTML(`${'— '.repeat(Math.max((item.level || 1) - 1, 0))}${item.name}`)}</option>`));
  organizationParentSelect.innerHTML = options.join('');
  assetOrgSelect.innerHTML = ['<option value="">未归属组织</option>']
    .concat((items || []).map((item) => `<option value="${escapeHTML(item.id)}">${escapeHTML(`${'— '.repeat(Math.max((item.level || 1) - 1, 0))}${item.name}`)}</option>`))
    .join('');
  userOrgScopeSelect.innerHTML = (items || []).map((item) => `<option value="${escapeHTML(item.id)}">${escapeHTML(item.name)}</option>`).join('');
}

function renderAssetScopeOptions(items) {
  userAssetScopeSelect.innerHTML = (items || []).map((item) => `<option value="${escapeHTML(item.id)}">${escapeHTML(item.name)} · ${escapeHTML(item.ip)}</option>`).join('');
}

function renderOrganizationTree(id, items) {
  const list = $(id);
  const rows = items || [];
  if (!rows.length) {
    list.innerHTML = '<li>暂无数据</li>';
    return;
  }
  const children = new Map();
  rows.forEach((item) => {
    const key = item.parent_id || '__root__';
    if (!children.has(key)) children.set(key, []);
    children.get(key).push(item);
  });
  const renderNode = (item) => `
    <li>
      <div class="tree-node">
        <strong>${escapeHTML(item.name)}</strong>
        <span class="list-meta">编码=${escapeHTML(item.code || '-')} · ID=${escapeHTML(item.id)}</span>
      </div>
      ${children.has(item.id) ? `<ul class="tree-list">${children.get(item.id).map(renderNode).join('')}</ul>` : ''}
    </li>
  `;
  list.innerHTML = `<li><ul class="tree-list">${(children.get('__root__') || []).map(renderNode).join('')}</ul></li>`;
}

async function loadThreatIntel() {
  const items = await request(`/api/v1/threat-intel?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('intel-list', items, (item) => `${item.type} · ${item.value} · 等级=${item.severity} · 来源=${item.source} · ${(item.tags || []).join(', ')}`);
}

async function loadSuppressionRules() {
  const items = await request(`/api/v1/suppression-rules?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('suppression-rules-list', items, (item) => `${item.name} · 源=${item.src_ip || '*'} · 目的=${item.dst_ip || '*'} · SID=${item.signature_id || '*'} · 签名=${item.signature || '*'} · ${item.enabled ? '启用' : '停用'}`);
}

async function loadRiskPolicies() {
  const items = await request(`/api/v1/risk-policies?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('risk-policies-list', items, (item) => `${item.name} · 高危=${item.severity1_score} · 中危=${item.severity2_score} · 低危=${item.severity3_score} · 默认=${item.default_score} · 情报+${item.intel_hit_bonus} · 核心资产+${item.critical_asset_bonus} · ${item.enabled ? '启用' : '停用'}`);
}

async function loadTicketAutomationPolicies() {
  const items = await request(`/api/v1/ticket-automation-policies?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('ticket-automation-policies-list', items, (item) => `${item.name} · 催办提前=${item.reminder_before_mins} 分钟 · 升级延迟=${item.escalation_after_mins} 分钟 · 升级处理人=${item.escalation_assignee || '-'} · 升级状态=${formatAlertStatus(item.escalation_status)} · ${item.enabled ? '启用' : '停用'}`);
}

async function loadRoleTemplates() {
  const templates = await request('/api/v1/role-templates');
  state.roleTemplates = Array.isArray(templates) ? templates : [];
  syncRoleProfilesWithTemplates(state.roleTemplates);
  renderUserRoleTemplateOptions();
}

async function loadUsers() {
  await loadUserScopeOptions();
  const users = await request(`/api/v1/users?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('users-list', users, (item) => `
    <div class="list-line">
      <strong>${item.display_name || item.username}</strong>
      <span class="role-chip role-chip-light">${formatRoles(item.roles).join('、') || '未分配'}</span>
    </div>
    <div class="list-meta">账号：${item.username}</div>
    <div class="list-meta">租户范围：${(item.allowed_tenants || []).join(', ') || '仅当前租户'} · 探针范围：${(item.allowed_probe_ids || []).join(', ') || '全部探针'}</div>
    <div class="list-meta">资产范围：${(item.allowed_asset_ids || []).join(', ') || '全部资产'} · 组织范围：${(item.allowed_org_ids || []).join(', ') || '全部组织'}</div>
  `);
}

async function loadUserScopeOptions() {
  const [organizations, assets] = await Promise.all([
    request(`/api/v1/organizations?tenant_id=${encodeURIComponent(tenantInput.value)}`),
    request(`/api/v1/assets?tenant_id=${encodeURIComponent(tenantInput.value)}`),
  ]);
  renderOrganizationOptions(organizations);
  renderAssetScopeOptions(assets);
}

async function loadRoles() {
  const roles = await request(`/api/v1/roles?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  const templateNames = new Set((state.roleTemplates || []).map((item) => item.name));
  const builtin = (roles || []).filter((item) => templateNames.has(item.name));
  const custom = (roles || []).filter((item) => !templateNames.has(item.name));
  $('roles-list').innerHTML = `
    ${renderRoleGroup('系统预置角色', builtin)}
    ${renderRoleGroup('自定义角色', custom)}
  `;
}

async function loadAudit() {
  const logs = await request(`/api/v1/audit/logs?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('audit-list', (logs || []).slice(0, 50), (item) => `${formatDateTime(item.created_at)} · ${item.action} · ${item.resource_type} · ${item.result}`);
}

async function loadReports() {
  const params = new URLSearchParams({ tenant_id: tenantInput.value });
  if (reportSinceInput.value) params.set('since', new Date(reportSinceInput.value).toISOString());
  const report = await request(`/api/v1/reports/summary?${params.toString()}`);
  persistReportFilters();
  renderList('report-alert-trend', report.alert_trend || [], (item) => `${item.date} · ${item.count}`);
  renderList('report-ticket-trend', report.ticket_trend || [], (item) => `${item.date} · ${item.count}`);
  renderList('report-signatures', report.top_signatures || [], (item) => `${item.date} · ${item.count}`);
  renderList('report-sources', report.top_source_ips || [], (item) => `${item.date} · ${item.count}`);
  renderChart('report-alert-chart', report.alert_trend || []);
  renderChart('report-ticket-chart', report.ticket_trend || []);
  renderChart('report-signatures-chart', report.top_signatures || []);
  renderChart('report-sources-chart', report.top_source_ips || []);
}

async function loadExportTasks() {
  const items = await request(`/api/v1/exports?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('exports-list', items, (item) => {
    const download = item.status === 'completed' ? `<button type="button" class="ghost export-download-btn" data-export-id="${item.id}" data-export-format="${item.format}">下载</button>` : '-';
    return `${formatDateTime(item.created_at)} · ${item.resource_type === 'alerts' ? '告警' : '流量'} · ${String(item.format || '').toUpperCase()} · ${formatExportStatus(item.status)} · ${item.query_summary || '-'} · ${download}`;
  });
  document.querySelectorAll('.export-download-btn').forEach((button) => {
    button.addEventListener('click', async () => downloadExportTask(button.dataset.exportId, button.dataset.exportFormat));
  });
}

async function loadNotificationChannels() {
  const items = await request(`/api/v1/notifications/channels?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('notification-channels-list', items, (item) => `${item.name} · ${formatNotificationChannelType(item.type)} · ${item.enabled ? '启用' : '停用'} · 目标=${item.target || '-'} · 事件=${(item.events || []).join(', ')}`);
}

async function loadNotificationTemplates() {
  const items = await request(`/api/v1/notifications/templates?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('notification-templates-list', items, (item) => `${item.name} · ${item.event_type} · ${item.title_template} · ${item.body_template}`);
}

async function loadNotificationRecords() {
  const items = await request(`/api/v1/notifications/records?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('notification-records-list', (items || []).slice(0, 50), (item) => `${formatDateTime(item.created_at)} · ${item.channel_name} · ${item.event_type} · ${formatExportStatus(item.status)} · 重试=${item.retry_count || 0} · ${item.error_message || item.summary || '-'}`);
}

async function loadQueryStats() {
  const params = new URLSearchParams({ tenant_id: tenantInput.value });
  if ((queryStatsScopeInput.value || 'all') === 'slow') {
    params.set('slow_only', 'true');
  }
  const items = await request(`/api/v1/query-stats?${params.toString()}`);
  persistQueryStatsFilters();
  const total = (items || []).length;
  const slow = (items || []).filter((item) => item.slow).length;
  const max = (items || []).reduce((out, item) => Math.max(out, Number(item.duration_ms || 0)), 0);
  const avg = total ? Math.round((items || []).reduce((out, item) => out + Number(item.duration_ms || 0), 0) / total) : 0;
  $('query-stat-total').textContent = String(total);
  $('query-stat-slow').textContent = String(slow);
  $('query-stat-avg').textContent = `${avg} ms`;
  $('query-stat-max').textContent = `${max} ms`;
  renderChart('query-stats-chart', (items || []).slice(0, 12).reverse().map((item) => ({
    date: new Date(item.recorded_at).toLocaleTimeString(),
    count: Number(item.duration_ms || 0),
  })));
  renderList('query-stats-list', items, (item) => {
    const marker = item.slow ? '慢查询' : '正常';
    return `${formatDateTime(item.recorded_at)} · ${item.query_type} · ${marker} · ${item.duration_ms} ms · 返回=${item.result_count} · ${item.summary}`;
  });
}

async function showAlertDetail(alertID, shouldNavigate = true) {
  if (shouldNavigate) {
    $('detail-badge').textContent = alertID;
    $('alert-detail').className = 'detail-card detail-hero';
    $('alert-detail').innerHTML = '<div class="detail-empty">正在加载告警详情...</div>';
    await navigate('alert-detail', { alertID });
    return;
  }
  const detail = await request(`/api/v1/alerts/${alertID}/detail`);
  if (detail.error) return;
  state.selectedAlert = detail;
  $('detail-badge').textContent = detail.alert.id;
  $('ticket-form').classList.remove('hidden');
  $('alert-detail').className = 'detail-card detail-hero';
  $('alert-detail').innerHTML = `
    <div class="detail-title-row">
      <div>
        <div class="detail-subtitle">${detail.alert.category || '未分类'} · ${detail.alert.signature_id || '-'}</div>
        <strong>${detail.alert.signature}</strong>
        <div class="cell-sub">聚合依据：源地址 + 目的地址 + 目的端口 + 协议 + 规则签名，30 分钟窗口，跨探针合并</div>
      </div>
      <div class="detail-score-card">
        <span class="severity-badge ${formatSeverityClass(detail.alert.severity)}">${formatSeverity(detail.alert.severity)}</span>
        <span class="status-pill ${formatAttackResultClass(detail.alert.attack_result)}">${formatAttackResult(detail.alert.attack_result)}</span>
        <span class="status-pill ${formatStatusClass(detail.alert.status)}">${formatAlertStatus(detail.alert.status)}</span>
        <strong>${detail.alert.risk_score || 0}</strong>
        <span>风险分</span>
      </div>
    </div>
    <div class="detail-meta detail-meta-3">
      <span>首次发生：${formatDateTime(detail.alert.first_seen_at)}</span>
      <span>最近发生：${formatDateTime(detail.alert.last_seen_at)}</span>
      <span>聚合次数：${detail.alert.event_count || 0}</span>
      <span>源地址：${detail.alert.src_ip}:${detail.alert.src_port || '-'}</span>
      <span>目的地址：${detail.alert.dst_ip}:${detail.alert.dst_port || '-'}</span>
      <span>协议：${detail.alert.proto || '-'}</span>
      <span>源资产：${detail.alert.source_asset_name || '-'}</span>
      <span>目标资产：${detail.alert.target_asset_name || '-'}</span>
      <span>攻击结果：${formatAttackResult(detail.alert.attack_result)}</span>
      <span>处理人：${detail.alert.assignee || '-'}</span>
    </div>
    <div class="event-list detail-section">
      <strong>判定依据</strong>
      ${renderDecisionBasis(detail.decision_basis)}
    </div>
    <div class="event-list detail-section">
      <strong>情报命中</strong>
      ${(detail.alert.threat_intel_tags || []).length
        ? (detail.alert.threat_intel_tags || []).map((tag) => `<span class="tag">${tag}</span>`).join('')
        : '<code>未命中情报标签</code>'}
    </div>
    <div class="event-list detail-section">
      <strong>关联流量</strong>
      <div class="scroll-panel">${(detail.flows || []).map((flow) => `<code>${flow.flow_id} · ${flow.src_ip}:${flow.src_port} -> ${flow.dst_ip}:${flow.dst_port} · ${flow.app_proto || flow.proto}</code>`).join('') || '<code>暂无关联流量</code>'}</div>
    </div>
    <div class="event-list detail-section"><strong>关联工单</strong>${(detail.tickets || []).map((ticket) => `<code>${ticket.id} · ${ticket.title} · ${formatAlertStatus(ticket.status)} · ${formatTicketPriority(ticket.priority)}</code>`).join('') || '<code>暂无关联工单</code>'}</div>
    <div class="event-list detail-section"><strong>处置记录</strong>${(detail.activities || []).map((activity) => `<code>${formatDateTime(activity.created_at)} · ${formatActivityAction(activity.action)} · ${activity.detail || '-'}</code>`).join('') || '<code>暂无处置记录</code>'}</div>
    <div class="event-list detail-section">
      <strong>原始命中联查</strong>
      <div class="detail-actions">
        <button class="ghost" type="button" data-alert-raw-link="true">查看原始命中</button>
      </div>
    </div>
    <div class="event-list detail-section">
      <strong>同源相似告警</strong>
      <div class="detail-actions">
        <button class="ghost" type="button" data-similar-mode="src" data-similar-value="${escapeHTML(detail.alert.src_ip || '')}">按同源联查</button>
      </div>
      ${(detail.similar_source_alerts || []).map((item) => `<code><a href="#/alerts/${encodeURIComponent(item.id)}">${item.signature}</a> · ${formatDateTime(item.last_seen_at)} · ${formatAttackResult(item.attack_result)}</code>`).join('') || '<code>暂无同源相似告警</code>'}
    </div>
    <div class="event-list detail-section">
      <strong>同源时间线</strong>
      ${renderTimelinePanel(detail.same_source_timeline || [], 'source')}
    </div>
    <div class="event-list detail-section">
      <strong>同目标相似告警</strong>
      <div class="detail-actions">
        <button class="ghost" type="button" data-similar-mode="dst" data-similar-value="${escapeHTML(detail.alert.dst_ip || '')}">按同目标联查</button>
      </div>
      ${(detail.similar_target_alerts || []).map((item) => `<code><a href="#/alerts/${encodeURIComponent(item.id)}">${item.signature}</a> · ${formatDateTime(item.last_seen_at)} · ${formatAttackResult(item.attack_result)}</code>`).join('') || '<code>暂无同目标相似告警</code>'}
    </div>
    <div class="event-list detail-section">
      <strong>同目标时间线</strong>
      ${renderTimelinePanel(detail.same_target_timeline || [], 'target')}
    </div>
    <div class="event-list detail-section">
      <strong>同 Flow 时间线</strong>
      ${renderTimelinePanel(detail.same_flow_timeline || [], 'flow')}
    </div>
    <div class="event-list detail-section">
      <strong>分析上下文事件流</strong>
      ${renderProtocolPanel(detail, 'alert-detail')}
    </div>
  `;
  document.querySelectorAll('[data-similar-mode]').forEach((button) => button.addEventListener('click', async () => {
    if (button.dataset.similarMode === 'src') {
      srcInput.value = button.dataset.similarValue || '';
      dstInput.value = '';
    } else {
      dstInput.value = button.dataset.similarValue || '';
      srcInput.value = '';
    }
    state.alertPage = 1;
    await navigate('alerts', { page: 1, pageSize: state.alertPageSize });
  }));
  document.querySelectorAll('[data-alert-raw-link]').forEach((button) => button.addEventListener('click', async () => {
    rawAlertSrcInput.value = detail.alert.src_ip || '';
    rawAlertDstInput.value = detail.alert.dst_ip || '';
    rawAlertSignatureInput.value = detail.alert.signature || '';
    rawAlertAttackResultInput.value = detail.alert.attack_result || '';
    rawAlertSinceInput.value = detail.alert.first_seen_at ? toDateTimeLocal(detail.alert.first_seen_at) : '';
    state.rawAlertPage = 1;
    await navigate('raw-alerts', { page: 1, pageSize: state.rawAlertPageSize });
  }));
  bindTimelineFilters();
  bindProtocolEventFilters();
}

function renderDecisionBasis(basis) {
  if (!basis) {
    return '<code>暂无判定依据</code>';
  }
  return `
    <div class="context-card">
      <div class="context-grid">
        <div class="context-field">
          <span>攻击结果</span>
          <strong>${escapeHTML(formatAttackResult(basis.attack_result))}</strong>
        </div>
        <div class="context-field">
          <span>结果说明</span>
          <strong>${escapeHTML(basis.attack_result_reason || '缺少可判定依据')}</strong>
        </div>
      </div>
      <div class="context-list">
        <span>聚合依据</span>
        ${(basis.aggregation_reason || []).map((item) => `<code>${escapeHTML(item)}</code>`).join('') || '<code>暂无聚合依据</code>'}
      </div>
      <div class="context-list">
        <span>风险依据</span>
        ${(basis.risk_reason || []).map((item) => `<code>${escapeHTML(item)}</code>`).join('') || '<code>暂无风险依据</code>'}
      </div>
      ${basis.response_snippet ? `
        <div class="context-body">
          <span>原始响应片段</span>
          <pre>${escapeHTML(basis.response_snippet)}</pre>
        </div>
      ` : ''}
    </div>
  `;
}

function renderTimelinePanel(items, relation) {
  const stats = summarizeTimeline(items, relation);
  const scope = `timeline-${relation}`;
  return `
    <div class="timeline-summary-grid">
      ${stats.map((item) => `
        <article class="card stat compact-stat">
          <span>${item.label}</span>
          <strong>${item.value}</strong>
        </article>
      `).join('')}
    </div>
    <div class="detail-actions timeline-filters">
      <button class="ghost active" type="button" data-timeline-filter="${scope}" data-kind="all">全部</button>
      <button class="ghost" type="button" data-timeline-filter="${scope}" data-kind="aggregate">告警</button>
      <button class="ghost" type="button" data-timeline-filter="${scope}" data-kind="protocol">协议</button>
      <button class="ghost" type="button" data-timeline-filter="${scope}" data-kind="raw">原始命中</button>
    </div>
    <div class="scroll-panel timeline-panel" data-timeline-scope="${scope}">
      ${renderTimelineSection(items, relation)}
    </div>
  `;
}

function renderTimelineSection(items, relation) {
  if (!items || !items.length) {
    return '<code>暂无时间线数据</code>';
  }
  return items.map((item) => `
    <div class="timeline-item" data-timeline-kind="${escapeHTML(item.item_kind || 'protocol')}">
      <div class="timeline-time">${formatDateTime(item.timestamp)}</div>
      <div class="timeline-content">
        <div class="timeline-head">
          <span class="tag subtle">${formatTimelineRelation(relation)}</span>
          <span class="tag subtle">${formatTimelineKind(item.item_kind)}</span>
          <strong>${escapeHTML(item.title || '事件')}</strong>
        </div>
        <div class="cell-sub">${escapeHTML(item.summary || '-')}</div>
        <div class="detail-actions">
          ${item.alert_id ? `<a class="ghost link-button" href="#/alerts/${encodeURIComponent(item.alert_id)}">查看告警</a>` : ''}
          ${item.raw_event_id ? `<a class="ghost link-button" href="#/raw-alerts/${encodeURIComponent(item.raw_event_id)}">查看原始命中</a>` : ''}
        </div>
      </div>
    </div>
  `).join('');
}

function bindTimelineFilters() {
  document.querySelectorAll('[data-timeline-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      const scope = button.dataset.timelineFilter;
      const kind = button.dataset.kind || 'all';
      document.querySelectorAll(`[data-timeline-filter="${scope}"]`).forEach((item) => {
        item.classList.toggle('active', item === button);
      });
      document.querySelectorAll(`[data-timeline-scope="${scope}"] [data-timeline-kind]`).forEach((row) => {
        row.classList.toggle('hidden', kind !== 'all' && row.dataset.timelineKind !== kind);
      });
    });
  });
}

function summarizeTimeline(items, relation) {
  const probes = new Set();
  const assets = new Set();
  const attackResults = { success: 0, failed: 0, attempted: 0, unknown: 0 };
  for (const item of items || []) {
    if (item.probe_id) probes.add(item.probe_id);
    if (relation === 'source' && item.dst_ip) assets.add(item.dst_ip);
    else if (relation === 'target' && item.src_ip) assets.add(item.src_ip);
    else {
      if (item.src_ip) assets.add(item.src_ip);
      if (item.dst_ip) assets.add(item.dst_ip);
    }
    const result = String(item.attack_result || 'unknown').toLowerCase();
    if (attackResults[result] !== undefined) attackResults[result] += 1;
    else attackResults.unknown += 1;
  }
  return [
    { label: relation === 'source' ? '影响目标数' : relation === 'target' ? '攻击源数' : '涉及端点数', value: String(assets.size) },
    { label: '涉及探针数', value: String(probes.size) },
    { label: '成功 / 失败', value: `${attackResults.success} / ${attackResults.failed}` },
    { label: '尝试 / 未知', value: `${attackResults.attempted} / ${attackResults.unknown}` },
  ];
}

async function showRawAlertDetail(rawAlertID, shouldNavigate = true) {
  const detail = await request(`/api/v1/raw-alerts/${rawAlertID}/detail`);
  if (detail.error) return;
  state.selectedRawAlert = detail;
  rawAlertDetailBadge.textContent = detail.item.id;
  if (shouldNavigate) {
    await navigate('raw-alert-detail', { rawAlertID });
    return;
  }
  rawAlertDetailPanel.className = 'detail-card detail-hero';
  rawAlertDetailPanel.innerHTML = `
    <div class="detail-title-row">
      <div>
        <div class="detail-subtitle">${detail.item.category || '未分类'} · ${detail.item.signature_id || '-'}</div>
        <strong>${detail.item.signature}</strong>
        <div class="cell-sub">${formatDateTime(detail.item.event_time)} · ${detail.item.probe_id} · 会话 ${detail.item.flow_id || '-'}</div>
      </div>
      <div class="detail-score-card">
        <span class="severity-badge ${formatSeverityClass(detail.item.severity)}">${formatSeverity(detail.item.severity)}</span>
        <span class="status-pill ${formatAttackResultClass(detail.item.attack_result)}">${formatAttackResult(detail.item.attack_result)}</span>
        <strong>${detail.aggregate_alerts?.length || 0}</strong>
        <span>关联聚合告警</span>
      </div>
    </div>
    <div class="detail-meta detail-meta-3">
      <span>源地址：${detail.item.src_ip}:${detail.item.src_port || '-'}</span>
      <span>目的地址：${detail.item.dst_ip}:${detail.item.dst_port || '-'}</span>
      <span>协议：${detail.item.app_proto || detail.item.proto || '-'}</span>
      <span>探针：${detail.item.probe_id || '-'}</span>
      <span>攻击结果：${formatAttackResult(detail.item.attack_result)}</span>
      <span>租户：${detail.item.tenant_id || '-'}</span>
    </div>
    <div class="event-list detail-section">
      <strong>分析上下文事件流</strong>
      ${renderProtocolPanel({ events: [detail.event], context_events: detail.context_events || [] }, 'raw-alert-detail')}
    </div>
    <div class="event-list detail-section">
      <strong>关联流量</strong>
      <div class="scroll-panel">${(detail.flows || []).map((flow) => `<code>${flow.flow_id} · ${flow.src_ip}:${flow.src_port} -> ${flow.dst_ip}:${flow.dst_port} · ${flow.app_proto || flow.proto}</code>`).join('') || '<code>暂无关联流量</code>'}</div>
    </div>
    <div class="event-list detail-section">
      <strong>关联聚合告警</strong>
      <div class="detail-actions">
        <button class="ghost" type="button" data-aggregate-link="true">按聚合条件查看</button>
      </div>
      ${(detail.aggregate_alerts || []).map((item) => `<code><a href="#/alerts/${encodeURIComponent(item.id)}">${item.signature}</a> · ${formatDateTime(item.last_seen_at)} · ${formatAttackResult(item.attack_result)}</code>`).join('') || '<code>暂无关联聚合告警</code>'}
    </div>
  `;
  document.querySelectorAll('[data-aggregate-link]').forEach((button) => button.addEventListener('click', async () => {
    srcInput.value = detail.item.src_ip || '';
    dstInput.value = detail.item.dst_ip || '';
    signatureInput.value = detail.item.signature || '';
    alertAttackResultInput.value = detail.item.attack_result || '';
    alertSinceInput.value = detail.item.event_time ? toDateTimeLocal(detail.item.event_time) : '';
    state.alertPage = 1;
    await navigate('alerts', { page: 1, pageSize: state.alertPageSize });
  }));
  bindProtocolEventFilters();
}

async function showTicketDetail(ticketID, shouldNavigate = true) {
  const detail = await request(`/api/v1/tickets/${ticketID}`);
  if (detail.error) return;
  state.selectedTicket = detail;
  $('ticket-detail-badge').textContent = detail.ticket.id;
  if (shouldNavigate) {
    await navigate('ticket-detail', { ticketID });
    return;
  }
  $('ticket-detail').className = 'detail-card';
  $('ticket-detail').innerHTML = `
    <strong>${detail.ticket.title}</strong>
    <div class="detail-meta">
      <span>状态：${formatAlertStatus(detail.ticket.status)}</span>
      <span>优先级：${formatTicketPriority(detail.ticket.priority)}</span>
      <span>处理人：${detail.ticket.assignee || '-'}</span>
      <span>关联告警：${detail.ticket.alert_id || '-'}</span>
      <span>SLA：${formatSLAStatus(detail.ticket.sla_status)}</span>
      <span>截止时间：${detail.ticket.sla_deadline ? formatDateTime(detail.ticket.sla_deadline) : '-'}</span>
      <span>最近催办：${detail.ticket.reminded_at ? formatDateTime(detail.ticket.reminded_at) : '-'}</span>
      <span>最近升级：${detail.ticket.escalated_at ? formatDateTime(detail.ticket.escalated_at) : '-'}</span>
    </div>
    <div class="event-list"><strong>处置记录</strong>${(detail.activities || []).map((activity) => `<code>${formatDateTime(activity.created_at)} · ${formatActivityAction(activity.action)}</code>`).join('') || '<code>暂无处置记录</code>'}</div>
  `;
}

async function showProbeDetail(probeID, shouldNavigate = true) {
  const detail = await request(`/api/v1/probes/${probeID}`);
  if (detail.error) return;
  state.selectedProbe = detail;
  $('probe-detail-badge').textContent = detail.probe.id;
  if (shouldNavigate) {
    await navigate('probe-detail', { probeID });
    return;
  }
  $('probe-detail').className = 'detail-card';
  $('probe-detail').innerHTML = `
    <strong>${detail.probe.name}</strong>
    <div class="detail-meta">
      <span>状态：${formatProbeStatus(detail.probe.status)}</span>
      <span>探针编码：${detail.probe.probe_code}</span>
      <span>已应用配置：${detail.probe.applied_config_id || '-'}</span>
      <span>已应用规则：${detail.probe.applied_rule_id || '-'}</span>
      <span>当前版本：${detail.probe.version || '-'}</span>
      <span>最近下发：${formatDeployStatus(detail.probe.last_deploy_status)}</span>
      <span>最近心跳：${detail.probe.last_heartbeat_at ? formatDateTime(detail.probe.last_heartbeat_at) : '-'}</span>
      <span>运行状态：${formatProbeRuntime(detail.probe)}</span>
      <span>CPU: ${Number(detail.probe.cpu_usage || 0).toFixed(1)}%</span>
      <span>内存：${Number(detail.probe.mem_usage || 0).toFixed(1)}%</span>
      <span>丢包率：${Number(detail.probe.drop_rate || 0).toFixed(2)}%</span>
    </div>
    <div class="event-list"><strong>待执行升级</strong>${detail.upgrade_task ? `<code>${formatUpgradeAction(detail.upgrade_task.action)} -> ${detail.upgrade_task.target_version} · ${formatDeployStatus(detail.upgrade_task.status)}</code>` : '<code>暂无待执行升级</code>'}</div>
    <div class="event-list"><strong>版本历史</strong>${(detail.version_history || []).map((item) => `<code>${formatDateTime(item.created_at)} · ${formatUpgradeAction(item.action)} · ${item.from_version || '-'} -> ${item.to_version} · ${formatDeployStatus(item.result)} · ${item.message}</code>`).join('') || '<code>暂无版本历史</code>'}</div>
    <div class="event-list"><strong>当前绑定</strong>${detail.binding ? `<code>配置=${detail.binding.probe_config_id} · 规则=${detail.binding.rule_bundle_id} · 更新时间=${formatDateTime(detail.binding.updated_at)}</code>` : '<code>暂无绑定</code>'}</div>
    <div class="event-list"><strong>下发记录</strong>${(detail.deployments || []).map((item) => `<code>${formatDateTime(item.created_at)} · ${formatDeployStatus(item.status)} · ${item.message}</code>`).join('') || '<code>暂无下发记录</code>'}</div>
  `;
  const metrics = await loadProbeMetrics(probeID);
  renderProbeMetrics(metrics);
}

async function updateSelectedAlert(status) {
  if (!state.selectedAlert) return;
  await request(`/api/v1/alerts/${state.selectedAlert.alert.id}`, { method: 'PATCH', body: JSON.stringify({ status, assignee: state.user?.username || '' }) });
  await showAlertDetail(state.selectedAlert.alert.id);
  await loadAlerts();
  await loadOverviewStats();
}

async function batchUpdateAlerts(status) {
  const alertIDs = Array.from(state.selectedAlertIDs);
  if (!alertIDs.length) return;
  await request('/api/v1/alerts/batch', {
    method: 'POST',
    body: JSON.stringify({
      tenant_id: tenantInput.value,
      alert_ids: alertIDs,
      status,
      assignee: state.user?.username || '',
    }),
  });
  state.selectedAlertIDs.clear();
  alertsSelectAllInput.checked = false;
  await loadAlerts();
  await loadOverviewStats();
}

async function batchCreateTicketsFromAlerts() {
  const alertIDs = Array.from(state.selectedAlertIDs);
  if (!alertIDs.length) return;
  await request('/api/v1/tickets/batch', {
    method: 'POST',
    body: JSON.stringify({
      tenant_id: tenantInput.value,
      alert_ids: alertIDs,
      title_prefix: '批量转办工单',
      description: '由告警中心批量转工单创建',
      priority: 'high',
      assignee: state.user?.username || '',
    }),
  });
  state.selectedAlertIDs.clear();
  alertsSelectAllInput.checked = false;
  await loadAlerts();
  await loadTickets();
  await loadOverviewStats();
}

async function updateSelectedTicket(status) {
  if (!state.selectedTicket) return;
  await request(`/api/v1/tickets/${state.selectedTicket.ticket.id}`, { method: 'PATCH', body: JSON.stringify({ status, assignee: state.user?.username || '' }) });
  await showTicketDetail(state.selectedTicket.ticket.id);
  await loadTickets();
  await loadOverviewStats();
}

async function batchUpdateTickets(status) {
  const ticketIDs = Array.from(state.selectedTicketIDs);
  if (!ticketIDs.length) return;
  await request('/api/v1/tickets/batch-update', {
    method: 'POST',
    body: JSON.stringify({
      tenant_id: tenantInput.value,
      ticket_ids: ticketIDs,
      status,
      assignee: state.user?.username || '',
    }),
  });
  state.selectedTicketIDs.clear();
  ticketsSelectAllInput.checked = false;
  await loadTickets();
  await loadOverviewStats();
}

async function createTicketFromAlert(event) {
  event.preventDefault();
  if (!state.selectedAlert) return;
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = state.selectedAlert.alert.tenant_id;
  data.alert_id = state.selectedAlert.alert.id;
  await request('/api/v1/tickets', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await showAlertDetail(state.selectedAlert.alert.id);
  await loadTickets();
  await loadOverviewStats();
}

async function createRole(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.permissions = splitCSV(data.permissions);
  await request('/api/v1/roles', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadRoles();
}

async function createProbeConfig(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.filters = splitCSV(data.filters);
  data.output_types = splitCSV(data.output_types);
  await request('/api/v1/probe-configs', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadProbeConfigs();
}

async function createRuleBundle(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.enabled = String(data.enabled).toLowerCase() === 'true';
  await request('/api/v1/rule-bundles', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadRuleBundles();
}

async function createNotificationChannel(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.enabled = String(data.enabled).toLowerCase() === 'true';
  data.events = splitCSV(data.events);
  await request('/api/v1/notifications/channels', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadNotificationChannels();
  await loadNotificationRecords();
}

async function createNotificationTemplate(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  await request('/api/v1/notifications/templates', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadNotificationTemplates();
}

async function applyProbeBinding(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  await request('/api/v1/probe-bindings', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadProbeBindings();
  await loadDeployments();
}

async function applyProbeBindingBatch(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  const result = await request('/api/v1/probe-bindings/batch', {
    method: 'POST',
    body: JSON.stringify({
      tenant_id: tenantInput.value,
      probe_ids: splitCSV(data.probe_ids),
      probe_config_id: data.probe_config_id,
      rule_bundle_id: data.rule_bundle_id,
    }),
  });
  $('probe-binding-batch-result').className = 'detail-card';
  $('probe-binding-batch-result').innerHTML = `
    <strong>批量绑定结果</strong>
    <div class="detail-meta">
      <span>请求数量：${result.requested || 0}</span>
      <span>成功数量：${result.applied || 0}</span>
    </div>
    <div class="event-list"><strong>明细</strong>${(result.items || []).map((item) => `<code>${item.probe_name} · 配置=${item.probe_config_id} · 规则=${item.rule_bundle_id}</code>`).join('') || '<code>暂无结果</code>'}</div>
  `;
  event.target.reset();
  await loadProbeBindings();
  await loadDeployments();
  await loadProbes();
}

async function loadProbeMetrics(probeID) {
  const params = new URLSearchParams({ limit: probeMetricsLimitInput.value || '20' });
  if (probeMetricsSinceInput.value) params.set('since', new Date(probeMetricsSinceInput.value).toISOString());
  return await request(`/api/v1/probes/${probeID}/metrics?${params.toString()}`);
}

async function createAlertExportTask() {
  const body = {
    tenant_id: tenantInput.value,
    resource_type: 'alerts',
    format: exportFormatInput.value || 'json',
    alert_query: {
      tenant_id: tenantInput.value,
      src_ip: srcInput.value,
      dst_ip: dstInput.value,
      signature: signatureInput.value,
      assignee: assigneeInput.value,
      severity: Number(severityInput.value || 0),
      since: alertSinceInput.value ? new Date(alertSinceInput.value).toISOString() : '',
      sort_by: alertSortByInput.value || 'last_seen_at',
      sort_order: alertSortOrderInput.value || 'desc',
    },
  };
  await request('/api/v1/exports', { method: 'POST', body: JSON.stringify(body) });
  await loadExportTasks();
}

async function createFlowExportTask() {
  const body = {
    tenant_id: tenantInput.value,
    resource_type: 'flows',
    format: exportFormatInput.value || 'json',
    flow_query: {
      tenant_id: tenantInput.value,
      src_ip: flowSrcInput.value,
      dst_ip: flowDstInput.value,
      app_proto: flowProtoInput.value,
    },
  };
  await request('/api/v1/exports', { method: 'POST', body: JSON.stringify(body) });
  await loadExportTasks();
}

async function downloadExportTask(taskID, format) {
  const response = await fetch(`/api/v1/exports/${taskID}/download`, {
    headers: state.token ? { Authorization: `Bearer ${state.token}` } : {},
  });
  if (!response.ok) return;
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${taskID}.${format || 'json'}`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

async function changeAlertPage(delta) {
  state.alertPage = Math.max(1, state.alertPage + delta);
  await navigate('alerts', { page: state.alertPage, pageSize: state.alertPageSize });
}

async function jumpAlertPage() {
  state.alertPage = Math.max(1, Number(alertsPageJumpInput.value || 1));
  await navigate('alerts', { page: state.alertPage, pageSize: state.alertPageSize });
}

async function changeTicketPage(delta) {
  state.ticketPage = Math.max(1, state.ticketPage + delta);
  await navigate('tickets', { page: state.ticketPage, pageSize: state.ticketPageSize });
}

async function jumpTicketPage() {
  state.ticketPage = Math.max(1, Number(ticketsPageJumpInput.value || 1));
  await navigate('tickets', { page: state.ticketPage, pageSize: state.ticketPageSize });
}

async function changeRawAlertPage(delta) {
  state.rawAlertPage = Math.max(1, state.rawAlertPage + delta);
  await navigate('raw-alerts', { page: state.rawAlertPage, pageSize: state.rawAlertPageSize });
}

async function jumpRawAlertPage() {
  state.rawAlertPage = Math.max(1, Number(rawAlertsPageJumpInput.value || 1));
  await navigate('raw-alerts', { page: state.rawAlertPage, pageSize: state.rawAlertPageSize });
}

async function resetAlertPageAndReload() {
  state.alertPage = 1;
  state.alertPageSize = Number(alertPageSizeInput.value || 10);
  persistAlertFilters();
  if (state.currentPage === 'alerts' || state.currentPage === 'alert-detail') {
    await navigate(state.currentPage === 'alert-detail' ? 'alert-detail' : 'alerts', {
      alertID: state.selectedAlert?.alert?.id,
      page: state.alertPage,
      pageSize: state.alertPageSize,
    });
  }
}

async function resetTicketPageAndReload() {
  state.ticketPage = 1;
  state.ticketPageSize = Number(ticketPageSizeInput.value || 10);
  persistTicketFilters();
  if (state.currentPage === 'tickets' || state.currentPage === 'ticket-detail') {
    await navigate(state.currentPage === 'ticket-detail' ? 'ticket-detail' : 'tickets', {
      ticketID: state.selectedTicket?.ticket?.id,
      page: state.ticketPage,
      pageSize: state.ticketPageSize,
    });
  }
}

async function resetRawAlertPageAndReload() {
  state.rawAlertPage = 1;
  state.rawAlertPageSize = Number(rawAlertPageSizeInput.value || 20);
  persistRawAlertFilters();
  if (state.currentPage === 'raw-alerts' || state.currentPage === 'raw-alert-detail') {
    await navigate(state.currentPage === 'raw-alert-detail' ? 'raw-alert-detail' : 'raw-alerts', {
      rawAlertID: state.selectedRawAlert?.item?.id,
      page: state.rawAlertPage,
      pageSize: state.rawAlertPageSize,
    });
  }
}

function persistAlertFilters() {
  localStorage.setItem(STORAGE_KEYS.alerts, JSON.stringify({
    src: srcInput.value,
    dst: dstInput.value,
    signature: signatureInput.value,
    assignee: assigneeInput.value,
    severity: severityInput.value,
    status: alertStatusInput.value,
    attackResult: alertAttackResultInput.value,
    category: alertCategoryInput.value,
    probe: alertProbeInput.value,
    minProbeCount: alertProbeCountInput.value,
    minWindowMins: alertWindowInput.value,
    since: alertSinceInput.value,
    sortBy: alertSortByInput.value,
    sortOrder: alertSortOrderInput.value,
    pageSize: alertPageSizeInput.value,
  }));
}

function persistRawAlertFilters() {
  localStorage.setItem(STORAGE_KEYS.rawAlerts, JSON.stringify({
    src: rawAlertSrcInput.value,
    dst: rawAlertDstInput.value,
    signature: rawAlertSignatureInput.value,
    probe: rawAlertProbeInput.value,
    severity: rawAlertSeverityInput.value,
    attackResult: rawAlertAttackResultInput.value,
    since: rawAlertSinceInput.value,
    pageSize: rawAlertPageSizeInput.value,
  }));
}

function persistTicketFilters() {
  localStorage.setItem(STORAGE_KEYS.tickets, JSON.stringify({
    status: ticketStatusInput.value,
    since: ticketSinceInput.value,
    sortBy: ticketSortByInput.value,
    sortOrder: ticketSortOrderInput.value,
    pageSize: ticketPageSizeInput.value,
  }));
}

function persistReportFilters() {
  localStorage.setItem(STORAGE_KEYS.reports, JSON.stringify({
    since: reportSinceInput.value,
  }));
}

function persistProbeFilters() {
  localStorage.setItem(STORAGE_KEYS.probes, JSON.stringify({
    metricsSince: probeMetricsSinceInput.value,
    metricsLimit: probeMetricsLimitInput.value,
    deploymentProbe: deploymentProbeInput.value,
    deploymentStatus: deploymentStatusInput.value,
    deploymentSince: deploymentSinceInput.value,
    deploymentLimit: deploymentLimitInput.value,
  }));
}

function persistQueryStatsFilters() {
  localStorage.setItem(STORAGE_KEYS.queryStats, JSON.stringify({
    scope: queryStatsScopeInput.value,
  }));
}

function restoreFilters() {
  restoreObject(STORAGE_KEYS.alerts, (value) => {
    srcInput.value = value.src || '';
    dstInput.value = value.dst || '';
    signatureInput.value = value.signature || '';
    assigneeInput.value = value.assignee || '';
    severityInput.value = value.severity || '';
    alertStatusInput.value = value.status || '';
    alertAttackResultInput.value = value.attackResult || '';
    alertCategoryInput.value = value.category || '';
    alertProbeInput.value = value.probe || '';
    alertProbeCountInput.value = value.minProbeCount || '';
    alertWindowInput.value = value.minWindowMins || '';
    alertSinceInput.value = value.since || '';
    alertSortByInput.value = value.sortBy || 'last_seen_at';
    alertSortOrderInput.value = value.sortOrder || 'desc';
    alertPageSizeInput.value = value.pageSize || '10';
  });
  restoreObject(STORAGE_KEYS.tickets, (value) => {
    ticketStatusInput.value = value.status || '';
    ticketSinceInput.value = value.since || '';
    ticketSortByInput.value = value.sortBy || 'created_at';
    ticketSortOrderInput.value = value.sortOrder || 'desc';
    ticketPageSizeInput.value = value.pageSize || '10';
  });
  restoreObject(STORAGE_KEYS.rawAlerts, (value) => {
    rawAlertSrcInput.value = value.src || '';
    rawAlertDstInput.value = value.dst || '';
    rawAlertSignatureInput.value = value.signature || '';
    rawAlertProbeInput.value = value.probe || '';
    rawAlertSeverityInput.value = value.severity || '';
    rawAlertAttackResultInput.value = value.attackResult || '';
    rawAlertSinceInput.value = value.since || '';
    rawAlertPageSizeInput.value = value.pageSize || '20';
  });
  restoreObject(STORAGE_KEYS.reports, (value) => {
    reportSinceInput.value = value.since || '';
  });
  restoreObject(STORAGE_KEYS.probes, (value) => {
    probeMetricsSinceInput.value = value.metricsSince || '';
    probeMetricsLimitInput.value = value.metricsLimit || '20';
    deploymentProbeInput.value = value.deploymentProbe || '';
    deploymentStatusInput.value = value.deploymentStatus || '';
    deploymentSinceInput.value = value.deploymentSince || '';
    deploymentLimitInput.value = value.deploymentLimit || '20';
  });
  restoreObject(STORAGE_KEYS.queryStats, (value) => {
    queryStatsScopeInput.value = value.scope || 'all';
  });
}

function restoreObject(key, apply) {
  try {
    const raw = localStorage.getItem(key);
    if (!raw) return;
    apply(JSON.parse(raw));
  } catch (_) {
  }
}

async function createAsset(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.tags = splitCSV(data.tags);
  await request('/api/v1/assets', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadAssets();
}

async function createOrganization(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  await request('/api/v1/organizations', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadOrganizations();
}

async function createThreatIntel(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.tags = splitCSV(data.tags);
  await request('/api/v1/threat-intel', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadThreatIntel();
}

async function createSuppressionRule(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.signature_id = Number(data.signature_id || 0);
  data.enabled = String(data.enabled).toLowerCase() === 'true';
  await request('/api/v1/suppression-rules', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadSuppressionRules();
}

async function createRiskPolicy(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.severity1_score = Number(data.severity1_score || 0);
  data.severity2_score = Number(data.severity2_score || 0);
  data.severity3_score = Number(data.severity3_score || 0);
  data.default_score = Number(data.default_score || 0);
  data.intel_hit_bonus = Number(data.intel_hit_bonus || 0);
  data.critical_asset_bonus = Number(data.critical_asset_bonus || 0);
  data.enabled = String(data.enabled).toLowerCase() === 'true';
  await request('/api/v1/risk-policies', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadRiskPolicies();
}

async function createTicketAutomationPolicy(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.reminder_before_mins = Number(data.reminder_before_mins || 0);
  data.escalation_after_mins = Number(data.escalation_after_mins || 0);
  data.enabled = String(data.enabled).toLowerCase() === 'true';
  await request('/api/v1/ticket-automation-policies', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadTicketAutomationPolicies();
}

async function createUpgradePackage(event) {
  event.preventDefault();
  const form = new FormData(event.target);
  const file = form.get('package_file');
  if (file instanceof File && file.size > 0) {
    form.set('tenant_id', tenantInput.value);
    const response = await fetch('/api/v1/upgrade-packages/upload', {
      method: 'POST',
      headers: state.token ? { Authorization: `Bearer ${state.token}` } : {},
      body: form,
    });
    if (!response.ok) {
      return;
    }
  } else {
    const data = Object.fromEntries(form.entries());
    data.tenant_id = tenantInput.value;
    data.enabled = String(data.enabled).toLowerCase() === 'true';
    delete data.package_file;
    await request('/api/v1/upgrade-packages', { method: 'POST', body: JSON.stringify(data) });
  }
  event.target.reset();
  await loadUpgradePackages();
}

async function downloadUpgradePackage(packageID) {
  const url = `/api/v1/upgrade-packages/${packageID}/download?tenant_id=${encodeURIComponent(tenantInput.value)}`;
  const response = await fetch(url, {
    headers: state.token ? { Authorization: `Bearer ${state.token}` } : {},
  });
  if (!response.ok) return;
  const blob = await response.blob();
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = `${packageID}.bin`;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(href);
}

async function createProbeUpgradeTask(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.max_retries = Number(data.max_retries || 1);
  await request('/api/v1/probe-upgrades', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadProbeUpgradeTasks();
  await loadProbes();
}

async function createProbeUpgradeTasksBatch(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  const result = await request('/api/v1/probe-upgrades/batch', {
    method: 'POST',
    body: JSON.stringify({
      tenant_id: tenantInput.value,
      probe_ids: splitCSV(data.probe_ids),
      action: data.action,
      target_version: data.target_version,
      max_retries: Number(data.max_retries || 1),
    }),
  });
  $('probe-upgrade-batch-result').className = 'detail-card';
  $('probe-upgrade-batch-result').innerHTML = `
    <strong>批量升级任务结果</strong>
    <div class="detail-meta">
      <span>请求数量：${result.requested || 0}</span>
      <span>成功数量：${result.applied || 0}</span>
    </div>
    <div class="event-list"><strong>明细</strong>${(result.items || []).map((item) => `<code>${item.probe_name} · 升级包=${item.package_id || '-'} · ${formatUpgradeAction(item.action)} ${item.previous_version || '-'} -> ${item.target_version} · 重试=${item.retry_count || 0}/${item.max_retries || 0}</code>`).join('') || '<code>暂无结果</code>'}</div>
  `;
  event.target.reset();
  await loadProbeUpgradeTasks();
  await loadProbes();
}

async function createUser(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.roles = data.role_template ? [data.role_template] : [];
  data.allowed_tenants = splitCSV(data.allowed_tenants);
  data.allowed_probe_ids = splitCSV(data.allowed_probe_ids);
  data.allowed_asset_ids = selectedValues(userAssetScopeSelect);
  data.allowed_org_ids = selectedValues(userOrgScopeSelect);
  delete data.role_template;
  await request('/api/v1/users', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  userAssetScopeSelect.selectedIndex = -1;
  userOrgScopeSelect.selectedIndex = -1;
  await loadUsers();
}

function splitCSV(value) {
  return String(value || '').split(',').map((item) => item.trim()).filter(Boolean);
}

function selectedValues(select) {
  return Array.from(select.selectedOptions || []).map((item) => item.value).filter(Boolean);
}

function renderInvestigationContext(detail) {
  const merged = mergeInvestigationEvents(detail);
  if (!merged.length) {
    return '<code>暂无可用于研判的上下文字段</code>';
  }
  return merged.map((event) => renderInvestigationEventCard(event)).join('');
}

function renderProtocolPanel(detail, scope) {
  const merged = mergeInvestigationEvents(detail);
  const visible = merged.slice(0, 36);
  if (!merged.length) {
    return '<code>暂无可用于研判的协议和上下文事件</code>';
  }
  return `
    <div class="detail-actions protocol-filters">
      <button class="ghost active" type="button" data-protocol-filter="${scope}" data-kind="all">全部</button>
      <button class="ghost" type="button" data-protocol-filter="${scope}" data-kind="http">只看 HTTP</button>
      <button class="ghost" type="button" data-protocol-filter="${scope}" data-kind="fileinfo">只看文件</button>
      <button class="ghost" type="button" data-protocol-filter="${scope}" data-kind="flow">只看 Flow</button>
    </div>
    <div class="cell-sub">共 ${merged.length} 条上下文事件，仅展示最新 ${visible.length} 条，避免详情页卡顿。</div>
    <div class="scroll-panel protocol-panel" data-protocol-scope="${scope}">
      ${renderProtocolViews(visible)}
    </div>
  `;
}

function renderProtocolViews(events) {
  if (!events.length) {
    return '<code>暂无可用于研判的协议和上下文事件</code>';
  }
  return `
    <div class="protocol-stream">
      ${events.map((event) => renderInvestigationEventCard(event)).join('')}
    </div>
  `;
}

function mergeInvestigationEvents(detail) {
  const merged = [...(detail?.context_events || []), ...(detail?.events || [])];
  const map = new Map();
  for (const event of merged) {
    const payload = event?.payload?.payload || event?.payload || {};
    const key = [
      payload.event_type || event?.event_type || '',
      payload.timestamp || event?.event_time || '',
      payload.tx_id || '',
      payload.flow_id || event?.payload?.flow_id || '',
      payload.src_ip || '',
      payload.dest_ip || payload.dst_ip || '',
      payload.alert?.signature_id || event?.payload?.alert?.signature_id || '',
    ].join('|');
    if (!map.has(key)) {
      map.set(key, event);
    }
  }
  return Array.from(map.values()).sort((left, right) => {
    const leftTime = new Date(left?.payload?.payload?.timestamp || left?.payload?.timestamp || left?.event_time || 0).getTime();
    const rightTime = new Date(right?.payload?.payload?.timestamp || right?.payload?.timestamp || right?.event_time || 0).getTime();
    return rightTime - leftTime;
  });
}

function renderInvestigationEventCard(event) {
  const payload = event?.payload?.payload || event?.payload || {};
  const eventKind = classifyInvestigationEvent(payload, event);
  const httpContext = extractHTTPContext(payload);
  const dnsContext = extractDNSContext(payload);
  const tlsContext = extractTLSContext(payload);
  const networkContext = extractNetworkContext(payload, event);
  const alertContext = extractAlertContext(payload, event);
  const fileContext = extractFileContext(payload);
  const payloadContext = extractPayloadContext(payload, httpContext);
  const bodyBlocks = [];
  if (payloadContext) {
    bodyBlocks.push(renderBodyBlock(payloadContext.label, payloadContext.value));
  }
  return `
    <div class="context-card ${eventKind === 'fileinfo' ? 'file-card' : ''}" data-protocol-kind="${escapeHTML(eventKind)}">
      <div class="context-card-head">
        <div class="context-card-title">
          <span class="tag">${formatEventType(payload.event_type || event?.payload?.event_type || 'raw')}</span>
          ${payload.app_proto || payload.proto ? `<span class="tag subtle">${escapeHTML(String(payload.app_proto || payload.proto).toUpperCase())}</span>` : ''}
          ${alertContext?.severity ? `<span class="tag ${formatSeverityClass(alertContext.severity)}">${formatSeverity(alertContext.severity)}</span>` : ''}
        </div>
        <span class="cell-sub">${formatDateTime(payload.timestamp || event?.event_time)}</span>
      </div>
      ${networkContext ? renderContextGrid(networkContext) : ''}
      ${httpContext ? renderHTTPContext(httpContext) : ''}
      ${dnsContext ? renderContextGrid(dnsContext) : ''}
      ${tlsContext ? renderContextGrid(tlsContext) : ''}
      ${alertContext ? renderContextGrid(alertContext) : ''}
      ${fileContext ? renderFileContext(fileContext) : ''}
      ${bodyBlocks.join('')}
    </div>
  `;
}

function renderContextGrid(items) {
  const values = items.filter((item) => item && item.value);
  if (!values.length) {
    return '';
  }
  return `
    <div class="context-grid">
      ${values.map((item) => `
        <div class="context-field">
          <span>${escapeHTML(item.label)}</span>
          <strong>${escapeHTML(item.value)}</strong>
        </div>
      `).join('')}
    </div>
  `;
}

function renderBodyBlock(label, value) {
  if (!value) return '';
  return `
    <div class="context-body">
      <span>${escapeHTML(label)}</span>
      <pre>${escapeHTML(value)}</pre>
    </div>
  `;
}

function renderHTTPContext(context) {
  return `
    <div class="http-view">
      <div class="http-summary-grid">
        ${context.method ? `<div class="context-field"><span>请求方法</span><strong>${escapeHTML(context.method)}</strong></div>` : ''}
        ${context.url ? `<div class="context-field"><span>请求地址</span><strong>${escapeHTML(context.url)}</strong></div>` : ''}
        ${context.host ? `<div class="context-field"><span>主机名</span><strong>${escapeHTML(context.host)}</strong></div>` : ''}
        ${context.status ? `<div class="context-field"><span>响应状态</span><strong>${escapeHTML(context.status)}</strong></div>` : ''}
        ${context.userAgent ? `<div class="context-field"><span>User-Agent</span><strong>${escapeHTML(context.userAgent)}</strong></div>` : ''}
        ${context.contentType ? `<div class="context-field"><span>内容类型</span><strong>${escapeHTML(context.contentType)}</strong></div>` : ''}
      </div>
      <div class="http-columns">
        <div class="http-column">
          <div class="context-list">
            <span>请求头</span>
            ${context.requestHeaders?.length ? context.requestHeaders.map((item) => `<code>${escapeHTML(item.name)}: ${escapeHTML(item.value)}</code>`).join('') : '<code>暂无可用请求头</code>'}
          </div>
          ${context.requestBody ? renderBodyBlock('请求体', context.requestBody) : ''}
        </div>
        <div class="http-column">
          <div class="context-list">
            <span>响应信息</span>
            ${context.status ? `<code>HTTP ${escapeHTML(context.status)}</code>` : '<code>暂无响应状态</code>'}
            ${context.responseHeaders?.length ? context.responseHeaders.map((item) => `<code>${escapeHTML(item.name)}: ${escapeHTML(item.value)}</code>`).join('') : ''}
          </div>
          ${context.responseBody ? renderBodyBlock('响应体', context.responseBody) : ''}
        </div>
      </div>
    </div>
  `;
}

function extractHTTPContext(payload) {
  const http = payload?.http && typeof payload.http === 'object' ? payload.http : {};
  const method = firstNonEmpty(http.http_method, payload.http_method, payload.method);
  const url = firstNonEmpty(http.url, payload.url, payload.uri);
  const host = firstNonEmpty(http.hostname, payload.hostname, http.host, payload.host);
  const userAgent = firstNonEmpty(http.http_user_agent, payload.http_user_agent, payload.user_agent);
  const contentType = firstNonEmpty(http.http_content_type, payload.http_content_type, payload.content_type);
  const status = firstNonEmpty(http.status, payload.status, payload.http_status);
  const requestBodyRaw = decodeBodyField(
    firstNonEmpty(
      payload.http_body,
      payload['http-body'],
      payload.http_request_body,
      payload.request_body,
      http.http_body,
      http.body,
    ),
  );
  const responseBodyRaw = decodeBodyField(firstNonEmpty(payload.http_response_body, http.http_response_body, payload.response_body));
  const requestText = firstReadableHTTPText(
    payload.payload_printable,
    payload.payload,
  );
  const requestParsed = parseHTTPRequest(requestText);
  const requestHeaders = filterUsefulHeaders(requestParsed.headers || []);
  const requestBody = summarizeText(selectUsefulBody(requestBodyRaw || requestParsed.body, contentType), 1200);
  const responseBody = summarizeText(selectUsefulBody(responseBodyRaw, contentType), 1200);
  if (!method && !url && !host && !userAgent && !contentType && !status && !requestBody && !responseBody && !requestHeaders.length) {
    return null;
  }
  return {
    method,
    url,
    host,
    userAgent,
    contentType,
    status,
    requestHeaders,
    responseHeaders: [],
    requestBody,
    responseBody,
  };
}

function extractNetworkContext(payload, event) {
  const srcIP = firstNonEmpty(payload.src_ip, event?.payload?.src_ip);
  const srcPort = firstNonEmpty(payload.src_port, event?.payload?.src_port);
  const dstIP = firstNonEmpty(payload.dest_ip, payload.dst_ip, event?.payload?.dst_ip);
  const dstPort = firstNonEmpty(payload.dest_port, payload.dst_port, event?.payload?.dst_port);
  const direction = firstNonEmpty(payload.direction);
  const txID = firstNonEmpty(payload.tx_id);
  const flowID = firstNonEmpty(payload.flow_id, event?.payload?.flow_id);
  const appProto = firstNonEmpty(payload.app_proto, payload.proto);
  return [
    { label: '源地址', value: srcIP ? `${srcIP}${srcPort ? `:${srcPort}` : ''}` : '' },
    { label: '目的地址', value: dstIP ? `${dstIP}${dstPort ? `:${dstPort}` : ''}` : '' },
    { label: '方向', value: direction },
    { label: '会话 ID', value: flowID },
    { label: '事务 ID', value: txID },
    { label: '协议', value: appProto },
  ];
}

function extractAlertContext(payload, event) {
  const alert = payload?.alert || event?.payload?.alert;
  if (!alert || typeof alert !== 'object') {
    return null;
  }
  const metadata = alert.metadata && typeof alert.metadata === 'object' ? alert.metadata : {};
  const cve = firstNonEmpty(...toFlatValues(metadata.cve));
  const tactic = firstNonEmpty(...toFlatValues(metadata.mitre_tactic_name));
  const technique = firstNonEmpty(...toFlatValues(metadata.mitre_technique_name));
  const severity = Number(alert.severity || 0);
  return [
    { label: '告警名称', value: firstNonEmpty(alert.signature) },
    { label: '攻击分类', value: firstNonEmpty(alert.category) },
    { label: 'CVE', value: cve },
    { label: '攻击阶段', value: tactic },
    { label: '攻击技术', value: technique },
    { label: '规则 ID', value: firstNonEmpty(alert.signature_id) },
    { label: '严重级别', value: severity ? formatSeverity(severity) : '', severity },
  ];
}

function extractFileContext(payload) {
  const file = Array.isArray(payload?.files) && payload.files.length ? payload.files[0] : null;
  if (!file || typeof file !== 'object') {
    return null;
  }
  return {
    fileName: firstNonEmpty(file.filename),
    size: firstNonEmpty(file.size),
    state: firstNonEmpty(file.state),
    stored: firstNonEmpty(file.stored),
    gaps: firstNonEmpty(file.gaps),
    txID: firstNonEmpty(file.tx_id, payload.tx_id),
  };
}

function extractDNSContext(payload) {
  const dns = payload?.dns && typeof payload.dns === 'object' ? payload.dns : payload;
  const rrname = firstNonEmpty(dns.rrname, payload.rrname, dns.query);
  const rrtype = firstNonEmpty(dns.rrtype, payload.rrtype);
  const txID = firstNonEmpty(dns.tx_id, payload.tx_id);
  const answers = Array.isArray(dns.answers) ? dns.answers.map((item) => item.rdata || item).filter(Boolean).slice(0, 3).join(', ') : '';
  if (!rrname && !rrtype && !txID && !answers) {
    return null;
  }
  return [
    { label: '查询域名', value: rrname },
    { label: '记录类型', value: rrtype },
    { label: '事务 ID', value: txID },
    { label: '解析结果', value: answers },
  ];
}

function extractTLSContext(payload) {
  const tls = payload?.tls && typeof payload.tls === 'object' ? payload.tls : payload;
  const sni = firstNonEmpty(tls.sni, payload.sni);
  const version = firstNonEmpty(tls.version, payload.version);
  const subject = firstNonEmpty(tls.subject, payload.subject);
  const issuer = firstNonEmpty(tls.issuerdn, tls.issuer, payload.issuer);
  const ja3 = firstNonEmpty(tls.ja3, payload.ja3);
  if (!sni && !version && !subject && !issuer && !ja3) {
    return null;
  }
  return [
    { label: 'SNI', value: sni },
    { label: 'TLS 版本', value: version },
    { label: '证书主题', value: subject },
    { label: '签发者', value: issuer },
    { label: 'JA3', value: ja3 },
  ];
}

function extractPayloadContext(payload, httpContext) {
  if (httpContext?.requestHeaders?.length || httpContext?.requestBody || httpContext?.responseBody) {
    return null;
  }
  const printable = summarizeText(firstNonEmpty(payload.payload_printable), 500);
  if (printable) {
    return { label: '可读载荷摘要', value: printable };
  }
  const decodedPayload = summarizeText(decodeBodyField(firstNonEmpty(payload.payload)), 500);
  if (decodedPayload) {
    return { label: '载荷摘要', value: decodedPayload };
  }
  return null;
}

function toFlatValues(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item || '').trim()).filter(Boolean);
  }
  if (value === undefined || value === null) {
    return [];
  }
  return [String(value).trim()].filter(Boolean);
}

function summarizeText(value, maxLength) {
  const text = String(value || '').trim();
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)} ...`;
}

function formatEventType(value) {
  const normalized = String(value || '').toLowerCase();
  const mapping = {
    alert: '告警命中',
    http: 'HTTP 请求/响应',
    dns: 'DNS 解析',
    tls: 'TLS 握手',
    fileinfo: '文件传输信息',
    flow: '流量会话',
  };
  return mapping[normalized] || (value || '事件');
}

function classifyInvestigationEvent(payload, event) {
  const normalized = String(payload.event_type || event?.payload?.event_type || '').toLowerCase();
  if (normalized === 'http' || normalized === 'dns' || normalized === 'tls' || normalized === 'flow' || normalized === 'fileinfo') {
    return normalized;
  }
  if (Array.isArray(payload?.files) && payload.files.length) {
    return 'fileinfo';
  }
  return normalized || 'other';
}

function renderFileContext(context) {
  if (!context) return '';
  return `
    <div class="file-highlight-card">
      <div class="file-highlight-head">
        <span class="tag tag-warm">文件事件</span>
        <strong>${escapeHTML(context.fileName || '未命名文件')}</strong>
      </div>
      <div class="context-grid">
        ${context.size ? `<div class="context-field"><span>文件大小</span><strong>${escapeHTML(context.size)}</strong></div>` : ''}
        ${context.state ? `<div class="context-field"><span>文件状态</span><strong>${escapeHTML(context.state)}</strong></div>` : ''}
        ${context.stored ? `<div class="context-field"><span>是否落盘</span><strong>${escapeHTML(context.stored)}</strong></div>` : ''}
        ${context.gaps ? `<div class="context-field"><span>是否缺包</span><strong>${escapeHTML(context.gaps)}</strong></div>` : ''}
        ${context.txID ? `<div class="context-field"><span>事务 ID</span><strong>${escapeHTML(context.txID)}</strong></div>` : ''}
      </div>
    </div>
  `;
}

function firstReadableHTTPText(...values) {
  for (const value of values) {
    const decoded = decodeBodyField(value);
    if (!decoded) continue;
    if (looksLikeHTTPRequest(decoded)) {
      return decoded;
    }
  }
  return '';
}

function looksLikeHTTPRequest(value) {
  const text = String(value || '');
  return /^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+\S+\s+HTTP\/\d/i.test(text.trim());
}

function parseHTTPRequest(value) {
  const text = String(value || '').replace(/\r\n/g, '\n');
  if (!text.trim()) {
    return { headers: [], body: '' };
  }
  const [head, ...bodyParts] = text.split('\n\n');
  const lines = head.split('\n').map((line) => line.trim()).filter(Boolean);
  const headers = [];
  for (const line of lines.slice(1)) {
    const index = line.indexOf(':');
    if (index === -1) continue;
    headers.push({ name: line.slice(0, index).trim(), value: line.slice(index + 1).trim() });
  }
  return {
    headers,
    body: bodyParts.join('\n\n').trim(),
  };
}

function filterUsefulHeaders(headers) {
  const allow = new Set(['host', 'user-agent', 'content-type', 'content-length', 'referer', 'x-forwarded-for', 'accept']);
  return (headers || []).filter((item) => allow.has(String(item.name || '').toLowerCase()));
}

function selectUsefulBody(value, contentType) {
  const text = String(value || '').trim();
  if (!text) return '';
  const type = String(contentType || '').toLowerCase();
  if (type.includes('json') || type.includes('xml') || type.includes('x-www-form-urlencoded') || type.includes('text') || looksStructuredContent(text)) {
    return text;
  }
  if (isReadableAnalysisText(text)) {
    return text;
  }
  return '';
}

function looksStructuredContent(value) {
  const text = String(value || '').trim();
  return text.startsWith('{') || text.startsWith('[') || text.startsWith('<') || text.includes('=');
}

function isReadableAnalysisText(value) {
  const text = String(value || '').trim();
  if (!text) return false;
  const sample = text.slice(0, 400);
  const printable = sample.replace(/[\x09\x0A\x0D\x20-\x7E]/g, '');
  return printable.length < sample.length * 0.15;
}

function bindProtocolEventFilters() {
  document.querySelectorAll('[data-protocol-filter]').forEach((button) => {
    button.addEventListener('click', () => {
      const scope = button.dataset.protocolFilter;
      const kind = button.dataset.kind || 'all';
      document.querySelectorAll(`[data-protocol-filter="${scope}"]`).forEach((item) => {
        item.classList.toggle('active', item === button);
      });
      document.querySelectorAll(`[data-protocol-scope="${scope}"] [data-protocol-kind]`).forEach((card) => {
        const current = card.dataset.protocolKind || 'other';
        card.classList.toggle('hidden', kind !== 'all' && current !== kind);
      });
    });
  });
}

function decodeBodyField(value) {
  if (!value) return '';
  if (typeof value !== 'string') {
    return JSON.stringify(value, null, 2);
  }
  const trimmed = value.trim();
  if (!trimmed) return '';
  if (trimmed.length > 32768) {
    return '';
  }
  if (!/^[A-Za-z0-9+/=\r\n]+$/.test(trimmed)) {
    return trimmed;
  }
  try {
    const normalized = trimmed.replace(/\s+/g, '');
    const decoded = atob(normalized);
    if (decoded && /[\x09\x0A\x0D\x20-\x7E]/.test(decoded)) {
      const nonPrintable = decoded.replace(/[\x09\x0A\x0D\x20-\x7E]/g, '');
      if (nonPrintable.length > decoded.length * 0.2) {
        return '';
      }
      return decoded;
    }
  } catch (_) {
  }
  return trimmed;
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (value !== undefined && value !== null && String(value).trim() !== '') {
      return String(value);
    }
  }
  return '';
}

function escapeHTML(value) {
  return String(value || '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatDateTime(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  return date.toLocaleString('zh-CN', { hour12: false });
}

function toDateTimeLocal(value) {
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const local = new Date(date.getTime() - date.getTimezoneOffset() * 60000);
  return local.toISOString().slice(0, 16);
}

function formatDurationSince(value) {
  if (!value) return '-';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '-';
  const diff = Math.max(0, Date.now() - date.getTime());
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds} 秒前`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes} 分钟前`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} 小时前`;
  const days = Math.floor(hours / 24);
  return `${days} 天前`;
}

function formatSeverity(value) {
  switch (Number(value || 0)) {
    case 1:
      return '高危';
    case 2:
      return '中危';
    case 3:
      return '低危';
    default:
      return '未知';
  }
}

function formatSeverityClass(value) {
  switch (Number(value || 0)) {
    case 1:
      return 'severity-high';
    case 2:
      return 'severity-medium';
    case 3:
      return 'severity-low';
    default:
      return 'severity-unknown';
  }
}

function formatAlertStatus(value) {
  switch (String(value || '').toLowerCase()) {
    case 'new':
      return '待研判';
    case 'ack':
      return '已确认';
    case 'closed':
      return '已关闭';
    case 'in_progress':
      return '处理中';
    case 'open':
      return '打开';
    default:
      return value || '未知';
  }
}

function formatStatusClass(value) {
  switch (String(value || '').toLowerCase()) {
    case 'new':
      return 'status-new';
    case 'ack':
      return 'status-ack';
    case 'closed':
      return 'status-closed';
    case 'in_progress':
      return 'status-progress';
    case 'open':
      return 'status-open';
    default:
      return 'status-default';
  }
}

function formatAttackResult(value) {
  switch (String(value || '').toLowerCase()) {
    case 'success':
      return '成功';
    case 'failed':
      return '失败';
    case 'attempted':
      return '尝试';
    default:
      return '未知';
  }
}

function formatAttackResultClass(value) {
  switch (String(value || '').toLowerCase()) {
    case 'success':
      return 'status-ack';
    case 'failed':
      return 'status-new';
    case 'attempted':
      return 'status-progress';
    default:
      return 'status-default';
  }
}

function formatProbeSummary(probeIDs) {
  const items = probeIDs || [];
  if (!items.length) return '未标记探针';
  return items.length === 1 ? `探针 ${items[0]}` : `探针 ${items[0]} 等 ${items.length} 个`;
}

function formatTicketPriority(value) {
  switch (String(value || '').toLowerCase()) {
    case 'critical':
      return '紧急';
    case 'high':
      return '高';
    case 'medium':
      return '中';
    case 'low':
      return '低';
    default:
      return value || '-';
  }
}

function formatPriorityClass(value) {
  switch (String(value || '').toLowerCase()) {
    case 'critical':
      return 'severity-high';
    case 'high':
      return 'severity-medium';
    case 'medium':
      return 'severity-low';
    case 'low':
      return 'severity-unknown';
    default:
      return 'severity-unknown';
  }
}

function formatSLAStatus(value) {
  switch (String(value || '').toLowerCase()) {
    case 'active':
      return '正常';
    case 'breached':
      return '已超时';
    default:
      return value || '-';
  }
}

function formatActivityAction(value) {
  const actions = {
    update_alert_status: '更新告警状态',
    create_ticket: '创建工单',
    update_ticket_status: '更新工单状态',
    register_probe: '探针注册',
    heartbeat_probe: '探针心跳',
  };
  return actions[value] || value || '-';
}

function formatTimelineRelation(value) {
  switch (String(value || '').toLowerCase()) {
    case 'source':
      return '同源';
    case 'target':
      return '同目标';
    case 'flow':
      return '同 Flow';
    default:
      return value || '时间线';
  }
}

function formatTimelineKind(value) {
  switch (String(value || '').toLowerCase()) {
    case 'aggregate':
      return '聚合告警';
    case 'raw':
      return '原始命中';
    case 'protocol':
      return '协议事件';
    default:
      return '时间线';
  }
}

function formatProbeStatus(value) {
  switch (String(value || '').toLowerCase()) {
    case 'online':
      return '在线';
    case 'offline':
      return '离线';
    default:
      return value || '未知';
  }
}

function formatProbeStatusClass(value) {
  switch (String(value || '').toLowerCase()) {
    case 'online':
      return 'status-ack';
    case 'offline':
      return 'status-new';
    default:
      return 'status-default';
  }
}

function formatProbeRuntime(probe) {
  if (!probe) return '-';
  const since = formatDurationSince(probe.last_heartbeat_at);
  if (String(probe.status || '').toLowerCase() === 'offline') {
    return `离线时长 ${since}`;
  }
  return `最后活跃 ${since}`;
}

function formatDeployStatus(value) {
  switch (String(value || '').toLowerCase()) {
    case 'pending':
      return '待下发';
    case 'applied':
    case 'success':
      return '成功';
    case 'failed':
      return '失败';
    default:
      return value || '-';
  }
}

function formatDeployStatusClass(value) {
  switch (String(value || '').toLowerCase()) {
    case 'pending':
      return 'status-progress';
    case 'applied':
    case 'success':
      return 'status-ack';
    case 'failed':
      return 'status-new';
    default:
      return 'status-default';
  }
}

function formatUpgradeAction(value) {
  return String(value || '').toLowerCase() === 'rollback' ? '回滚' : '升级';
}

function formatExportStatus(value) {
  switch (String(value || '').toLowerCase()) {
    case 'completed':
      return '已完成';
    case 'delivered':
      return '已送达';
    case 'running':
      return '执行中';
    case 'failed':
      return '失败';
    case 'expired':
      return '已过期';
    default:
      return value || '-';
  }
}

function formatNotificationChannelType(value) {
  switch (String(value || '').toLowerCase()) {
    case 'webhook':
      return 'Webhook';
    case 'console':
      return '控制台';
    default:
      return value || '-';
  }
}

function renderList(id, items, formatter) {
  $(id).innerHTML = (items || []).map((item) => `<li>${formatter(item)}</li>`).join('') || '<li>暂无数据</li>';
}

function renderRoleGroup(title, items) {
  return `
    <li class="group-title">${title}</li>
    ${items && items.length ? items.map((item) => `
      <li>
        <div class="list-line">
          <strong>${ROLE_PROFILES[item.name]?.label || item.name}</strong>
          <span class="role-chip role-chip-light">${item.name}</span>
        </div>
        <div class="list-meta">${ROLE_PROFILES[item.name]?.desc || item.description || '自定义角色'}</div>
        <div class="list-meta">权限：${(item.permissions || []).join(', ') || '无'}</div>
      </li>
    `).join('') : '<li class="muted">暂无数据</li>'}
  `;
}

function syncSelectedAlerts(alerts) {
  const visibleIDs = new Set((alerts || []).map((alert) => alert.id));
  state.selectedAlertIDs = new Set(Array.from(state.selectedAlertIDs).filter((id) => visibleIDs.has(id)));
}

function toggleSelectAllAlerts(checked) {
  document.querySelectorAll('.alert-select').forEach((input) => {
    input.checked = checked;
    const alertID = input.dataset.alertId;
    if (!alertID) return;
    if (checked) {
      state.selectedAlertIDs.add(alertID);
    } else {
      state.selectedAlertIDs.delete(alertID);
    }
  });
}

function updateSelectAllState(alerts) {
  const items = alerts || [];
  if (!items.length) {
    alertsSelectAllInput.checked = false;
    alertsSelectAllInput.indeterminate = false;
    return;
  }
  const selectedCount = items.filter((alert) => state.selectedAlertIDs.has(alert.id)).length;
  alertsSelectAllInput.checked = selectedCount === items.length;
  alertsSelectAllInput.indeterminate = selectedCount > 0 && selectedCount < items.length;
}

function syncSelectedTickets(tickets) {
  const visibleIDs = new Set((tickets || []).map((ticket) => ticket.id));
  state.selectedTicketIDs = new Set(Array.from(state.selectedTicketIDs).filter((id) => visibleIDs.has(id)));
}

function toggleSelectAllTickets(checked) {
  document.querySelectorAll('.ticket-select').forEach((input) => {
    input.checked = checked;
    const ticketID = input.dataset.ticketId;
    if (!ticketID) return;
    if (checked) {
      state.selectedTicketIDs.add(ticketID);
    } else {
      state.selectedTicketIDs.delete(ticketID);
    }
  });
}

function updateSelectAllTicketsState(tickets) {
  const items = tickets || [];
  if (!items.length) {
    ticketsSelectAllInput.checked = false;
    ticketsSelectAllInput.indeterminate = false;
    return;
  }
  const selectedCount = items.filter((ticket) => state.selectedTicketIDs.has(ticket.id)).length;
  ticketsSelectAllInput.checked = selectedCount === items.length;
  ticketsSelectAllInput.indeterminate = selectedCount > 0 && selectedCount < items.length;
}

function renderChart(id, items) {
  const container = $(id);
  const dataset = items || [];
  if (!dataset.length) {
    container.innerHTML = '<div class="chart-bar"><span class="chart-bar-label">暂无数据</span></div>';
    return;
  }
  const maxValue = Math.max(...dataset.map((item) => item.count || 0), 1);
  container.innerHTML = dataset.map((item) => {
    const height = Math.max(8, Math.round(((item.count || 0) / maxValue) * 120));
    return `
      <div class="chart-bar">
        <span class="chart-bar-value">${item.count || 0}</span>
        <div class="chart-bar-fill" style="height:${height}px"></div>
        <span class="chart-bar-label">${item.date}</span>
      </div>
    `;
  }).join('');
}

function renderProbeMetrics(items) {
  const dataset = (items || []).slice().reverse();
  const cpu = dataset.map((item) => ({
    date: new Date(item.created_at).toLocaleTimeString(),
    count: Number(item.cpu_usage || 0),
  }));
  const mem = dataset.map((item) => ({
    date: new Date(item.created_at).toLocaleTimeString(),
    count: Number(item.mem_usage || 0),
  }));
  const drop = dataset.map((item) => ({
    date: new Date(item.created_at).toLocaleTimeString(),
    count: Number(item.drop_rate || 0),
  }));
  renderChart('probe-metrics-chart-cpu', cpu);
  renderChart('probe-metrics-chart-mem', mem);
  renderChart('probe-metrics-chart-drop', drop);
}

async function request(url, options = {}, auth = true) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
  if (auth && state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(url, { ...options, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) return { error: data.error || response.statusText };
  return data;
}

function showApp() {
  const profile = resolveRoleProfile(state.user);
  $('user-summary').textContent = `${state.user.display_name} · ${state.user.tenant_id} · ${profile.label}`;
  $('login-view').classList.add('hidden');
  $('app-view').classList.remove('hidden');
}

function resolveRoleProfile(user) {
  const roleNames = Array.isArray(user?.roles) ? user.roles : [];
  for (const roleName of roleNames) {
    if (ROLE_PROFILES[roleName]) {
      return ROLE_PROFILES[roleName];
    }
  }
  return {
    label: roleNames[0] || '未分类角色',
    desc: '未命中预置角色模板，默认展示全部模块。',
    modules: MODULES.map((module) => module.id),
    focus: [],
  };
}

function syncRoleProfilesWithTemplates(templates) {
  for (const template of templates || []) {
    if (!template?.name) continue;
    if (!ROLE_PROFILES[template.name]) {
      ROLE_PROFILES[template.name] = { label: template.label || template.name, desc: template.description || '', modules: template.modules || [], focus: [] };
      continue;
    }
    ROLE_PROFILES[template.name].label = template.label || ROLE_PROFILES[template.name].label;
    ROLE_PROFILES[template.name].desc = template.description || ROLE_PROFILES[template.name].desc;
    if (Array.isArray(template.modules) && template.modules.length) {
      ROLE_PROFILES[template.name].modules = template.modules;
    }
  }
}

function renderUserRoleTemplateOptions() {
  const select = $('user-role-template');
  if (!select) return;
  const templates = state.roleTemplates || [];
  if (!templates.length) return;
  select.innerHTML = templates.map((template) => `<option value="${template.name}">${template.label}</option>`).join('');
}

function formatRoles(roles) {
  return (roles || []).map((role) => ROLE_PROFILES[role]?.label || role);
}

function formatOverviewStatValue(key, stats) {
  switch (key) {
    case 'alerts_open':
      return String(stats.alerts_open ?? 0);
    case 'alerts_closed':
      return String(stats.alerts_closed ?? 0);
    case 'probes_online':
      return String(stats.probes_online ?? 0);
    case 'tickets_open':
      return String(stats.tickets_open ?? 0);
    case 'flows_observed':
      return String(stats.flows_observed ?? 0);
    default:
      return '-';
  }
}

function buildOverviewStats(profile, stats) {
  const metricMap = {
    alerts_open: { label: '待处理告警', value: stats.alerts_open ?? 0 },
    alerts_closed: { label: '已关闭告警', value: stats.alerts_closed ?? 0 },
    probes_online: { label: '在线探针', value: stats.probes_online ?? 0 },
    tickets_open: { label: '处理中工单', value: stats.tickets_open ?? 0 },
    flows_observed: { label: '已观测流量', value: stats.flows_observed ?? 0 },
  };
  const labelMap = {
    '超级管理员': ['probes_online', 'alerts_open', 'tickets_open', 'flows_observed'],
    '系统管理员': ['probes_online', 'tickets_open', 'alerts_closed', 'flows_observed'],
    '安全运营人员': ['alerts_open', 'tickets_open', 'alerts_closed', 'flows_observed'],
    '安全分析人员': ['alerts_open', 'flows_observed', 'alerts_closed', 'probes_online'],
    '审计人员': ['alerts_closed', 'tickets_open', 'probes_online', 'flows_observed'],
  };
  return (labelMap[profile.label] || ['alerts_open', 'probes_online', 'tickets_open', 'flows_observed']).map((key) => metricMap[key]);
}

function startExportAutoRefresh() {
  stopExportAutoRefresh();
  state.exportRefreshTimer = window.setInterval(async () => {
    if (state.currentPage === 'exports') {
      await loadExportTasks();
    }
  }, 5000);
}

function stopExportAutoRefresh() {
  if (state.exportRefreshTimer) {
    window.clearInterval(state.exportRefreshTimer);
    state.exportRefreshTimer = null;
  }
}

(async function bootstrap() {
  if (!state.token) return;
  const currentUser = await request('/api/v1/auth/me');
  if (currentUser.error) {
    localStorage.removeItem('ndr_token');
    return;
  }
  state.user = currentUser;
  await afterLogin();
})();
