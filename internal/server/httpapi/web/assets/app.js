const state = {
  token: localStorage.getItem('ndr_token') || '',
  user: null,
  modules: [],
  currentPage: 'overview',
  selectedAlert: null,
  selectedTicket: null,
  selectedProbe: null,
  alertPage: 1,
  ticketPage: 1,
  alertPageSize: 10,
  ticketPageSize: 10,
  exportRefreshTimer: null,
};

const STORAGE_KEYS = {
  alerts: 'ndr_alert_filters',
  tickets: 'ndr_ticket_filters',
  reports: 'ndr_report_filters',
  probes: 'ndr_probe_filters',
  queryStats: 'ndr_query_stats_filters',
};

const MODULES = [
  { id: 'overview', title: '总览', desc: '模块入口和整体视图', permission: null },
  { id: 'alerts', title: '告警中心', desc: '告警筛选、详情和处置', permission: 'alert.read' },
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
const alertSinceInput = $('alert-since-filter');
const alertSortByInput = $('alert-sort-by');
const alertSortOrderInput = $('alert-sort-order');
const alertPageSizeInput = $('alert-page-size');
const alertsPageJumpInput = $('alerts-page-jump');
const alertsTotalInfo = $('alerts-total-info');
const backToAlertsBtn = $('back-to-alerts-btn');
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
const assetForm = $('asset-form');
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
$('tickets-prev-btn').addEventListener('click', async () => changeTicketPage(-1));
$('tickets-next-btn').addEventListener('click', async () => changeTicketPage(1));
$('tickets-jump-btn').addEventListener('click', async () => jumpTicketPage());
$('export-alerts-btn').addEventListener('click', async () => createAlertExportTask());
$('export-flows-btn').addEventListener('click', async () => createFlowExportTask());
$('export-alerts-page-btn').addEventListener('click', async () => createAlertExportTask());
$('export-flows-page-btn').addEventListener('click', async () => createFlowExportTask());
$('refresh-exports-btn').addEventListener('click', async () => loadExportTasks());
$('refresh-query-stats-btn').addEventListener('click', async () => loadQueryStats());
backToAlertsBtn.addEventListener('click', async () => {
  navigate('alerts');
  await loadAlerts();
});

[srcInput, dstInput, signatureInput, assigneeInput, severityInput, alertStatusInput, alertCategoryInput, alertProbeInput, alertSinceInput, alertSortByInput, alertSortOrderInput, alertPageSizeInput]
  .forEach((input) => input.addEventListener('change', async () => resetAlertPageAndReload()));
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
  if (state.selectedProbe?.probe?.id) {
    await showProbeDetail(state.selectedProbe.probe.id);
  }
});
probeMetricsLimitInput.addEventListener('change', async () => {
  persistProbeFilters();
  if (state.selectedProbe?.probe?.id) {
    await showProbeDetail(state.selectedProbe.probe.id);
  }
});
[deploymentProbeInput, deploymentStatusInput, deploymentSinceInput, deploymentLimitInput]
  .forEach((input) => input.addEventListener('change', async () => {
    persistProbeFilters();
    if (state.currentPage === 'probes') {
      await loadDeployments();
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
  tenantInput.value = state.user.tenant_id;
  state.alertPageSize = Number(alertPageSizeInput.value || 10);
  state.ticketPageSize = Number(ticketPageSizeInput.value || 10);
  state.modules = resolveModules(state.user.permissions || []);
  renderNavigation();
  renderOverviewCards();
  showApp();
  navigate(state.modules[0]?.id || 'overview');
  await refreshCurrentPage();
}

function resolveModules(permissions) {
  return MODULES.filter((module) => !module.permission || permissions.includes('*') || permissions.includes(module.permission));
}

function renderNavigation() {
  $('nav-menu').innerHTML = state.modules.map((module) => `
    <button class="nav-btn ${module.id === state.currentPage ? 'active' : ''}" data-page="${module.id}">${module.title}</button>
  `).join('');
  document.querySelectorAll('.nav-btn').forEach((button) => {
    button.addEventListener('click', async () => {
      navigate(button.dataset.page);
      await refreshCurrentPage();
    });
  });
}

function renderOverviewCards() {
  $('overview-cards').innerHTML = state.modules.filter((module) => module.id !== 'overview').map((module) => `
    <button class="module-card" data-page="${module.id}">
      <strong>${module.title}</strong>
      <span>${module.desc}</span>
    </button>
  `).join('');
  document.querySelectorAll('.module-card').forEach((button) => {
    button.addEventListener('click', async () => {
      navigate(button.dataset.page);
      await refreshCurrentPage();
    });
  });
}

function navigate(page) {
  stopExportAutoRefresh();
  state.currentPage = page;
  const current = MODULES.find((item) => item.id === page);
  $('page-title').textContent = page === 'alert-detail' ? '告警详情' : (current?.title || '总览');
  document.querySelectorAll('.page').forEach((pageEl) => pageEl.classList.add('hidden'));
  const target = $(`page-${page}`);
  if (target) target.classList.remove('hidden');
  document.querySelectorAll('.nav-btn').forEach((button) => {
    button.classList.toggle('active', button.dataset.page === (page === 'alert-detail' ? 'alerts' : page));
  });
  if (page === 'exports') {
    startExportAutoRefresh();
  }
}

async function refreshCurrentPage() {
  await loadOverviewStats();
  switch (state.currentPage) {
    case 'alerts':
      await loadAlerts();
      break;
    case 'alert-detail':
      if (state.selectedAlert?.alert?.id) {
        await showAlertDetail(state.selectedAlert.alert.id, false);
      }
      break;
    case 'flows':
      await loadFlows();
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
  const stats = await request(`/api/v1/dashboard/stats?tenant_id=${encodeURIComponent(tenant)}`);
  $('stat-alerts').textContent = stats.alerts_open ?? 0;
  $('stat-probes').textContent = stats.probes_online ?? 0;
  $('stat-tickets').textContent = stats.tickets_open ?? 0;
  $('stat-flows').textContent = stats.flows_observed ?? 0;
}

async function loadAlerts() {
  const params = new URLSearchParams({ tenant_id: tenantInput.value });
  if (srcInput.value) params.set('src_ip', srcInput.value);
  if (dstInput.value) params.set('dst_ip', dstInput.value);
  if (signatureInput.value) params.set('signature', signatureInput.value);
  if (assigneeInput.value) params.set('assignee', assigneeInput.value);
  if (severityInput.value) params.set('severity', severityInput.value);
  if (alertStatusInput.value) params.set('status', alertStatusInput.value);
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
  $('alerts-body').innerHTML = alerts.map((alert) => `
    <tr data-alert-id="${alert.id}" class="alert-row">
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
        <div class="cell-sub">${formatProbeSummary(alert.probe_ids)}</div>
      </td>
      <td>
        <div class="cell-primary">${alert.dst_ip}:${alert.dst_port}</div>
        <div class="cell-sub">${alert.target_asset_name || '未识别资产'}</div>
      </td>
      <td>${alert.target_asset_name || '-'}</td>
      <td><span class="status-pill ${formatStatusClass(alert.status)}">${formatAlertStatus(alert.status)}</span></td>
      <td>${alert.risk_score || 0}</td>
      <td>${alert.event_count || 0}</td>
    </tr>
  `).join('');
  document.querySelectorAll('.alert-row').forEach((row) => row.addEventListener('click', async () => {
    await showAlertDetail(row.dataset.alertId);
  }));
  const total = response.total || 0;
  const pages = Math.max(1, Math.ceil(total / (response.page_size || state.alertPageSize)));
  $('alerts-page-info').textContent = `第 ${response.page || 1} 页 / 共 ${pages} 页`;
  const localFiltered = Boolean(alertCategoryInput.value || alertProbeInput.value);
  alertsTotalInfo.textContent = localFiltered ? `当前页筛选后 ${alerts.length} 条 / 服务端共 ${total} 条` : `共 ${total} 条告警`;
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
  $('tickets-list').innerHTML = tickets.map((ticket) => `<li data-ticket-id="${ticket.id}" class="ticket-row">${ticket.title} · ${formatAlertStatus(ticket.status)} · ${formatTicketPriority(ticket.priority)} · SLA=${formatSLAStatus(ticket.sla_status)} </li>`).join('') || '<li>暂无数据</li>';
  document.querySelectorAll('.ticket-row').forEach((row) => row.addEventListener('click', () => showTicketDetail(row.dataset.ticketId)));
  $('tickets-page-info').textContent = `第 ${response.page || 1} 页 / 共 ${Math.max(1, Math.ceil((response.total || 0) / (response.page_size || state.ticketPageSize)))} 页`;
}

async function loadProbes() {
  const probes = await request(`/api/v1/probes?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  $('probes-list').innerHTML = (probes || []).map((item) => `<li data-probe-id="${item.id}" class="probe-row">${item.name} · ${formatProbeStatus(item.status)} · 编码 ${item.probe_code} · 最近心跳=${formatDateTime(item.last_heartbeat_at)} · ${formatProbeRuntime(item)} · 已应用配置=${item.applied_config_id || '-'} · 已应用规则=${item.applied_rule_id || '-'} · 下发状态=${formatDeployStatus(item.last_deploy_status)}</li>`).join('') || '<li>暂无数据</li>';
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
  renderList('upgrade-packages-list', items, (item) => `${item.version} · ${item.enabled ? '启用' : '停用'} · ${item.package_url} · 校验=${item.checksum || '-'} · ${item.notes || '-'}`);
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
  const items = await request(`/api/v1/assets?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('assets-list', items, (item) => `${item.name} · ${item.ip} · 类型=${item.asset_type} · 重要度=${item.importance_level} · ${(item.tags || []).join(', ')}`);
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

async function loadUsers() {
  const users = await request(`/api/v1/users?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('users-list', users, (item) => `${item.username} · 角色：${(item.roles || []).join(', ')} · 租户范围：${(item.allowed_tenants || []).join(', ') || '-'} · 探针范围：${(item.allowed_probe_ids || []).join(', ') || '-'}`);
}

async function loadRoles() {
  const roles = await request(`/api/v1/roles?tenant_id=${encodeURIComponent(tenantInput.value)}`);
  renderList('roles-list', roles, (item) => `${item.name} · 权限：${(item.permissions || []).join(', ')}`);
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
  const detail = await request(`/api/v1/alerts/${alertID}/detail`);
  if (detail.error) return;
  state.selectedAlert = detail;
  $('detail-badge').textContent = detail.alert.id;
  $('ticket-form').classList.remove('hidden');
  if (shouldNavigate) {
    navigate('alert-detail');
  }
  $('alert-detail').className = 'detail-card detail-hero';
  $('alert-detail').innerHTML = `
    <div class="detail-title-row">
      <div>
        <div class="detail-subtitle">${detail.alert.category || '未分类'} · ${detail.alert.signature_id || '-'}</div>
        <strong>${detail.alert.signature}</strong>
      </div>
      <div class="detail-score-card">
        <span class="severity-badge ${formatSeverityClass(detail.alert.severity)}">${formatSeverity(detail.alert.severity)}</span>
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
      <span>处理人：${detail.alert.assignee || '-'}</span>
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
      <strong>协议上下文</strong>
      <div class="scroll-panel">${(detail.context_events || []).map((event) => renderRawEventCard(event)).join('') || '<code>暂无协议上下文</code>'}</div>
    </div>
    <div class="event-list detail-section">
      <strong>原始事件</strong>
      <div class="scroll-panel">${(detail.events || []).map((event) => renderRawEventCard(event)).join('') || '<code>暂无原始事件</code>'}</div>
    </div>
  `;
}

async function showTicketDetail(ticketID) {
  const detail = await request(`/api/v1/tickets/${ticketID}`);
  if (detail.error) return;
  state.selectedTicket = detail;
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

async function showProbeDetail(probeID) {
  const detail = await request(`/api/v1/probes/${probeID}`);
  if (detail.error) return;
  state.selectedProbe = detail;
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

async function updateSelectedTicket(status) {
  if (!state.selectedTicket) return;
  await request(`/api/v1/tickets/${state.selectedTicket.ticket.id}`, { method: 'PATCH', body: JSON.stringify({ status, assignee: state.user?.username || '' }) });
  await showTicketDetail(state.selectedTicket.ticket.id);
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
  await loadAlerts();
}

async function jumpAlertPage() {
  state.alertPage = Math.max(1, Number(alertsPageJumpInput.value || 1));
  await loadAlerts();
}

async function changeTicketPage(delta) {
  state.ticketPage = Math.max(1, state.ticketPage + delta);
  await loadTickets();
}

async function jumpTicketPage() {
  state.ticketPage = Math.max(1, Number(ticketsPageJumpInput.value || 1));
  await loadTickets();
}

async function resetAlertPageAndReload() {
  state.alertPage = 1;
  state.alertPageSize = Number(alertPageSizeInput.value || 10);
  persistAlertFilters();
  if (state.currentPage === 'alerts') {
    await loadAlerts();
  }
}

async function resetTicketPageAndReload() {
  state.ticketPage = 1;
  state.ticketPageSize = Number(ticketPageSizeInput.value || 10);
  persistTicketFilters();
  if (state.currentPage === 'tickets') {
    await loadTickets();
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
    category: alertCategoryInput.value,
    probe: alertProbeInput.value,
    since: alertSinceInput.value,
    sortBy: alertSortByInput.value,
    sortOrder: alertSortOrderInput.value,
    pageSize: alertPageSizeInput.value,
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
    alertCategoryInput.value = value.category || '';
    alertProbeInput.value = value.probe || '';
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
  const data = Object.fromEntries(new FormData(event.target).entries());
  data.tenant_id = tenantInput.value;
  data.enabled = String(data.enabled).toLowerCase() === 'true';
  await request('/api/v1/upgrade-packages', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadUpgradePackages();
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
  data.roles = splitCSV(data.roles);
  data.allowed_tenants = splitCSV(data.allowed_tenants);
  data.allowed_probe_ids = splitCSV(data.allowed_probe_ids);
  await request('/api/v1/users', { method: 'POST', body: JSON.stringify(data) });
  event.target.reset();
  await loadUsers();
}

function splitCSV(value) {
  return String(value || '').split(',').map((item) => item.trim()).filter(Boolean);
}

function renderRawEventCard(event) {
  const payload = event?.payload?.payload || event?.payload || {};
  const httpContext = extractHTTPContext(payload);
  return `
    <div class="raw-event-card">
      <div class="raw-event-head">
        <span class="tag">${payload.event_type || event?.payload?.event_type || 'raw'}</span>
        <span class="cell-sub">${formatDateTime(payload.timestamp || event?.event_time)}</span>
      </div>
      ${httpContext ? renderHTTPContext(httpContext) : ''}
      <code class="raw-json">${renderRawEventPayload(event)}</code>
    </div>
  `;
}

function renderRawEventPayload(event) {
  const payload = event?.payload?.payload || event?.payload || {};
  return escapeHTML(JSON.stringify(payload, null, 2));
}

function renderHTTPContext(context) {
  return `
    <div class="raw-grid">
      ${context.method ? `<div class="raw-field"><span>请求方法</span><strong>${escapeHTML(context.method)}</strong></div>` : ''}
      ${context.url ? `<div class="raw-field"><span>请求地址</span><strong>${escapeHTML(context.url)}</strong></div>` : ''}
      ${context.host ? `<div class="raw-field"><span>主机名</span><strong>${escapeHTML(context.host)}</strong></div>` : ''}
      ${context.userAgent ? `<div class="raw-field"><span>User-Agent</span><strong>${escapeHTML(context.userAgent)}</strong></div>` : ''}
      ${context.contentType ? `<div class="raw-field"><span>内容类型</span><strong>${escapeHTML(context.contentType)}</strong></div>` : ''}
      ${context.status ? `<div class="raw-field"><span>响应状态</span><strong>${escapeHTML(context.status)}</strong></div>` : ''}
    </div>
    ${context.body ? `<div class="raw-body"><span>HTTP Body</span><pre>${escapeHTML(context.body)}</pre></div>` : ''}
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
  const body = decodeBodyField(
    firstNonEmpty(
      payload.http_body,
      payload['http-body'],
      payload.http_request_body,
      payload.request_body,
      http.http_body,
      http.body,
    ),
  );
  if (!method && !url && !host && !userAgent && !contentType && !status && !body) {
    return null;
  }
  return { method, url, host, userAgent, contentType, status, body };
}

function decodeBodyField(value) {
  if (!value) return '';
  if (typeof value !== 'string') {
    return JSON.stringify(value, null, 2);
  }
  const trimmed = value.trim();
  if (!trimmed) return '';
  try {
    const normalized = trimmed.replace(/\s+/g, '');
    const decoded = atob(normalized);
    if (decoded && /[\x09\x0A\x0D\x20-\x7E]/.test(decoded)) {
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
  $('user-summary').textContent = `${state.user.display_name} · ${state.user.tenant_id} · 角色：${(state.user.roles || []).join(', ')}`;
  $('login-view').classList.add('hidden');
  $('app-view').classList.remove('hidden');
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
