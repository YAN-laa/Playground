# MVP API 草案

## 探针管理

### `POST /api/v1/probes/register`

注册探针。

### `POST /api/v1/probes/heartbeat`

上报探针心跳。

### `GET /api/v1/probes`

查询探针列表。

返回中包含：

1. 当前应用配置 `applied_config_id`
2. 当前应用规则 `applied_rule_id`
3. 最近一次下发状态 `last_deploy_status`
4. 最近一次下发消息 `last_deploy_message`
5. 最近一次下发时间 `last_deploy_at`

## 事件接入

### `POST /api/v1/events/ingest`

批量上报 Suricata 风格事件。

## 告警中心

### `GET /api/v1/alerts`

查询告警列表。

查询参数：

1. `tenant_id`
2. `status`
3. `since`
4. `src_ip`
5. `dst_ip`
6. `signature`
7. `severity`
8. `assignee`
9. `sort_by`
10. `sort_order`
11. `page`
12. `page_size`

### `GET /api/v1/alerts/{id}`

查询告警详情。

### `GET /api/v1/alerts/{id}/detail`

查询告警详情和关联原始事件，需要 bearer token。

返回内容包括：

1. `alert`
2. `events`
3. `flows`
4. `tickets`
5. `activities`

### `PATCH /api/v1/alerts/{id}`

更新告警状态和处理人。

## 工单中心

### `POST /api/v1/tickets`

从告警创建工单。

### `GET /api/v1/tickets`

查询工单列表。

查询参数：

1. `tenant_id`
2. `status`
3. `since`
4. `sort_by`
5. `sort_order`
6. `page`
7. `page_size`

### `GET /api/v1/tickets/{id}`

查询工单详情，需要 bearer token。

### `PATCH /api/v1/tickets/{id}`

更新工单状态，需要 bearer token。

## Flow

### `GET /api/v1/flows`

查询 Flow 列表，需要 bearer token。

查询参数：

1. `tenant_id`
2. `src_ip`
3. `dst_ip`
4. `app_proto`
5. `since`

## Assets

### `GET /api/v1/assets`

查询资产列表，需要 bearer token。

### `POST /api/v1/assets`

创建资产，需要 bearer token。

## Threat Intel

### `GET /api/v1/threat-intel`

查询情报列表，需要 bearer token。

### `POST /api/v1/threat-intel`

创建情报，需要 bearer token。

## Policies

### `GET /api/v1/suppression-rules`

查询抑制规则，需要 bearer token。

### `POST /api/v1/suppression-rules`

创建抑制规则，需要 bearer token。

当前支持的匹配字段：

1. `src_ip`
2. `dst_ip`
3. `signature_id`
4. `signature`

### `GET /api/v1/risk-policies`

查询风险评分策略，需要 bearer token。

### `POST /api/v1/risk-policies`

创建风险评分策略，需要 bearer token。

### `GET /api/v1/ticket-automation-policies`

查询工单自动化规则，需要 bearer token。

### `POST /api/v1/ticket-automation-policies`

创建工单自动化规则，需要 bearer token。

字段包括：

1. `reminder_before_mins`
2. `escalation_after_mins`
3. `escalation_assignee`
4. `escalation_status`

## Dashboard

### `GET /api/v1/dashboard/stats`

返回总览统计数据，需要 bearer token。

### `GET /api/v1/reports/summary`

返回报表中心摘要数据，需要 bearer token。

查询参数：

1. `tenant_id`
2. `since`

## Probe Configs

### `GET /api/v1/probe-configs`

查询探针配置模板，需要 bearer token。

### `POST /api/v1/probe-configs`

创建探针配置模板，需要 bearer token。

## Rule Bundles

### `GET /api/v1/rule-bundles`

查询规则版本，需要 bearer token。

### `POST /api/v1/rule-bundles`

创建规则版本，需要 bearer token。

## Probe Bindings

### `GET /api/v1/probe-bindings`

查询探针绑定关系，需要 bearer token。

### `POST /api/v1/probe-bindings`

给探针绑定配置模板和规则版本，需要 bearer token。

请求体：

1. `tenant_id`
2. `probe_id`
3. `probe_config_id`
4. `rule_bundle_id`

### `GET /api/v1/probes/{id}/binding`

探针侧拉取当前探针绑定的配置模板和规则版本。

### `GET /api/v1/probes/{id}/metrics`

查询探针指标时间线，需要 bearer token。

查询参数：

1. `since`
2. `limit`

## Deployments

### `GET /api/v1/deployments`

查询探针配置/规则下发记录，需要 bearer token。

查询参数：

1. `tenant_id`
2. `probe_id`
3. `status`
4. `since`
5. `limit`

### `POST /api/v1/deployments/ack`

探针侧回执配置/规则已应用。

## 认证与平台管理

### `POST /api/v1/auth/login`

登录并返回 bearer token。

### `GET /api/v1/auth/me`

返回当前登录用户和有效权限，需要 bearer token。

### `POST /api/v1/users`

创建用户，需要 bearer token。

### `GET /api/v1/users`

查询用户列表，需要 bearer token。

### `POST /api/v1/roles`

创建角色，需要 bearer token。

### `GET /api/v1/roles`

查询角色列表，需要 bearer token。

### `GET /api/v1/audit/logs`

查询审计日志，需要 bearer token。

### `GET /api/v1/query-stats`

查询最近查询耗时统计，需要 bearer token。

## Exports

### `POST /api/v1/exports`

创建异步导出任务，需要 bearer token。

请求体：

1. `tenant_id`
2. `resource_type`: `alerts` 或 `flows`
3. `format`: 当前支持 `json`、`csv`
4. `alert_query`
5. `flow_query`

### `GET /api/v1/exports`

查询导出任务列表，需要 bearer token。

### `GET /api/v1/exports/{id}`

查询单个导出任务状态，需要 bearer token。

### `GET /api/v1/exports/{id}/download`

下载导出结果文件，需要 bearer token。

## 权限模型

当前内置权限编码：

1. `probe.read`
2. `probe.write`
3. `alert.read`
4. `alert.write`
5. `ticket.read`
6. `ticket.write`
7. `user.read`
8. `user.write`
9. `role.read`
10. `role.write`
11. `audit.read`
12. `asset.read`
13. `asset.write`
14. `intel.read`
15. `intel.write`
16. `notify.read`
17. `notify.write`
18. `policy.read`
19. `policy.write`

角色中包含 `*` 时表示全权限。
