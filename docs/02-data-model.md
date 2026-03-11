# NDR 平台核心数据模型设计初稿

## 1. 设计目标

数据模型需要同时满足以下要求：

1. 支持原始事件可回放、可追溯
2. 支持标准化事件统一处理
3. 支持聚合告警视图
4. 支持告警与工单、Flow、资产关联
5. 支持多租户和数据权限
6. 为检索型存储和事务型存储分层提供基础

---

## 2. 模型分层

建议按四层建模：

1. 接入层对象
2. 事件层对象
3. 业务层对象
4. 平台管理对象

---

## 3. 接入层对象

### 3.1 `probe`

用途：

1. 记录探针基础信息
2. 维护探针在线状态
3. 支撑探针管理和分组

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `probe_code` | string | 探针唯一编码 |
| `name` | string | 探针名称 |
| `group_id` | string | 探针分组 |
| `region` | string | 区域 |
| `ip` | string | 探针管理 IP |
| `status` | string | online/offline/degraded |
| `version` | string | Agent 版本 |
| `rule_version` | string | Suricata 规则版本 |
| `last_heartbeat_at` | datetime | 最近心跳时间 |
| `created_at` | datetime | 创建时间 |
| `updated_at` | datetime | 更新时间 |

索引建议：

1. `tenant_id + probe_code`
2. `tenant_id + status`
3. `last_heartbeat_at`

### 3.2 `probe_heartbeat`

用途：

1. 保存探针周期性状态快照
2. 支撑在线监控和历史分析

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `probe_id` | string | 探针 ID |
| `status` | string | 当前状态 |
| `cpu_usage` | float | CPU 使用率 |
| `memory_usage` | float | 内存使用率 |
| `drop_rate` | float | 丢包率 |
| `event_rate` | int | 每秒事件数 |
| `heartbeat_at` | datetime | 心跳时间 |

---

## 4. 事件层对象

### 4.1 `raw_event`

用途：

1. 保存原始上报事件
2. 用于排障、重放、审计

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `probe_id` | string | 探针 ID |
| `trace_id` | string | 链路追踪 ID |
| `event_type` | string | alert/flow/http/dns/tls |
| `event_time` | datetime | 原始事件时间 |
| `ingest_time` | datetime | 接入时间 |
| `raw_payload` | json/text | 原始报文 |
| `parse_status` | string | pending/success/failed |
| `parse_error` | string | 失败原因 |

索引建议：

1. `tenant_id + probe_id + event_time`
2. `trace_id`
3. `parse_status + ingest_time`

### 4.2 `normalized_event`

用途：

1. 标准化后的统一事件模型
2. 作为规则处理和聚合输入

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `probe_id` | string | 探针 ID |
| `raw_event_id` | string | 原始事件 ID |
| `event_type` | string | 事件类型 |
| `event_time` | datetime | 标准事件时间 |
| `src_ip` | string | 源 IP |
| `src_port` | int | 源端口 |
| `dst_ip` | string | 目的 IP |
| `dst_port` | int | 目的端口 |
| `proto` | string | 传输协议 |
| `app_proto` | string | 应用协议 |
| `signature_id` | int | 规则 ID |
| `signature` | string | 规则名称 |
| `category` | string | 告警分类 |
| `severity` | int | 严重级别 |
| `flow_id` | string | flow 标识 |
| `fingerprint` | string | 聚合指纹 |
| `labels` | json | 补充标签 |

索引建议：

1. `tenant_id + event_time`
2. `tenant_id + fingerprint + event_time`
3. `tenant_id + src_ip + event_time`
4. `tenant_id + dst_ip + event_time`
5. `tenant_id + signature_id + event_time`

### 4.3 `network_flow`

用途：

1. 保存会话或流量元数据
2. 用于告警关联和回溯

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `probe_id` | string | 探针 ID |
| `flow_id` | string | flow 标识 |
| `start_time` | datetime | 开始时间 |
| `end_time` | datetime | 结束时间 |
| `src_ip` | string | 源 IP |
| `src_port` | int | 源端口 |
| `dst_ip` | string | 目的 IP |
| `dst_port` | int | 目的端口 |
| `proto` | string | 协议 |
| `app_proto` | string | 应用协议 |
| `src_bytes` | bigint | 源出字节 |
| `dst_bytes` | bigint | 目的出字节 |
| `src_pkts` | bigint | 源出包数 |
| `dst_pkts` | bigint | 目的出包数 |
| `flow_state` | string | 会话状态 |

索引建议：

1. `tenant_id + flow_id`
2. `tenant_id + start_time`
3. `tenant_id + src_ip + start_time`
4. `tenant_id + dst_ip + start_time`

---

## 5. 业务层对象

### 5.1 `alert`

用途：

1. 作为前端告警主视图
2. 聚合多个标准化事件形成操作对象

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `alert_no` | string | 告警编号 |
| `fingerprint` | string | 聚合指纹 |
| `first_seen_at` | datetime | 首次出现 |
| `last_seen_at` | datetime | 最近出现 |
| `event_count` | int | 聚合事件数 |
| `probe_ids` | json | 涉及探针 ID 列表 |
| `src_ip` | string | 主源 IP |
| `dst_ip` | string | 主目的 IP |
| `dst_port` | int | 主目的端口 |
| `proto` | string | 协议 |
| `signature_id` | int | 规则 ID |
| `signature` | string | 规则名称 |
| `category` | string | 分类 |
| `severity` | int | 原始严重级 |
| `risk_score` | int | 风险分 |
| `status` | string | new/ack/in_progress/closed/false_positive |
| `assignee` | string | 当前处理人 |
| `source_asset_id` | string | 源资产 ID |
| `target_asset_id` | string | 目标资产 ID |
| `intel_tags` | json | 情报标签 |
| `attack_stage` | string | 攻击阶段 |
| `last_ticket_id` | string | 最近工单 |
| `created_at` | datetime | 创建时间 |
| `updated_at` | datetime | 更新时间 |

索引建议：

1. `tenant_id + first_seen_at`
2. `tenant_id + status + last_seen_at`
3. `tenant_id + severity + last_seen_at`
4. `tenant_id + src_ip + last_seen_at`
5. `tenant_id + dst_ip + last_seen_at`
6. `tenant_id + signature_id + last_seen_at`
7. `tenant_id + fingerprint`

### 5.2 `alert_event_relation`

用途：

1. 记录告警与事件的关联
2. 支撑聚合结果回看

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `alert_id` | string | 告警 ID |
| `event_id` | string | 标准化事件 ID |
| `event_time` | datetime | 事件时间 |

### 5.3 `asset`

用途：

1. 资产富化
2. 风险画像和归属分析

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `ip` | string | 资产 IP |
| `hostname` | string | 主机名 |
| `asset_type` | string | server/workstation/network_device |
| `importance_level` | int | 重要级 |
| `owner` | string | 负责人 |
| `department` | string | 部门 |
| `business_system` | string | 业务系统 |
| `tags` | json | 标签 |

索引建议：

1. `tenant_id + ip`
2. `tenant_id + hostname`

### 5.4 `ticket`

用途：

1. 告警处置闭环
2. 运维追踪

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `ticket_no` | string | 工单编号 |
| `source_type` | string | alert/manual |
| `source_id` | string | 来源对象 ID |
| `title` | string | 工单标题 |
| `description` | text | 工单描述 |
| `priority` | string | low/medium/high/critical |
| `status` | string | open/assigned/in_progress/closed |
| `assignee` | string | 处理人 |
| `sla_deadline` | datetime | SLA 截止时间 |
| `created_by` | string | 创建人 |
| `created_at` | datetime | 创建时间 |
| `closed_at` | datetime | 关闭时间 |

索引建议：

1. `tenant_id + source_type + source_id`
2. `tenant_id + status + created_at`
3. `tenant_id + assignee + created_at`

### 5.5 `ticket_activity`

用途：

1. 工单处理记录留痕
2. 审计与复盘

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `ticket_id` | string | 工单 ID |
| `action` | string | create/assign/comment/close |
| `operator` | string | 操作人 |
| `content` | text | 操作说明 |
| `created_at` | datetime | 创建时间 |

---

## 6. 平台管理对象

### 6.1 `tenant`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `name` | string | 租户名称 |
| `status` | string | 状态 |
| `created_at` | datetime | 创建时间 |

### 6.2 `user`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `username` | string | 用户名 |
| `display_name` | string | 显示名 |
| `email` | string | 邮箱 |
| `password_hash` | string | 密码哈希 |
| `status` | string | active/disabled |
| `auth_type` | string | local/ldap/sso |
| `created_at` | datetime | 创建时间 |

### 6.3 `role`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `name` | string | 角色名称 |
| `description` | string | 描述 |

### 6.4 `permission`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `code` | string | 权限编码 |
| `name` | string | 权限名称 |
| `category` | string | alert/ticket/probe/admin |

### 6.5 `user_role`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `user_id` | string | 用户 ID |
| `role_id` | string | 角色 ID |

### 6.6 `role_permission`

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `role_id` | string | 角色 ID |
| `permission_id` | string | 权限 ID |

### 6.7 `data_scope`

用途：

1. 定义数据权限边界

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `subject_type` | string | user/role |
| `subject_id` | string | 用户或角色 ID |
| `scope_type` | string | probe_group/asset_group |
| `scope_value` | string | 权限范围值 |

### 6.8 `audit_log`

用途：

1. 记录平台审计行为

核心字段：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `id` | string | 主键 |
| `tenant_id` | string | 租户 ID |
| `user_id` | string | 用户 ID |
| `action` | string | 操作类型 |
| `resource_type` | string | 资源类型 |
| `resource_id` | string | 资源 ID |
| `request_ip` | string | 请求 IP |
| `result` | string | success/failed |
| `created_at` | datetime | 时间 |

---

## 7. 关键关系

1. `probe 1:N raw_event`
2. `raw_event 1:1 normalized_event`
3. `normalized_event N:1 alert`
4. `alert 1:N ticket` 或 `alert 1:1 current_ticket`
5. `alert N:1 asset`
6. `tenant 1:N user`
7. `user N:M role`
8. `role N:M permission`

---

## 8. 存储分层建议

### 事务库

适合：

1. `probe`
2. `ticket`
3. `user`
4. `role`
5. `audit_log`

### 检索库

适合：

1. `normalized_event`
2. `alert`
3. `network_flow`

### 原始存储

适合：

1. `raw_event.raw_payload`
2. 导出文件
3. 可选 pcap 片段

---

## 9. 首版实现建议

MVP 第一版不必把所有模型一次实现完，建议首批落地：

1. `probe`
2. `probe_heartbeat`
3. `raw_event`
4. `normalized_event`
5. `alert`
6. `ticket`
7. `user`
8. `role`
9. `audit_log`

第二批再补：

1. `network_flow`
2. `asset`
3. `data_scope`
4. `ticket_activity`
