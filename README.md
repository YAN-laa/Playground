# NDR Platform

这是一个面向 `NDR / 流量威胁检测平台` 的首版骨架仓库，当前包含：

1. 产品与架构文档
2. 服务端最小 API
3. 探针端最小上报客户端
4. 基于内存存储的主链路演示
5. 用户、角色、登录、审计的最小实现
6. PostgreSQL 存储实现和前端管理台

## 目录

```text
docs/                  产品与设计文档
cmd/server/            服务端启动入口
cmd/probe-agent/       探针端演示入口
internal/shared/       共享模型
internal/server/       服务端实现
```

部署手册见：

1. [deployment-guide.md](/Users/yan/Documents/Playground/docs/deploy/deployment-guide.md)
2. 服务端环境模板：[server.env.example](/Users/yan/Documents/Playground/deploy/env/server.env.example)
3. 探针环境模板：[probe-agent.env.example](/Users/yan/Documents/Playground/deploy/env/probe-agent.env.example)

## 当前已实现链路

1. 探针注册
2. 探针心跳
3. 告警事件上报
4. 告警按指纹聚合
5. 告警列表与详情查询
6. 告警状态更新
7. 告警转工单
8. 用户、角色、登录、审计
9. RBAC 权限控制
10. 前端管理台
11. Memory / PostgreSQL 可切换存储
12. 告警详情、状态处置、前端建工单

## 启动服务端

```bash
go run ./cmd/server
```

默认监听 `:8080`，默认使用 `memory` 存储。

打开浏览器访问：

```text
http://localhost:8080/
```

前端当前支持：

1. 登录后先进入总览页
2. 总览页按当前用户权限展示模块入口
3. 左侧导航按用户权限显示模块
4. 告警中心、Flow 检索、工单中心、探针管理、报表中心、用户管理、角色管理、审计日志分别独立页面展示
5. 告警高级筛选：`src_ip / dst_ip / signature / assignee / severity`
6. 告警详情展示关联 Flow、工单、处置活动历史
7. 告警确认 / 关闭
8. 基于当前告警创建工单
9. 工单详情与状态流转

如果你跑了 `go run ./cmd/probe-agent` 但前端没数据，先看租户过滤：

1. `probe-agent` 默认上报到 `demo-tenant`
2. 现在前端登录后会自动把查询租户切到当前用户租户
3. 如果你手动改过顶部租户输入框，需要切回正确租户再刷新

当前新增接口：

1. `GET /api/v1/flows`
2. `GET /api/v1/tickets/{id}`
3. `PATCH /api/v1/tickets/{id}`
4. `GET /api/v1/alerts/{id}/detail`
5. `GET /api/v1/auth/me`
6. `GET /api/v1/dashboard/stats`
7. `GET/POST /api/v1/probe-configs`
8. `GET/POST /api/v1/rule-bundles`
9. `GET/POST /api/v1/probe-bindings`
10. `GET /api/v1/deployments`
11. `GET /api/v1/probes/{id}/binding`
12. `POST /api/v1/deployments/ack`
13. `GET /api/v1/probes/{id}/metrics`

本轮还新增了：

1. 独立活动模型 `Activity`，不再只依赖审计日志拼处置历史
2. 探针配置模板管理
3. 规则版本管理
4. 探针绑定和模拟下发记录
5. Dashboard 统计接口
6. 报表中心趋势统计接口
7. 探针主动拉取绑定并回执下发状态
8. 告警和工单列表的服务端分页、排序、时间筛选
9. 探针列表显示最后应用配置、规则和下发状态
10. 前端保存告警/工单/报表筛选条件
11. 下发状态区分 `pending / applied / failed`
12. 报表中心简易图表展示
13. 探针详情页
14. `probe-agent` 长驻模式持续心跳、轮询绑定、周期上报事件
15. 探针指标时间线与探针详情图表
16. 批量绑定结果汇总
17. 下发记录筛选
18. PostgreSQL 旧库兼容迁移和基础索引
19. Dockerfile
20. GitHub Actions 基础 CI
21. `.env.example`
22. 查询层抽象，告警/Flow 查询已从业务存储调用中拆出
23. 告警查询和 Flow 查询写入审计日志
24. `APP_SEARCH` 配置切换，支持本地查询引擎和 OpenSearch 检索骨架
25. 告警和 Flow 写入路径已接入检索索引器骨架
26. OpenSearch 启动时自动检查并创建基础索引
27. `ingest` 路径支持 OpenSearch 批量写入
28. OpenSearch bulk 重试和失败 DLQ 落地
29. 查询耗时统计和慢查询审计
30. 异步导出任务、状态轮询和结果下载
31. 前端导出中心和 CSV 导出
32. 探针端本地缓冲和失败补传
33. 查询统计页、慢查询视图和导出中心自动刷新
34. 探针缓冲目录容量控制与导出文件过期清理
35. 通知模板和失败补发任务
36. 资产中心、情报中心与告警富化
37. 策略中心，支持抑制规则和风险评分策略

38. 工单自动化规则，支持催办和超时升级

## 使用 PostgreSQL 启动

先启动数据库：

```bash
docker compose up -d
```

再启动服务端：

```bash
make run-server-pg
```

如果要以 OpenSearch 查询骨架启动：

```bash
make run-server-os
```

说明：

1. 设置 `APP_STORE=postgres`
2. 通过 `DATABASE_URL` 连接 PostgreSQL
3. 表结构会在启动时自动初始化
4. `APP_SEARCH=local|opensearch`
5. `APP_SEARCH=opensearch` 时需要配置 `OPENSEARCH_URL`
6. 可选配置：
   `OPENSEARCH_RETRY_MAX`、`OPENSEARCH_RETRY_BACKOFF`、`OPENSEARCH_DLQ_FILE`
7. 慢查询阈值：
   `APP_SLOW_QUERY_THRESHOLD`
8. 导出目录：
   `APP_EXPORT_DIR`
9. 认证模式支持 `APP_AUTH_MODE=simple|jwt`，JWT 模式需要配置 `APP_JWT_SECRET`

如果要跑 PostgreSQL 初始化测试：

```bash
DATABASE_URL=postgres://ndr:ndr@localhost:5432/ndr?sslmode=disable go test ./...
```

## 运行演示探针

```bash
go run ./cmd/probe-agent
```

如果要模拟持续轮询绑定：

```bash
go run ./cmd/probe-agent --poll-count 5 --poll-interval 10s
```

如果要以长驻模式运行：

```bash
go run ./cmd/probe-agent --daemon --poll-interval 10s --heartbeat-interval 15s --event-interval 30s
```

如果要持续读取真实 `eve.json`：

```bash
NDR_EVE_FILE=/path/to/eve.json go run ./cmd/probe-agent --daemon --poll-interval 10s --heartbeat-interval 15s --event-interval 5s
```

如果要指定本地缓冲目录：

```bash
NDR_BUFFER_DIR=./probe-buffer go run ./cmd/probe-agent --daemon
```

如果要控制缓冲上限：

```bash
NDR_BUFFER_MAX_FILES=200 NDR_BUFFER_MAX_BYTES=67108864 go run ./cmd/probe-agent --daemon
```

执行后会自动：

1. 注册一个探针
2. 上报一次心跳
3. 拉取当前探针绑定的配置和规则
4. 如果发现新绑定则回执 `applied`
5. 在 daemon 模式下持续上报演示事件，或者增量读取 `eve.json`
6. 当服务端不可达时，事件批次会先落盘到本地缓冲目录，恢复后优先补传
7. 当缓冲目录超过文件数或字节数上限时，会按最老批次优先淘汰

如果要模拟应用失败：

```bash
NDR_FORCE_APPLY_FAIL=1 go run ./cmd/probe-agent
```

## 试用 API

默认内置管理员账号：

1. `tenant_id`: `demo-tenant`
2. `username`: `admin`
3. `password`: `admin123`

先登录获取 bearer token：

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"demo-tenant","username":"admin","password":"admin123"}'
```

登录后再访问受保护接口。

```bash
curl http://localhost:8080/api/v1/alerts \
  -H 'Authorization: Bearer <token>'
```

```bash
curl http://localhost:8080/api/v1/probes \
  -H 'Authorization: Bearer <token>'
```

权限说明：

1. `admin` 角色拥有 `*`
2. 示例 `analyst` 角色只应拥有业务相关权限，例如 `alert.read`、`ticket.write`
3. 没有权限的接口会返回 `403 permission denied`

策略中心说明：

1. `抑制规则` 会在告警聚合前生效，命中后事件不会进入告警列表
2. 当前支持按 `src_ip / dst_ip / signature_id / signature` 精确匹配
3. `风险评分策略` 会覆盖默认评分基线
4. 当前评分支持：
   `severity1_score / severity2_score / severity3_score / default_score / intel_hit_bonus / critical_asset_bonus`

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tenant-a","name":"analyst","description":"Security analyst","permissions":["alert.read","ticket.write"]}'
```

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H 'Authorization: Bearer <token>' \
  -H 'Content-Type: application/json' \
  -d '{"tenant_id":"tenant-a","username":"alice","display_name":"Alice","password":"alice123","roles":["analyst"]}'
```

```bash
curl http://localhost:8080/api/v1/audit/logs?tenant_id=tenant-a \
  -H 'Authorization: Bearer <token>'
```

## 下一步建议

1. 引入检索型存储承载告警和 Flow 查询
2. 把探针绑定真正下发到 `probe-agent`，补版本回执和失败重试
3. 在 `pipeline-service` 中拆出标准化、富化、聚合、抑制模块
4. 认证模式支持 `APP_AUTH_MODE=simple|jwt`，JWT 模式需要配置 `APP_JWT_SECRET`


## Data Scope And SLA

- 用户支持 `allowed_tenants` 和 `allowed_probe_ids` 两类数据范围。
- 普通用户查询接口会按租户范围做过滤，探针/Flow/告警会继续受探针范围限制。
- 工单创建时会自动生成 `sla_deadline`。
- 后台定时扫描超时工单，命中后会把 `sla_status` 置为 `breached` 并触发 `ticket.sla_breach` 通知。
- 通知发送支持统一重试：
  - `APP_NOTIFY_RETRY_MAX`
  - `APP_NOTIFY_RETRY_BACKOFF`
- SLA 配置支持：
  - `APP_TICKET_SLA_SCAN_INTERVAL`
  - `APP_SLA_CRITICAL`
  - `APP_SLA_HIGH`
  - `APP_SLA_MEDIUM`
  - `APP_SLA_LOW`


- 通知模板支持按 `event_type` 渲染摘要。
- 通知失败会写发送记录，并由后台补发循环继续重试。
- 补发相关配置：
  - `APP_NOTIFY_RETRY_SCAN_INTERVAL`

工单自动化规则说明：

1. 可配置 `reminder_before_mins`，在 SLA 到期前触发一次催办通知
2. 可配置 `escalation_after_mins`，在 SLA 到期后按规则升级
3. 升级时可修改处理人 `escalation_assignee`
4. 升级时可修改工单状态 `escalation_status`，例如 `escalated`
