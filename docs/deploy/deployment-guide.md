# NDR 部署使用手册

这份手册按 Linux 单机部署写，默认系统是 `Ubuntu 22.04 / Debian 12` 一类环境。

目标分两部分：

1. 服务端部署
2. 探针端部署

本文默认目录：

1. 服务端安装目录：`/opt/ndr`
2. 探针安装目录：`/opt/ndr-probe`
3. 服务端配置目录：`/etc/ndr/server.env`
4. 探针配置目录：`/etc/ndr/probe-agent.env`

## 一、部署前准备

### 1. 基础要求

服务端建议：

1. CPU: 4 Core 以上
2. 内存: 8 GB 以上
3. 磁盘: 100 GB 以上
4. 系统: Linux x86_64
5. 数据库: PostgreSQL 16

探针端建议：

1. CPU: 4 Core 以上
2. 内存: 8 GB 以上
3. 磁盘: 50 GB 以上
4. 已安装并运行 `Suricata`
5. `eve.json` 已开启输出

### 2. 拉代码并编译

```bash
cd /opt
git clone <你的仓库地址> ndr-platform
cd /opt/ndr-platform
chmod +x deploy/scripts/*.sh
./deploy/scripts/build-release.sh
```

编译后会生成：

1. `/opt/ndr-platform/bin/ndr-server`
2. `/opt/ndr-platform/bin/probe-agent`

---

## 二、服务端部署

### 1. 安装 PostgreSQL

如果本机还没有 PostgreSQL，可以直接用仓库自带 `docker-compose.yml`：

```bash
cd /opt/ndr-platform
docker compose up -d postgres
```

默认数据库信息：

1. `DB`: `ndr`
2. `USER`: `ndr`
3. `PASSWORD`: `ndr`
4. `PORT`: `5432`

### 2. 安装服务端文件

```bash
cd /opt/ndr-platform
sudo ./deploy/scripts/install-server.sh
```

这一步会完成：

1. 创建系统用户 `ndr`
2. 复制二进制到 `/opt/ndr/bin/ndr-server`
3. 生成 `/etc/ndr/server.env`
4. 安装 `systemd` 单元

### 3. 修改服务端配置

编辑：

```bash
sudo vi /etc/ndr/server.env
```

建议至少修改以下内容：

```bash
APP_STORE=postgres
APP_SEARCH=local
NDR_SERVER_ADDR=:8080

DATABASE_URL=postgres://ndr:ndr@127.0.0.1:5432/ndr?sslmode=disable

APP_AUTH_MODE=jwt
APP_JWT_SECRET=请替换为足够长的随机字符串
APP_JWT_TTL=12h

APP_EXPORT_DIR=/var/lib/ndr/exports
APP_EXPORT_TTL=24h
APP_EXPORT_CLEANUP_INTERVAL=1h

APP_SLOW_QUERY_THRESHOLD=1500ms

APP_NOTIFY_RETRY_MAX=2
APP_NOTIFY_RETRY_BACKOFF=500ms
APP_NOTIFY_RETRY_SCAN_INTERVAL=30s

APP_TICKET_SLA_SCAN_INTERVAL=1m
APP_SLA_CRITICAL=30m
APP_SLA_HIGH=4h
APP_SLA_MEDIUM=8h
APP_SLA_LOW=24h
```

如果你要启用 OpenSearch，把下面几项打开并改值：

```bash
APP_SEARCH=opensearch
OPENSEARCH_URL=http://127.0.0.1:9200
OPENSEARCH_USERNAME=
OPENSEARCH_PASSWORD=
OPENSEARCH_ALERT_INDEX=ndr-alerts
OPENSEARCH_FLOW_INDEX=ndr-flows
OPENSEARCH_RETRY_MAX=2
OPENSEARCH_RETRY_BACKOFF=500ms
OPENSEARCH_DLQ_FILE=/var/lib/ndr/opensearch.dlq
```

### 4. 启动服务端

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ndr-server
sudo systemctl status ndr-server
```

查看日志：

```bash
sudo journalctl -u ndr-server -f
```

### 5. 验证服务端

健康检查：

```bash
curl http://127.0.0.1:8080/healthz
```

预期返回：

```json
{"status":"ok"}
```

Web 控制台：

1. 打开 [http://127.0.0.1:8080/](http://127.0.0.1:8080/)
2. 默认管理员：
   - `tenant_id`: `demo-tenant`
   - `username`: `admin`
   - `password`: `admin123`

---

## 三、探针端部署

### 1. 安装 Suricata

如果还没装：

```bash
sudo apt-get update
sudo apt-get install -y suricata
```

### 2. 确认 `eve.json` 输出

编辑 Suricata 配置：

```bash
sudo vi /etc/suricata/suricata.yaml
```

确认 `eve-log` 已启用，至少包含：

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert
        - flow
        - http
        - dns
        - tls
```

重启 Suricata：

```bash
sudo systemctl restart suricata
sudo systemctl status suricata
```

### 3. 安装探针端文件

```bash
cd /opt/ndr-platform
sudo ./deploy/scripts/install-probe.sh
```

这一步会完成：

1. 创建系统用户 `ndr`
2. 复制二进制到 `/opt/ndr-probe/bin/probe-agent`
3. 生成 `/etc/ndr/probe-agent.env`
4. 安装 `systemd` 单元

### 4. 修改探针配置

编辑：

```bash
sudo vi /etc/ndr/probe-agent.env
```

最小可用配置：

```bash
NDR_SERVER_URL=http://服务端IP:8080
NDR_TENANT_ID=demo-tenant
NDR_PROBE_CODE=probe-hz-01
NDR_PROBE_NAME=Hangzhou Probe 01

NDR_EVE_FILE=/var/log/suricata/eve.json

NDR_BUFFER_DIR=/var/lib/ndr-probe/buffer
NDR_BUFFER_MAX_FILES=200
NDR_BUFFER_MAX_BYTES=67108864

NDR_POLL_INTERVAL=10s
NDR_HEARTBEAT_INTERVAL=15s
NDR_EVENT_INTERVAL=5s
```

需要你特别确认的项目：

1. `NDR_SERVER_URL` 必须能从探针机访问到服务端
2. `NDR_TENANT_ID` 要和服务端租户一致
3. `NDR_PROBE_CODE` 每台探针必须唯一
4. `NDR_EVE_FILE` 必须和 Suricata 实际输出文件一致
5. `NDR_BUFFER_DIR` 要有写权限
6. 一旦配置 `NDR_EVE_FILE`，探针只会上报该文件中的事件；没有新增事件时不会回退发送内置 demo 告警

### 5. 启动探针

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ndr-probe-agent
sudo systemctl status ndr-probe-agent
```

查看日志：

```bash
sudo journalctl -u ndr-probe-agent -f
```

### 6. 验证探针

看日志里是否出现：

1. `binding sync result`
2. `events ingested`
3. `heartbeat failed` 不应持续出现

服务端 UI 验证：

1. 登录控制台
2. 进入“探针管理”
3. 查看探针是否在线
4. 进入“告警中心”
5. 查看是否有新告警

---

## 四、常见部署命令

### 1. 重启服务端

```bash
sudo systemctl restart ndr-server
```

### 2. 重启探针

```bash
sudo systemctl restart ndr-probe-agent
```

### 3. 查看服务端日志

```bash
sudo journalctl -u ndr-server -n 200 --no-pager
```

### 4. 查看探针日志

```bash
sudo journalctl -u ndr-probe-agent -n 200 --no-pager
```

### 5. 手工前台调试探针

先停掉服务：

```bash
sudo systemctl stop ndr-probe-agent
```

再手工执行：

```bash
cd /opt/ndr-probe
sudo -u ndr env $(grep -v '^#' /etc/ndr/probe-agent.env | xargs) \
  /opt/ndr-probe/bin/probe-agent \
  --server ${NDR_SERVER_URL} \
  --tenant ${NDR_TENANT_ID} \
  --probe-code ${NDR_PROBE_CODE} \
  --name ${NDR_PROBE_NAME} \
  --daemon \
  --poll-interval ${NDR_POLL_INTERVAL} \
  --heartbeat-interval ${NDR_HEARTBEAT_INTERVAL} \
  --event-interval ${NDR_EVENT_INTERVAL} \
  --buffer-dir ${NDR_BUFFER_DIR}
```

---

## 五、部署后建议

1. 第一时间修改默认管理员密码
2. 生产环境不要继续使用 `APP_AUTH_MODE=simple`
3. 服务端建议固定 PostgreSQL，不要继续用 `memory`
4. 生产探针建议固定接真实 `eve.json`
5. 如果数据量上来，尽快启用 OpenSearch
