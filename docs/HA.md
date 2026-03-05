# NanoDNS 高可用部署指南

## 问题分析

NanoDNS 是无状态服务——每次查询完全由本地 JSON 回答，不存在写入争用。
HA 只需解决两个相互独立的问题：

| 问题 | 本文方案 |
|------|---------|
| **服务可用性**：一台宕机时客户端不中断 | 多节点 + LB / VIP，探测 `/health` |
| **配置一致性**：多节点 JSON 保持同步 | 节点间 HTTP 推拉，无需外部依赖 |

---

## 代码改动概述

本次新增 `nanodns/mgmt.py` 并修改 `config.py` / `server.py`，
**零外部依赖**，仅用 Python 标准库。

### 新 HTTP 管理端口（默认 9053）

| 端点 | 方法 | 用途 |
|------|------|------|
| `/health` | GET | **存活探测**：服务未启动 → 503 |
| `/ready` | GET | **就绪探测**：配置未加载 → 503 |
| `/metrics` | GET | 缓存命中率、记录数、版本号、运行时长 |
| `/cluster` | GET | 本节点状态 + 逐个探测所有 peer |
| `/config/raw` | GET | 返回当前原始 JSON（供 peer catch-up 拉取）|
| `/reload` | POST | 从磁盘重载配置，bump 版本，推送给所有 peer |
| `/sync` | POST | 接收 peer 推送的 JSON，版本比对后 apply |

启用方式（`nanodns.json`）：

```json
{
  "server": {
    "mgmt_port": 9053,
    "mgmt_host": "0.0.0.0",
    "peers": ["10.0.0.12:9053", "10.0.0.13:9053"],
    "hot_reload": true
  }
}
```

### 配置版本号

每个 `nanodns.json` 的 `server.config_version` 字段是一个单调递增整数：

- 初始值 `1`（`nanodns init` 生成）
- 每次调用 `/reload` 或文件热重载时自动 +1
- peer 通过比较版本号决定接受还是拒绝推送：
  - 收到的版本 > 本节点版本 → 接受并 apply
  - 收到的版本 < 本节点版本 → 拒绝（防止回滚）
  - 版本相同但 checksum 相同 → 幂等，忽略（防重复 apply）

---

## 配置同步机制（零依赖）

### 推送路径（在线节点，毫秒级）

```
操作员修改 nanodns.json（在任意一台）
         │
         ▼
  POST /reload  或  hot_reload 文件监视器（5s 轮询）
         │
  从磁盘读 → config_version + 1 → apply_config()
         │
  遍历 server.peers → POST /sync (raw bytes)
         │
  peer 收到后:
    checksum 相同?  → 200 already_current（跳过）
    版本更低?       → 409 rejected_stale（防回滚）
    版本更高?       → 写盘 → apply_config() → 200 applied
```

### 拉取路径（节点重启 / 网络分区恢复，30s 内）

```
节点启动或每 30s 定时触发 _reconcile_peers()
         │
  GET /health 询问所有 peer 的当前 version
         │
  有 peer 的 version > 我的 version?
    否 → 跳过
    是 → GET /config/raw 从最高版本 peer 拉取原始字节
         → 写盘 → apply_config()
         → 再推给其他 peer（级联追赶）
```

### 时序保证

| 场景 | 行为 |
|------|------|
| A 推送，B 在线 | B 在 `_PEER_TIMEOUT`(5s) 内应用 |
| A 推送，B 宕机 | B 重启后 10s 内通过 pull 自动追赶 |
| A B 同时 reload | 版本号更大的一方的配置最终胜出 |
| 重复推送相同内容 | checksum 检测，幂等跳过 |
| 网络分区后恢复 | 30s reconcile 循环自动追赶 |

---

## 部署方案

### 方案一：Active-Active + resolv.conf（最简单）

适合：2–3 台 VM，客户端配多个 nameserver。

```
/etc/resolv.conf（每台客户端）：
  nameserver 10.0.0.11   # ns1
  nameserver 10.0.0.12   # ns2
  nameserver 10.0.0.13   # ns3
  options timeout:1 attempts:2
```

操作系统 DNS 解析器在第一个超时（1s）后自动重试下一个。
两台 NanoDNS 同时提供服务，任意一台宕机客户端最多感知 1s 延迟。

**nanodns.json（ns1）**：
```json
{
  "server": {
    "host": "0.0.0.0", "port": 53,
    "mgmt_port": 9053, "hot_reload": true,
    "peers": ["10.0.0.12:9053", "10.0.0.13:9053"]
  }
}
```

**更新配置**（在任意节点执行，自动扩散）：
```bash
# 编辑 nanodns.json，然后：
curl -s -X POST http://10.0.0.11:9053/reload | jq .

# 验证所有节点版本一致：
for h in 10.0.0.11 10.0.0.12 10.0.0.13; do
  echo -n "$h: "; curl -s http://$h:9053/health | jq .version
done
```

---

### 方案二：Active-Passive + Keepalived VIP

适合：需要单一入口 IP，2 台机器。

```
客户端 nameserver 10.0.0.53 (VIP)
         │
  ┌──────┴──────┐  VRRP 心跳 (2s)
  │   ns1       │  ← MASTER（持有 VIP）
  │  :53 :9053  │
  └─────────────┘
         │ (ns1 宕机后 VIP 在 ~2s 内漂移到 ns2)
  ┌──────┴──────┐
  │   ns2       │  ← BACKUP
  │  :53 :9053  │
  └─────────────┘
```

**`/etc/keepalived/keepalived.conf`（ns1）**：
```
vrrp_script chk_nanodns {
    script "/usr/bin/curl -sf http://127.0.0.1:9053/health"
    interval 2
    weight   -20
    fall     2
    rise     3
}

vrrp_instance DNS_HA {
    state     MASTER
    interface eth0
    virtual_router_id 53
    priority  100
    authentication { auth_type PASS; auth_pass nanodns_ha }
    virtual_ipaddress { 10.0.0.53/24 }
    track_script { chk_nanodns }
}
```

ns2 同上，`state BACKUP`，`priority 80`。

---

### 方案三：Active-Active + HAProxy（推荐生产）

适合：流量较高，希望同时用 3 台，单一 :53 入口。

```
客户端 nameserver 10.0.0.53 (HAProxy)
              │
        ┌─────▼──────┐
        │  HAProxy   │  UDP :53  健康检查 HTTP :9053
        └─┬────┬────┬┘
          │    │    │
        ns1  ns2  ns3
```

**`haproxy.cfg`**（见项目根目录 `haproxy.cfg`）：
```
backend dns_nodes
    balance    leastconn
    option     httpchk GET /health
    http-check expect status 200
    server ns1 10.0.0.11:53 check port 9053 inter 2s fall 2 rise 3 proto udp
    server ns2 10.0.0.12:53 check port 9053 inter 2s fall 2 rise 3 proto udp
    server ns3 10.0.0.13:53 check port 9053 inter 2s fall 2 rise 3 proto udp
```

---

### 方案四：Docker Compose（3 节点，见 `docker-compose.yml`）

```bash
# 启动 3 节点集群
docker compose up -d

# 验证集群状态
curl -s http://localhost:9053/cluster | jq .

# 更新配置：编辑 nanodns.json，然后：
curl -s -X POST http://localhost:9053/reload | jq .
# → 自动推给 ns2、ns3

# 模拟节点宕机测试
docker stop nanodns-ns1
dig @127.0.0.1 -p 5302 web.internal.lan A +short  # ns2 仍正常响应
docker start nanodns-ns1
# ns1 重启后 ≤30s 自动从 ns2/ns3 追赶最新配置
```

---

### 方案五：Kubernetes（ConfigMap 统一管理）

```yaml
# 3 副本 Deployment + topologySpreadConstraints 保证跨节点
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate: { maxUnavailable: 1 }
  template:
    spec:
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: DoNotSchedule

      containers:
        - name: nanodns
          livenessProbe:
            httpGet: { path: /health, port: 9053 }
            periodSeconds: 5
          readinessProbe:
            httpGet: { path: /ready, port: 9053 }
            periodSeconds: 3
```

K8s 场景下 `peers` 可以留空——ConfigMap 变更触发滚动重启，每个新 Pod
从 ConfigMap 读取最新配置，不需要节点间同步。

---

## 运维参考

### 查看集群状态

```bash
# 单节点状态（版本号 + 缓存命中率）
curl -s http://ns1:9053/metrics | jq .

# 集群全景（所有节点版本一致性）
curl -s http://ns1:9053/cluster | jq .
# 期望输出：每个 peer 的 version 与 self.version 相同

# 快速检查版本一致性
for h in ns1 ns2 ns3; do
  printf "%-8s v%s\n" $h $(curl -s http://$h:9053/health | jq -r .version)
done
```

### 手动触发同步

```bash
# 在 ns1 重载 + 推送给所有 peer
curl -s -X POST http://ns1:9053/reload | jq '{version: .version, peers: .peers}'

# 强制 ns3 从 peer 追赶（如果它落后）
curl -s http://ns3:9053/cluster | jq '.peers | to_entries[] | select(.value.version > (.value|.version))'
# 如果 ns3 落后，30s 内 _reconcile_peers 会自动追赶；也可重启节点立即触发
```

### 新节点加入集群

1. 在新节点安装 NanoDNS，配置文件写任意一台现有节点为 peer
2. 启动 NanoDNS：`nanodns start --config nanodns.json`
3. 新节点启动 10s 后 `_reconcile_peers` 自动从 peer 拉取最新配置
4. 在现有节点的 `nanodns.json` 里把新节点加入 `peers` 并 `/reload`

---

## 方案选型

| | resolv.conf 多NS | Keepalived | HAProxy | K8s |
|---|---|---|---|---|
| 节点数 | 2+ | 2 | 2+ | 3+（建议）|
| 工作模式 | Active-Active | Active-Passive | Active-Active | Active-Active |
| 故障感知时间 | 1–5s（OS resolver）| ~2s（VRRP）| ~2s（health check）| ~5s（probe）|
| 配置管理 | peer sync | peer sync | peer sync | ConfigMap |
| 运维复杂度 | 最低 | 低 | 中 | 高（需 K8s）|
| 推荐场景 | 小型内网 | 需单 IP | 生产，流量较高 | 容器化基础设施 |

---

## 新配置字段说明

```json
{
  "server": {
    "mgmt_host": "0.0.0.0",
    "mgmt_port": 9053,
    "peers": ["10.0.0.12:9053", "10.0.0.13:9053"],
    "config_version": 1
  }
}
```

| 字段 | 默认值 | 说明 |
|------|--------|------|
| `mgmt_host` | `"0.0.0.0"` | 管理端点监听地址；生产建议限为 management VLAN IP |
| `mgmt_port` | `0` | `0` = 禁用管理端点 |
| `peers` | `[]` | 其他节点的 `host:port`（管理端口）；留空则不做节点间同步 |
| `config_version` | `1` | 自动维护，**不要手动修改** |
