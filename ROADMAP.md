# AnyLink 项目迭代路线图

> 本文档基于项目现状分析，制定了详细的迭代发展计划。  
> 分为 6 个迭代阶段，每阶段包含明确的目标、具体任务、涉及文件、验收标准和依赖关系。  
> 预计总周期约 12-18 个月，各阶段可根据实际需求灵活调整优先级。

---

## 当前项目现状

### 已有能力
| 能力领域 | 现状 |
|---------|------|
| 认证方式 | 本地数据库、LDAP/AD、RADIUS、TOTP 双因素 |
| 网络模式 | TUN (NAT/桥接)、TAP、macvtap、DTLS-UDP |
| 会话管理 | 内存存储、单节点、TTL 过期 |
| 访问控制 | 用户组策略、ACL (IP/端口/协议)、用户级策略覆盖 |
| 监控告警 | Prometheus 基础指标、内存实时统计、历史聚合 |
| 管理界面 | Vue 2 + Element UI 管理后台、用户自助门户 |
| 部署方式 | Docker (特权/非特权)、Docker Compose、Systemd、K8s 基础 YAML |
| 安全机制 | JWT 认证、防暴力破解、请求限制、LDAP 注入防护 |

### 关键技术栈
- **后端**: Go 1.22, xORM, gorilla/mux, lego (ACME)
- **前端**: Vue 2.6, Element UI 2.4, ECharts, Axios
- **数据库**: SQLite3 / MySQL / PostgreSQL / MSSQL
- **协议**: OpenConnect (IETF draft), TLS 1.2+, DTLS 1.2

### 核心架构限制 (迭代需解决)
1. **会话内存存储** → 单节点瓶颈，无法横向扩展
2. **IPv4 Only** → ARP 模块不支持 IPv6
3. **Vue 2 即将 EOL** → 前端框架需升级
4. **无 API 文档** → 不利于二次开发和生态集成
5. **测试覆盖率 < 15%** → 重构风险高

---

## 迭代阶段总览

```
Phase 1 (v0.16)  基础设施加固       ← 当前优先
Phase 2 (v0.17)  企业认证集成
Phase 3 (v0.18)  高可用与集群化
Phase 4 (v0.19)  安全与合规增强
Phase 5 (v0.20)  监控运营与生态
Phase 6 (v1.0)   前端现代化与产品化
```

---

## Phase 1: 基础设施加固 (v0.16)

> **目标**: 提升代码质量、完善测试覆盖、补全 API 文档，为后续大规模重构打好基础。

### 1.1 测试覆盖率提升

**目标**: 关键模块测试覆盖率从 <15% 提升到 50%+

| 任务 | 涉及文件/目录 | 验收标准 |
|------|-------------|---------|
| 认证模块单元测试 | `server/dbdata/user.go`<br>`server/dbdata/userauth_ldap.go`<br>`server/dbdata/userauth_radius.go` | 覆盖正常登录、密码错误、账户过期、LDAP/RADIUS 超时等场景 |
| Admin API 集成测试 | `server/admin/api_user.go`<br>`server/admin/api_group.go`<br>`server/admin/api_set*.go` | 覆盖 CRUD 操作、权限校验、参数校验 |
| 会话管理测试 | `server/sessdata/session.go`<br>`server/sessdata/ip_pool.go` | 覆盖会话创建/销毁、并发安全、IP 分配/回收 |
| ACL 规则引擎测试 | `server/handler/payload.go`<br>`server/dbdata/group.go` | 覆盖 TCP/UDP/ICMP 匹配、端口范围、CIDR 验证 |
| Portal API 测试 | `server/admin/api_user_portal.go` | 覆盖登录、密码修改、OTP 绑定全流程 |

**具体实现方案**:
- 使用 SQLite 内存数据库进行测试 (参考现有 `preIpData/closeIpdata` 模式)
- 使用 `httptest.NewRecorder` 测试 HTTP Handler
- Mock LDAP/RADIUS 外部依赖
- 在 CI 中增加 `go test -coverprofile` 并上报 Codecov

### 1.2 OpenAPI 文档生成

**目标**: 所有 Admin API 和 Portal API 自动生成 Swagger/OpenAPI 3.0 文档

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 集成 swag 工具 | `server/admin/server.go`<br>`server/admin/api_*.go` | 所有 Handler 函数添加 swag 注释 |
| 请求/响应结构体标注 | `server/admin/api_base.go`<br>`server/dbdata/tables.go` | 所有 DTO 添加 json tag 和 swag 描述 |
| Swagger UI 集成 | `server/admin/server.go` | `/swagger/` 路径提供交互式文档 |
| API 版本化准备 | `server/admin/server.go` | 路由增加 `/v1/` 前缀 (保留旧路由兼容) |

**具体实现方案**:
- 引入 `github.com/swaggo/swag` 和 `github.com/swaggo/http-swagger`
- 每个 Handler 添加 `@Summary`, `@Description`, `@Tags`, `@Accept`, `@Produce`, `@Param`, `@Success`, `@Failure` 注释
- 构建时通过 `swag init` 自动生成 `docs/` 目录
- CI 中添加 `swag init` 校验步骤

### 1.3 配置管理优化

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 环境变量映射完善 | `server/base/config.go` | 所有配置项均可通过 `LINK_` 前缀环境变量覆盖 |
| 配置校验增强 | `server/base/cfg.go` | 启动时校验必填项、格式、范围，错误时输出明确提示 |
| 配置热重载 (部分) | `server/base/config.go`<br>`server/dbdata/setting.go` | 证书、SMTP、审计策略支持数据库级热更新，无需重启 |
| Docker 环境变量文档 | `docker/` | Dockerfile 中列出所有支持的 ENV 变量 |

### 1.4 IPv6 基础支持

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| NDP 协议实现 | `server/pkg/arpdis/` | 新增 `ndp.go` 实现 IPv6 邻居发现 |
| IPv6 隧道地址分配 | `server/sessdata/ip_pool.go` | 支持 IPv6 CIDR 配置和地址分配 |
| IPv6 路由下发 | `server/handler/link_tunnel.go` | CSTP 响应头包含 IPv6 路由信息 |
| 双栈模式配置 | `server/base/config.go`<br>`server/conf/server-sample.toml` | 新增 `ipv6_cidr`, `ipv6_gateway` 等配置项 |
| IPv6 ACL 支持 | `server/handler/payload.go`<br>`server/dbdata/group.go` | ACL 规则支持 IPv6 CIDR 匹配 |

**注意事项**:
- 当前 `server/pkg/arpdis/arp.go:4` 已标注 `TODO: IPv4 only`
- TAP 模式下已有 IPv6 包类型识别 (EtherType 0x86DD) 但被丢弃
- 需要同时处理 TUN 和 TAP 两种模式下的 IPv6 数据转发

---

## Phase 2: 企业认证集成 (v0.17)

> **目标**: 接入企业级 SSO 和第三方认证，满足企业统一身份管理需求。

### 2.1 SAML 2.0 / SSO 支持

**目标**: 支持对接 Okta、Azure AD、Keycloak 等主流 IdP

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| SAML SP 实现 | 新增 `server/dbdata/userauth_saml.go` | 完成 SP 元数据生成、断言解析、签名验证 |
| SAML 认证流程集成 | `server/handler/link_auth.go` | 支持 SP-Initiated SSO 和 IdP-Initiated SSO |
| SAML 配置 UI | `web/src/pages/group/List.vue` | 组认证配置中新增 SAML 类型，支持 IdP 元数据 URL 导入 |
| SAML 组映射 | `server/dbdata/userauth_saml.go` | 支持基于 SAML 属性自动分配用户组 |
| SAML 测试 | `server/dbdata/userauth_saml_test.go` | Mock IdP 测试完整 SSO 流程 |

**技术选型**: `github.com/crewjam/saml` 库

**认证流程设计**:
```
1. 用户在 AnyConnect 客户端输入连接地址
2. AnyLink 检测到组配置为 SAML，返回 SSO 重定向 URL
3. 用户浏览器跳转到 IdP 登录页面
4. IdP 认证成功后，POST SAML Response 到 AnyLink ACS 端点
5. AnyLink 验证断言签名、时间、Audience 等条件
6. 创建 VPN 会话，返回 Session Token 给客户端
```

### 2.2 OAuth2 / OIDC 支持

**目标**: 支持 GitHub、Google、企业微信、钉钉、飞书扫码登录

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| OAuth2 通用框架 | 新增 `server/dbdata/userauth_oauth.go` | 实现 Authorization Code Flow |
| OIDC 发现 | `server/dbdata/userauth_oauth.go` | 支持 `.well-known/openid-configuration` 自动发现 |
| 企业微信适配 | 新增 `server/dbdata/userauth_wechat.go` | 支持企业微信扫码登录和用户信息获取 |
| 钉钉适配 | 新增 `server/dbdata/userauth_dingtalk.go` | 支持钉钉扫码登录 |
| 飞书适配 | 新增 `server/dbdata/userauth_feishu.go` | 支持飞书扫码登录 |
| OAuth 回调页面 | 新增 `server/handler/link_auth_oauth.go` | 处理 OAuth 回调、Token 交换、用户映射 |
| 前端登录页适配 | `web/src/pages/Login.vue` | 显示第三方登录按钮 |

**技术选型**: `golang.org/x/oauth2` + 各平台 SDK

**配置结构设计**:
```go
type AuthOAuth struct {
    Provider       string // generic, wechat, dingtalk, feishu
    ClientID       string
    ClientSecret   string
    AuthURL        string // Authorization endpoint
    TokenURL       string // Token endpoint
    UserInfoURL    string // UserInfo endpoint
    Scopes         []string
    UserMapping    map[string]string // IdP field → AnyLink field
    AutoCreateUser bool              // 自动创建用户
    DefaultGroups  []string          // 自动分配的默认组
}
```

### 2.3 LDAP 用户同步增强

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 定时自动同步 | `server/cron/ldap_sync.go` (新增) | 支持定时从 LDAP 同步用户列表 |
| 增量同步 | `server/dbdata/userauth_ldap.go` | 基于 `whenChanged` 属性增量同步 |
| 组映射规则 | `server/dbdata/userauth_ldap.go` | 支持 LDAP 组 → AnyLink 组的映射规则 |
| 同步日志 | `server/dbdata/userauth_ldap.go` | 同步过程详细日志，包括新增/更新/禁用统计 |
| 同步配置 UI | `web/src/pages/set/Other.vue` | LDAP 同步间隔、映射规则配置界面 |

### 2.4 多因素认证策略增强

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 按组配置 MFA 级别 | `server/dbdata/tables.go` Group 结构体 | 组可配置: 无 MFA / 可选 MFA / 强制 MFA |
| MFA 白名单网段 | `server/handler/link_auth.go` | 来自内网 IP 段的连接可豁免 MFA |
| 设备信任记忆 | `server/handler/link_auth_otp.go` | 已验证设备 (MAC+证书) 一定时间内免 OTP |
| FIDO2/WebAuthn 支持 | 新增 `server/dbdata/userauth_webauthn.go` | 支持 YubiKey 等硬件密钥认证 |

---

## Phase 3: 高可用与集群化 (v0.18)

> **目标**: 实现多节点部署、会话共享、负载均衡，支撑大规模企业用户接入。

### 3.1 Redis 会话后端

**目标**: 将内存会话存储迁移到 Redis，实现多节点会话共享

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 会话存储接口抽象 | `server/sessdata/session.go` | 定义 `SessionStore` 接口 (Get/Set/Delete/List) |
| 内存存储适配 | `server/sessdata/store_memory.go` (新增) | 现有逻辑迁移为内存实现 (默认) |
| Redis 存储适配 | `server/sessdata/store_redis.go` (新增) | Redis Hash 存储会话，支持 TTL |
| IP 池 Redis 化 | `server/sessdata/ip_pool.go` | IP 分配使用 Redis Set 实现跨节点互斥 |
| DTLS Session 共享 | `server/sessdata/session.go` | DTLS SessionID → Token 映射存入 Redis |
| Redis 配置 | `server/base/config.go`<br>`server/conf/server-sample.toml` | 新增 `redis_addr`, `redis_password`, `redis_db` 配置 |

**接口设计**:
```go
type SessionStore interface {
    NewSession(sess *Session) error
    GetSession(token string) (*Session, error)
    DeleteSession(token string) error
    ListSessions() ([]*Session, error)
    GetSessionByDtls(dtlsSid string) (*Session, error)
    
    // IP Pool
    AllocateIP(pool string) (net.IP, error)
    ReleaseIP(pool string, ip net.IP) error
    IsIPAllocated(pool string, ip net.IP) (bool, error)
}
```

**Redis 数据结构设计**:
```
anylink:session:{token}     → Hash (Session 字段)
anylink:dtls:{dtlsSid}      → String (token)
anylink:ippool:{pool}       → Set (已分配 IP 列表)
anylink:ipmap:{mac}         → String (固定 IP)
anylink:online:count        → String (在线人数)
anylink:lock:{username}     → String (锁定状态, 带 TTL)
```

### 3.2 负载均衡支持

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 节点注册与心跳 | 新增 `server/cluster/node.go` | 节点向 Redis 注册，定时心跳 |
| 会话亲和性 | `server/handler/link_tunnel.go` | 支持 Proxy Protocol 传递客户端真实 IP |
| 跨节点用户踢出 | `server/sessdata/session.go` | 通过 Redis Pub/Sub 广播踢人事件 |
| 带宽统计聚合 | `server/dbdata/statsinfo.go` | 多节点带宽数据聚合统计 |
| 集群状态页面 | `web/src/pages/Home.vue` | 仪表盘显示各节点状态、连接数分布 |

### 3.3 数据库优化

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 连接池配置化 | `server/dbdata/db.go` | MaxOpenConns、MaxIdleConns、ConnMaxLifetime 可配置 |
| 审计日志分表 | `server/dbdata/db_orm.go` | 支持按月自动分表 (MySQL/PostgreSQL) |
| 慢查询日志 | `server/dbdata/db.go` | 超过阈值的查询记录到日志 |
| 数据库迁移工具 | 新增 `server/dbdata/migration.go` | 版本化数据库迁移 (替代 xORM 自动同步) |

### 3.4 Helm Chart

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| Chart 基础结构 | 新增 `deploy/helm/anylink/` | Chart.yaml, values.yaml, templates/ |
| Deployment 模板 | `deploy/helm/anylink/templates/deployment.yaml` | 支持多副本、资源限制、亲和性配置 |
| Service 模板 | `deploy/helm/anylink/templates/service.yaml` | TCP/UDP 端口，可选 LoadBalancer |
| ConfigMap/Secret | `deploy/helm/anylink/templates/` | 配置文件和密钥管理 |
| HPA 自动扩缩 | `deploy/helm/anylink/templates/hpa.yaml` | 基于 CPU/连接数的自动扩缩 |
| 健康检查探针 | `deploy/helm/anylink/templates/deployment.yaml` | liveness + readiness + startup probe |
| 文档 | `deploy/helm/anylink/README.md` | 安装、升级、配置说明 |

---

## Phase 4: 安全与合规增强 (v0.19)

> **目标**: 实现零信任网络访问能力，满足企业安全合规要求。

### 4.1 设备合规检查 (NAC)

**目标**: 客户端连接前检查设备安全状态

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 设备信息采集 | `server/handler/link_tunnel.go` | 从 AnyConnect 客户端采集 OS 版本、补丁级别 |
| 合规策略定义 | 新增 `server/dbdata/compliance.go` | 定义合规规则 (最低 OS 版本、防病毒状态等) |
| 合规检查引擎 | 新增 `server/handler/link_compliance.go` | 连接时执行合规检查，不合规拒绝接入 |
| 合规策略 UI | `web/src/pages/group/` | 按组配置合规策略 |
| 合规日志 | `server/dbdata/tables.go` | 新增 ComplianceLog 表记录检查结果 |

**合规规则模型**:
```go
type CompliancePolicy struct {
    Id              int
    Name            string
    MinOSVersion    map[string]string  // {"windows": "10.0", "macos": "12.0"}
    RequireAntivirus bool
    RequireFirewall  bool
    AllowJailbroken  bool
    CustomChecks     []ComplianceCheck
    Action           string            // "block" | "warn" | "quarantine"
}
```

### 4.2 零信任访问控制

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 动态 ACL 引擎 | `server/handler/payload.go` | ACL 规则支持基于时间、设备、位置的条件 |
| 最小权限策略 | `server/dbdata/group.go` | 默认拒绝所有，仅允许显式授权的资源 |
| 会话实时评估 | `server/sessdata/session.go` | 连接期间持续评估风险，动态调整权限 |
| 微分段支持 | `server/handler/payload.go` | 细粒度的应用级访问控制 (Layer 7) |

### 4.3 审计与合规报告

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| Syslog 输出 | 新增 `server/base/syslog.go` | 支持 RFC 5424 Syslog 日志输出 |
| CEF 格式日志 | `server/base/syslog.go` | 支持 ArcSight CEF 格式 (SIEM 集成) |
| 合规报表导出 | `server/admin/api_set_audit.go` | 生成 PDF/CSV 合规报表 |
| 操作审计 | 新增 `server/admin/audit_middleware.go` | 管理员操作全部记录到独立审计表 |
| 数据保留策略 | `server/dbdata/setting.go` | 可配置的日志保留周期，自动清理 |

### 4.4 异常检测

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 异地登录检测 | `server/handler/link_auth.go` | 基于 IP 地理位置检测异地登录 |
| 异常时间登录 | `server/handler/link_auth.go` | 非工作时间登录触发告警 |
| 风险评分引擎 | 新增 `server/admin/risk_score.go` | 综合登录频率、地点、设备、时间的风险评分 |
| 自动响应 | `server/admin/lockmanager.go` | 高风险操作自动限制或阻断 |

---

## Phase 5: 监控运营与生态集成 (v0.20)

> **目标**: 完善监控告警体系，打通企业 IM 和运维工具链。

### 5.1 Webhook 告警系统

**目标**: 关键事件实时推送到企业 IM

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| Webhook 框架 | 新增 `server/admin/webhook.go` | 统一的 Webhook 发送接口 |
| 企业微信适配 | `server/admin/webhook.go` | 支持企业微信群机器人 Webhook |
| 钉钉适配 | `server/admin/webhook.go` | 支持钉钉群机器人 Webhook |
| 飞书适配 | `server/admin/webhook.go` | 支持飞书群机器人 Webhook |
| Slack 适配 | `server/admin/webhook.go` | 支持 Slack Incoming Webhook |
| 告警事件定义 | `server/admin/webhook.go` | 用户上线/下线/认证失败/账户锁定/证书即将过期 |
| 告警配置 UI | `web/src/pages/set/Other.vue` | Webhook URL、事件类型选择 |

**事件类型枚举**:
```go
const (
    EventUserLogin       = "user.login"
    EventUserLogout      = "user.logout"
    EventAuthFailed      = "auth.failed"
    EventAccountLocked   = "account.locked"
    EventCertExpiring    = "cert.expiring"
    EventHighBandwidth   = "bandwidth.high"
    EventNodeDown        = "node.down"
    EventConfigChanged   = "config.changed"
)
```

### 5.2 Grafana 集成

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| Prometheus 指标完善 | `server/admin/api_health.go` | 新增连接延迟、认证耗时、ACL 命中率等指标 |
| Grafana 仪表盘模板 | 新增 `deploy/grafana/anylink-dashboard.json` | 开箱即用的监控面板 |
| 告警规则模板 | 新增 `deploy/grafana/anylink-alerts.yaml` | Grafana 告警规则模板 |
| 文档 | 新增 `doc/monitoring.md` | Prometheus + Grafana 部署和配置指南 |

**新增 Prometheus 指标**:
```
anylink_auth_duration_seconds{method,status}   - 认证请求耗时
anylink_auth_total{method,status}              - 认证请求总数
anylink_active_sessions{group}                 - 各组活跃会话数
anylink_acl_hits_total{action}                 - ACL 命中次数
anylink_tunnel_errors_total{type}              - 隧道错误次数
anylink_cert_expiry_days{domain}               - 证书剩余有效天数
anylink_ip_pool_usage{pool}                    - IP 池使用率
anylink_dtls_handshake_duration_seconds        - DTLS 握手耗时
```

### 5.3 用量报表系统

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 报表数据聚合 | 新增 `server/admin/report.go` | 按用户/组/时段聚合使用统计 |
| 报表 API | `server/admin/server.go` | `/report/{daily,weekly,monthly}` 接口 |
| PDF 报表导出 | `server/admin/report.go` | 支持下载 PDF 格式报表 |
| CSV 数据导出 | `server/admin/report.go` | 支持 CSV 格式原始数据导出 |
| 定时报表邮件 | `server/cron/report.go` (新增) | 支持定时发送周报/月报到管理员邮箱 |

### 5.4 OpenTelemetry 集成

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| OTel SDK 集成 | `server/base/` | 初始化 TracerProvider 和 MeterProvider |
| 链路追踪注入 | `server/handler/link_auth.go`<br>`server/handler/link_tunnel.go` | 关键操作添加 Span |
| 日志关联 | `server/base/log.go` | 日志中包含 TraceID |
| 配置项 | `server/base/config.go` | `otel_endpoint`, `otel_service_name` |

---

## Phase 6: 前端现代化与产品化 (v1.0)

> **目标**: 前端框架升级，提升用户体验，达到 1.0 发布品质。

### 6.1 前端框架升级

**目标**: Vue 2 + Element UI → Vue 3 + Element Plus (或 Naive UI)

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 技术选型与脚手架 | `web/` | Vue 3 + Vite + TypeScript + Element Plus |
| 页面迁移 - 登录 | `web/src/pages/Login.vue` | 功能等价 + SSO 登录按钮 |
| 页面迁移 - 仪表盘 | `web/src/pages/Home.vue` | 实时统计 + 集群节点状态 |
| 页面迁移 - 用户管理 | `web/src/pages/user/*.vue` | 所有 CRUD + 在线管理 |
| 页面迁移 - 组管理 | `web/src/pages/group/*.vue` | 认证配置 + 策略管理 |
| 页面迁移 - 设置 | `web/src/pages/set/*.vue` | 所有设置页面 |
| 页面迁移 - 审计 | `web/src/components/audit/*.vue` | 操作日志 + 访问审计 |
| 响应式适配 | 所有页面 | 移动端管理界面可用 |
| 暗色主题 | 全局样式 | 支持暗色/亮色主题切换 |

### 6.2 用户自助门户增强

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 门户界面独立化 | `web/src/pages/portal/` | 独立的用户门户 SPA |
| 设备管理 | 门户 API + 前端 | 用户可查看/解绑已授权设备 |
| 连接指引 | 门户前端 | 根据 OS 显示对应客户端下载和配置步骤 |
| 自助组申请 | 门户 API + 前端 | 用户可申请加入新组 (需管理员审批) |
| 通知中心 | 门户前端 | 展示密码即将过期、证书更新等通知 |

### 6.3 国际化 (i18n)

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 前端 i18n 框架 | `web/` | 集成 vue-i18n，提取所有硬编码文本 |
| 中文语言包 | `web/src/locales/zh-CN.json` | 完整的中文翻译 |
| 英文语言包 | `web/src/locales/en-US.json` | 完整的英文翻译 |
| 后端错误消息国际化 | `server/` | API 错误消息支持多语言 |
| 语言切换 | 前端 | 支持用户手动切换语言 |

### 6.4 产品化打磨

| 任务 | 涉及文件 | 验收标准 |
|------|---------|---------|
| 安装引导向导 | 门户前端 | 首次安装的图形化配置引导 |
| 备份恢复功能 | `server/admin/api_backup.go` (新增) | 支持配置和用户数据的导出/导入 |
| 版本升级检查 | `server/admin/api_health.go` | 后台提示新版本可用 |
| 完善文档站 | `doc/` | API 参考、运维手册、故障排查指南 |
| 性能测试报告 | `doc/benchmark.md` | 不同规模下的性能基线数据 |

---

## 依赖关系与里程碑

```
Phase 1 (基础设施加固)
  │
  ├── Phase 2 (企业认证) ← 依赖: API 文档、测试框架
  │     │
  │     └── Phase 4 (安全合规) ← 依赖: 认证框架
  │
  ├── Phase 3 (高可用集群) ← 依赖: 测试覆盖、配置优化
  │     │
  │     └── Phase 5 (监控运营) ← 依赖: 集群架构、Prometheus 指标
  │
  └── Phase 6 (前端现代化) ← 可独立进行，但建议在 Phase 2 后启动
```

### 里程碑定义

| 里程碑 | 版本 | 关键交付物 |
|--------|------|-----------|
| M1: 质量基线 | v0.16 | 测试覆盖率 50%+, OpenAPI 文档, IPv6 基础 |
| M2: 企业就绪 | v0.17 | SAML SSO, OAuth2, 企业 IM 登录, LDAP 同步 |
| M3: 规模就绪 | v0.18 | Redis 会话, 多节点集群, Helm Chart |
| M4: 安全合规 | v0.19 | NAC, 零信任策略, SIEM 集成, 合规报表 |
| M5: 运营就绪 | v0.20 | Webhook 告警, Grafana 面板, 用量报表 |
| M6: 正式发布 | v1.0 | Vue 3 前端, i18n, 安装引导, 完整文档 |

---

## 技术选型参考

### 新增依赖评估

| 用途 | 候选库 | 选择理由 |
|------|--------|---------|
| SAML 2.0 | `github.com/crewjam/saml` | Go 生态最活跃的 SAML 库 |
| OAuth2 | `golang.org/x/oauth2` | 官方库，稳定可靠 |
| Redis | `github.com/redis/go-redis/v9` | 官方推荐客户端 |
| WebAuthn | `github.com/go-webauthn/webauthn` | W3C WebAuthn 标准实现 |
| Swagger | `github.com/swaggo/swag` | Go 生态主流 API 文档工具 |
| GeoIP | `github.com/oschwald/maxminddb-golang` | 高性能 IP 地理位置查询 |
| PDF 报表 | `github.com/jung-kurt/gofpdf` | 纯 Go PDF 生成 |
| OpenTelemetry | `go.opentelemetry.io/otel` | CNCF 官方可观测性标准 |
| Vue 3 | `vue@3` + `element-plus` | 官方推荐升级路径 |
| i18n | `vue-i18n@9` | Vue 3 官方国际化方案 |

---

## 风险与缓解

| 风险 | 影响 | 概率 | 缓解措施 |
|------|------|------|---------|
| Redis 引入增加运维复杂度 | 高 | 中 | 默认内存模式，Redis 为可选项 |
| SAML/OAuth 认证流程与 AnyConnect 协议冲突 | 高 | 中 | 研究 AnyConnect SSO 协议扩展，必要时通过 Portal 页面中转 |
| Vue 2→3 迁移工作量大 | 中 | 高 | 使用 @vue/compat 渐进迁移，分页面逐步替换 |
| IPv6 支持影响现有网络功能 | 高 | 低 | 双栈模式默认关闭，充分测试后再默认启用 |
| 集群模式下 DTLS 会话迁移困难 | 高 | 中 | 首期仅支持会话亲和 (Sticky Session)，后续实现会话迁移 |
| 第三方 IdP 兼容性问题 | 中 | 中 | 优先支持主流 IdP (Okta, Azure AD, Keycloak)，提供详细配置文档 |

---

## 贡献指南

### 参与迭代开发

1. 选择感兴趣的 Phase 和任务
2. 在 Issues 中创建对应 Issue 并关联此路线图
3. 新建 PR 提交到 `dev` 分支
4. 确保新增代码有对应的测试用例
5. 更新相关文档

### 任务认领

请在对应任务后标注认领人和预计完成时间：
- 格式: `@username (预计 YYYY-MM-DD)`
- 例如: `@contributor1 (预计 2026-06-15)`

---

> 📝 本文档为动态文档，将根据社区反馈和实际进展持续更新。  
> 最后更新: 2026-03-31
