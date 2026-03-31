# AnyLink 安全漏洞修复文档

## 概述

本次安全审计共发现 10 个安全漏洞，已全部按建议修复。以下为各漏洞详情及修复方案。

---

## 漏洞修复清单

### 1. LDAP 注入 (CWE-90) — 🔴 高危

**文件：** `server/dbdata/userauth_ldap.go:107-111`

**问题：** LDAP 查询过滤器直接拼接用户输入的用户名（`name`），未进行转义。攻击者可通过构造特殊用户名绕过 LDAP 认证。

**修复方案：** 对所有拼接到 LDAP 过滤器中的值使用 `ldap.EscapeFilter()` 进行转义，包括 `auth.ObjectClass`、`auth.SearchAttr`、`name` 和 `auth.MemberOf`。

```go
// 修复前
filterAttr := "(objectClass=" + auth.ObjectClass + ")"
filterAttr += "(" + auth.SearchAttr + "=" + name + ")"

// 修复后
filterAttr := "(objectClass=" + ldap.EscapeFilter(auth.ObjectClass) + ")"
filterAttr += "(" + ldap.EscapeFilter(auth.SearchAttr) + "=" + ldap.EscapeFilter(name) + ")"
```

---

### 2. JWT 签名算法未验证 (CWE-347) — 🔴 高危

**文件：** `server/admin/common.go:28-32`

**问题：** JWT 解析时的 keyfunc 未检查 `token.Method` 是否为预期的 HMAC 签名算法，存在算法混淆攻击风险。

**修复方案：** 在 keyfunc 中添加签名方法类型断言，拒绝非 HMAC 算法。

```go
// 修复后
if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
    return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
}
```

---

### 3. 默认 JWT 密钥硬编码 (CWE-798) — 🔴 高危

**文件：** `server/base/config.go:8`

**问题：** JWT 密钥有硬编码的默认值 `abcdef.0123456789.abcdef`。

**现有防护：** 代码中已有保护机制（`server/base/cfg.go:134-141`），在启动时检测到使用默认密钥时会自动生成新的随机密钥并输出警告信息。无需额外修改。

---

### 4. Shell 命令注入 (CWE-78) — 🔴 高危

**文件：**
- `server/pkg/utils/util.go:108-114`（`ParseName` 函数）
- `server/base/mod.go:73-76`（`CheckModOrLoad` 函数）

**问题：**
1. `ParseName()` 仅过滤了空格、引号、分号，但未过滤反引号 `` ` ``、`$()`、`|`、`&` 等 shell 元字符。用户名/组名通过 `ParseName()` 后传入 `ip link` 命令的 `alias` 参数。
2. `CheckModOrLoad()` 使用 `sh -c` 执行 `modprobe`，但该参数由内部硬编码值控制。

**修复方案：**
1. `ParseName()` 增加对所有 shell 危险字符的过滤（反引号、`$`、`|`、`&`、`()`、`>`、`<`、换行符）。
2. `CheckModOrLoad()` 改为直接使用 `exec.Command("modprobe", mod)` 而非 `sh -c`。

---

### 5. CORS Origin 反射 (CWE-346) — 🟠 中危

**文件：** `server/admin/api_base.go:82-88`

**问题：** 中间件将请求的 `Origin` 头直接回显为 `Access-Control-Allow-Origin` 值，等同于允许任意跨域请求。

**修复方案：** 移除 `Access-Control-Allow-Origin` 的动态回显，仅保留方法和头部的 CORS 配置。管理后台应仅允许同源访问。

---

### 6. 密码重置端点无速率限制 (CWE-770) — 🟠 中危

**文件：** `server/admin/api_user_portal.go`

**问题：** `/portal/password/request_reset` 端点无请求频率限制，攻击者可以：
- 大量发送重置邮件进行邮件轰炸
- 快速填满 token 存储空间（上限 10000）
- 通过暴力枚举用户名

**修复方案：** 添加基于客户端 IP 的速率限制器，每 5 分钟最多允许 3 次密码重置请求。超出限制返回 HTTP 429 Too Many Requests。

---

### 7. TLS 证书验证可关闭 (CWE-295) — 🟠 中危

**文件：**
- `server/admin/common.go:87`（SMTP）
- `server/dbdata/userauth_ldap.go:95`（LDAP）

**问题：** `InsecureSkipVerify` 配置项允许管理员关闭 TLS 证书验证，使 LDAP 和 SMTP 连接暴露于中间人攻击。

**修复方案：** 在 `InsecureSkipVerify` 启用时输出明确的安全警告日志，提醒管理员存在 MITM 攻击风险。

---

### 8. SQL 字符串拼接 (CWE-89) — 🟡 低危

**文件：**
- `server/dbdata/user_act_log.go:182`
- `server/dbdata/statsinfo.go:238-244`
- `server/dbdata/audit.go:60`

**问题：** `ClearUserActLog()`、`ClearStatsInfo()`、`ClearAccessAudit()` 使用字符串拼接构建 SQL WHERE 子句。虽然当前 `ts` 参数来自服务端 cron 内部生成，非用户直接可控，但此编码模式不安全。

**修复方案：** 全部改为参数化查询（使用 `?` 占位符）。

```go
// 修复前
xdb.Where("created_at < '" + ts + "'").Delete(&UserActLog{})

// 修复后
xdb.Where("created_at < ?", ts).Delete(&UserActLog{})
```

**注意：** `getStatsWhere()` 中的 `sd.feTime` 和 `min` 同样使用字符串拼接，但它们是由服务端 `time.Now().Format()` 和 `strconv.Itoa()` 生成的，不可被外部控制。由于涉及数据库特定的函数语法（TIMESTAMPDIFF、JULIANDAY 等），这些不适合简单参数化，且当前无安全风险。

---

### 9. 不安全指针操作 (CWE-248) — 🟡 低危

**文件：** `server/pkg/utils/unsafe.go`

**问题：** 使用 `unsafe.Pointer` 进行 `[]byte` 和 `string` 之间的零拷贝转换，绕过 Go 的内存安全机制。在 Go 版本升级或 GC 优化变化时可能导致内存损坏。

**修复方案：** 替换为标准的安全类型转换（`string(b)` 和 `[]byte(s)`）。现代 Go 编译器已对这些转换进行了优化，性能差异极小。

---

### 10. X-Portal-User 通过请求头传递 (CWE-287) — 🟠 中危

**文件：** `server/admin/api_user_portal.go:525-533`

**问题：** Portal 中间件通过 `r.Header.Set("X-Portal-User", ...)` 传递已认证的用户名，下游通过 `r.Header.Get("X-Portal-User")` 获取。由于 HTTP 请求头可以被客户端伪造（虽然中间件会覆盖，但这种模式在安全编码中是不推荐的），使用 `context.Context` 是更安全的做法。

**修复方案：** 改为使用 Go 的 `context.Context` 传递用户名，使用不可导出的 `contextKey` 类型防止键冲突：

```go
type contextKey string
const portalUserKey contextKey = "portal_user"

// 中间件中
ctx := context.WithValue(r.Context(), portalUserKey, username)
next.ServeHTTP(w, r.WithContext(ctx))

// 获取用户名
func getUsernameFromCtx(r *http.Request) string {
    if v, ok := r.Context().Value(portalUserKey).(string); ok {
        return v
    }
    return ""
}
```

---

## 修复文件汇总

| 文件 | 修改类型 |
|------|----------|
| `server/dbdata/userauth_ldap.go` | LDAP 注入修复 + TLS 警告日志 |
| `server/admin/common.go` | JWT 算法验证 + SMTP TLS 警告日志 |
| `server/pkg/utils/util.go` | Shell 字符过滤增强 |
| `server/pkg/utils/unsafe.go` | 移除 unsafe 指针操作 |
| `server/admin/api_base.go` | CORS 策略修复 |
| `server/admin/api_user_portal.go` | 密码重置限速 + Context 传递用户名 |
| `server/dbdata/user_act_log.go` | SQL 参数化查询 |
| `server/dbdata/statsinfo.go` | SQL 参数化查询 |
| `server/dbdata/audit.go` | SQL 参数化查询 |
| `server/base/mod.go` | 移除 sh -c 调用 |

## 验证

所有修改已通过：
- ✅ 代码编译 (`go build ./dbdata/ ./handler/ ./admin/ ./base/ ./sessdata/ ./cron/ ./pkg/...`)
- ✅ 单元测试 (`go test ./pkg/utils/ ./admin/ ./dbdata/ ./sessdata/`)
