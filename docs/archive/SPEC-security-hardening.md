> **已执行归档**（1.1.0）。实现与验收记录见 `docs/SPEC.md`，迁移步骤见 `docs/MIGRATION-1.1.md`。

# SPEC · 安全重构（1.1.0）

> 工单：零隐式信任 + 双平面 + 设备配对 + TLS。执行完成后并入 `SPEC.md` 并移入 `docs/archive/`。
> 状态：执行中（分支 `refactor/security`）。基线 1.0.0 → **1.1.0（B 位）**；过程中用 C 位标记检查点（1.0.1、1.0.2…）。

## 1. 背景与目标

1.0.0 的公开发布版把"回环"当作信任边界，导致三类对手中的两类未覆盖：

- A 局域网/Tailnet 设备：已有 token/凭据，基本覆盖；
- B 本机其他进程/用户：回环免鉴权、凭据明文/ACL 宽、凭据接口免鉴权；
- C 浏览器页面：无 Origin/Host/Content-Type/CSRF 校验 → 任意网页可 CSRF 改命令并执行（SEC-01）。

目标：**取消隐式信任**，所有请求经同一套声明式鉴权；本地管理面、远程面板、节点互联三套身份彼此独立；非回环默认 TLS；设备靠一次性配对建立长期信任。

## 2. 不可变条件

- 只处理局域网/同一 Tailnet，不接受公网请求；不做 UPnP/端口转发。
- 后端继续以 Python 标准库为主；本轮经用户明确许可可引入外部库（`cryptography` 用于 TLS/密钥）。
- 被监控服务默认只读；写边界仍按 `services[].settings` 白名单。
- 面板视觉与主要信息架构不变；功能集合不缩水。
- 版本规则：A 不动（1）；整个计划完成升 B（1.1.0）；执行过程中用 C 标记检查点（1.0.1、1.0.2…）。

## 3. 目标架构

### 3.1 三个平面

| 平面 | 入口 | 身份 | 默认 |
| --- | --- | --- | --- |
| 本地管理面 | 回环 listener（HTTP） | 壳注入的 launch token → 短会话；浏览器登录（管理员口令） | 开 |
| 远程面板面 | 网络 listener（HTTPS） | 设备配对（一次性码 → 设备密钥/设备 token）；管理员口令登录 | 关，显式开启 |
| 节点互联面 | 网络 listener 或 SSH 中转 | 节点配对（交换公钥/指纹）→ 节点 token | 关，显式配对 |

### 3.2 网络模式

- 默认 `127.0.0.1:8090`，HTTP（不出机器）。
- 网络访问两档正式模式，均需显式开启：
  - `lan`：绑定指定网卡（默认当前 LAN IP）`<ip>:8443`，HTTPS，CIDR 白名单（RFC1918）。
  - `tailnet`：只绑 Tailscale 地址 `100.x:8443`（或用户指定），HTTPS，`100.64.0.0/10` 白名单。
- 监听地址不使用 `0.0.0.0` 作为网络模式实现；检测到当前网络为 Public 时拒绝开启并提示。
- TLS：首次开启时用 `cryptography` 生成 ECDSA P-256 自签证书（SAN：主机名 + 各接口 IP），
  指纹在 UI/配对二维码展示；手机钉指纹。证书/私钥存 `.state/tls/`，ACL 收紧。

### 3.3 身份与凭据

- 节点身份：ECDSA P-256 证书（TLS）+ Ed25519 签名密钥（配对/审计）；首次运行生成。
- 管理员口令：`hashlib.scrypt`（n=2^14, r=8, p=1，16 B salt），`hmac.compare_digest` 校验；
  首次启动生成一次性 **setup code**（仅内存 + 界面展示，不落盘），强制设口令后才能写操作。
- 会话：32 B 随机会话 id，服务端 `SessionStore`；Cookie = `HMAC(node-secret, sid)`，
  `HttpOnly + SameSite=Strict + Secure(HTTPS) + Path=/`；TTL 30 min 滑动，最长 30 天；可吊销。
- launch token：壳启动时生成（仅内存），经 URL fragment 交给 WebView，交换本地 write 会话；
  不进入日志/查询串。
- 本地 CLI/脚本：`.state/local-token`（随机 32 B，ACL 仅当前用户+SYSTEM+Admins），
  经 `X-Mozunitor-Local-Token` 使用；不再有 `?token=` 与 loopback 免鉴权。
- 设备：配对后生成设备密钥（Android Keystore 保存）/设备 token；作用域 read 或 write；
  UI 可列出设备、最后使用时间、吊销。
- 节点：配对后保存对端节点 id + 公钥指纹 + 节点 token（`.state/peers.json`）；不再使用
  `SHA256(username:password)` 作为节点共享密钥。

### 3.4 请求管线（所有请求，顺序固定）

1. **listener 判定**：本地 / 网络；网络 listener 先查来源 CIDR，非白名单 403。
2. **Host 校验**：只接受该 listener 的地址集合（IP/主机名/端口）；否则 421/403。
3. **路由匹配**：声明式 `ROUTES` 表；未知路径 404；方法不符 405。
4. **认证**：会话 Cookie / 本地 token / 设备 token / launch token 交换；无隐式回环信任。
5. **授权**：`read < write < admin`；每条路由声明所需 scope；本地专属路由（如 `commands`、
   `credentials` 替代品）额外要求 listener=local。
6. **CSRF**：Cookie 认证的写请求必须带 `X-Mozunitor-CSRF`（与会话绑定）；
   带 `Origin` 必须同源；`Sec-Fetch-Site: cross-site` 直接 403；Header 认证（本地/设备 token）豁免。
7. **Content-Type**：JSON 端点必须 `application/json`，否则 415；请求体上限 64 KB（登录/配对 8 KB）。
8. **限流**：登录/配对按 IP+身份指数退避；失败锁定；其余写操作按 IP 限速。
9. **审计**：所有写操作与认证事件写 `logs/security.jsonl`（不含 token/口令）。
10. **响应头**：CSP、`X-Content-Type-Options`、`X-Frame-Options: DENY`、`Referrer-Policy: no-referrer`、
    `Cache-Control: no-store`；`Server: Mozunitor`（不带版本）。

### 3.5 路由表（API v2）

| 方法/路径 | scope | listener | CSRF | 说明 |
| --- | --- | --- | --- | --- |
| `GET /`、`/static/*` | 无 | any | - | 静态资源（不含数据） |
| `GET /api/setup/status` | 无 | local | - | 仅返回 needs_setup/节点名/版本 |
| `POST /api/setup/complete` | setup | local | - | 一次性 setup code + 设管理员口令 |
| `POST /api/session/login` | 无 | any | - | 口令 → 会话（限流） |
| `POST /api/session/launch` | launch | local | - | launch token → 会话 |
| `GET /api/session` | read | any | - | 当前会话/级别/设备 |
| `POST /api/session/logout` | read | any | 是 | 注销当前会话 |
| `GET /api/state`、`/api/node`、`/api/history` | read | any | - | 监控数据（字段最小化后） |
| `POST /api/restart`、`/api/stop` | write | any | 是 | 单任务锁；回执必须带判据 |
| `GET /api/op` | read | any | - | 视图/链接 |
| `POST /api/op` | write | any | 是 | 脚本/动作（脚本目录对齐 APP_DIR） |
| `GET /api/settings` | read | any | - | 远端不带命令字段 |
| `POST /api/settings` | write | any | 是 | `commands` 段 admin+local |
| `GET/POST /api/service-settings` | read/write | any | POST 是 | 白名单参数，写前确认+审计 |
| `GET /api/security` | admin | any | - | 网络模式/证书指纹/设备/会话 |
| `POST /api/security/network` | admin | local | 是 | 开关网络模式、改监听、轮换证书 |
| `POST /api/security/password` | admin | local | 是 | 改管理员口令（需旧口令） |
| `POST /api/pair/start` | admin | any | 是 | 生成一次性配对码（TTL 5 min） |
| `POST /api/pair/complete` | 无 | network | - | 配对码 + 设备公钥 → 设备 token（限流） |
| `GET /api/devices`、`POST /api/devices/revoke` | admin | any | 是 | 设备管理 |
| ~~`/api/auth`、`/api/credentials`、`?token=`~~ | - | - | - | 410 Gone，指向新流程 |

### 3.6 中继 / 转发 / mesh

- relay 继续 `ssh -L` → 对端回环 listener；对端认证用节点 token（配对时创建）。
- forwards：网络模式下按目标生成**短 TTL ticket**（绑定目标 + 来源 CIDR + 过期），
  不再复用面板 token；默认关闭。
- mesh 发现仍走 Tailscale，但只有**已配对节点**可读/控；未配对一律 403。

## 4. 配置 schema（v2）

```jsonc
{
  "listen": {
    "local": {"host": "127.0.0.1", "port": 8090},
    "network": {
      "enabled": false,
      "mode": "lan",                    // "lan" | "tailnet"
      "bind": "",                        // 空=自动选接口
      "port": 8443,
      "allowed_cidrs": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
                        "100.64.0.0/10", "fd7a:115c:a1e0::/48"]
    }
  },
  "security": {
    "session_ttl_s": 1800,
    "session_max_age_s": 2592000,
    "login_window_s": 300,
    "login_max_failures": 5,
    "lockout_s": 300
  },
  "access": {"local_token_file": ".state/local-token"},
  "peers": {"list": []},                 // 配对后写 id/fingerprint
  "node": {"id": "...", "name": "..."},
  "relay": {...}, "forwards": {...}, "intervals": {...}, "ui": {...},
  "groups": [...], "services": [...]
}
```

迁移：启动时把旧 `listen.host/port` 规范化为 `local`；`host` 非回环时迁移为网络模式并强制 TLS，
在 UI 标红要求确认；旧 `.state/access-tokens.json`、`credentials.json` 不迁移（安全原因），
流程改为重新初始化（setup code + 设口令 + 配对）。

## 5. 代码结构

```
monitor_server.py            入口：解析参数、加载配置、启动 listener（保持文件名兼容 tools）
mozunitor/
  __init__.py                版本
  config.py                  配置加载/规范化/迁移
  security/
    passwords.py             scrypt 口令
    identity.py              节点密钥、TLS 证书、launch token、本地 token、ACL
    sessions.py              服务端会话 + Cookie 签名
    authz.py                 声明式路由表与 scope
    csrf.py                  CSRF/Origin/Host 校验
    ratelimit.py             指数退避/锁定
    audit.py                 security.jsonl
    pairing.py               配对码、设备/节点记录
  net/
    listeners.py             本地/网络 listener、CIDR 白名单、网络类别检查
    tls.py                   证书生成/加载/指纹
    http.py                  请求管线中间件（基于 http.server）
  api/                       路由实现（逐步迁出 monitor_server 的业务函数）
  mesh/                      节点配对与转发
  forwards/                  ticket 与代理
  probe/                     采集（后续迁移）
static/                      登录/设置向导/安全页
mobile/                      配对、多面板、证书钉住、Keystore
```

## 6. 阶段与验收（C 位检查点）

| 阶段 | 内容 | 检查点 | 验收 |
| --- | --- | --- | --- |
| P1 | security 包：口令/会话/authz/限流/审计 + 单测 | 1.0.1 | `python tools\security_selftest.py` 全 PASS；路由表无漏声明 |
| P2 | HTTP 管线接入：loopback 也要会话/本地 token；CSRF/Origin/Host/Content-Type | 1.0.2 | 本轮 CSRF PoC 全失败；旧 `?token=` 410；正常登录可用 |
| P3 | 网络 listener + TLS + setup 向导 + 安全页 | 1.0.3 | 网络模式显式开启；证书指纹/设备/会话可管理；非白名单 403 |
| P4 | 设备配对 + 手机端（多面板/钉证书/Keystore） | 1.0.4 | 手机扫码配对后免密；吊销后 401；旧配置不再可用 |
| P5 | mesh/relay/forwards 改节点 token/ticket | 1.0.5 | 双实例 mesh/relay 通过；未配对节点 403 |
| P6 | 文档、迁移说明、回归、导出公开仓库 | **1.1.0** | 全量安全回归 + Android 全链路 + UX 四视口；exe/APK 构建 |

## 7. 验收矩阵（回归门禁）

- SEC-01：三种来源（loopback/LAN/file://）的 CSRF PoC 必须 401/403/415，命令不得执行。
- SEC-02：`.state` 内无明文口令；icacls 仅当前用户/SYSTEM/Admins；`/api/security/password` 远端需 admin。
- SEC-03：用户名/口令错误统一 401；5 次失败后 429/锁定；read 会话看不到路径/端口。
- SEC-04：HTTPS 下 Cookie 有 `Secure`；`?token=` 不存在；安全头齐全；无版本头。
- SEC-05：非白名单来源 403；Public 网络拒绝开网络模式。
- SEC-06：旧 `?token=`/`/api/auth`/`/api/credentials` 410；无明文 token 文件。
- FUN-01：`cmd /c`、`powershell`、`exe+args` 均真实执行；无判据时 `ok=null`。
- REL-01：APK 默认不指向不可达地址；支持多面板/扫码。
- 既有功能：面板/详情/设置/ops/保活/中继/forwards 不回归。

## 8. 风险与回滚

- 破坏性 API：旧客户端/书签/脚本失效；发版说明必须列出迁移步骤。
- 证书：自签证书在浏览器有一次性提示；手机钉指纹；证书轮换要有重新配对流程。
- 回滚：分支 + 版本 tag；旧 1.0.0 部署不受影响（不自动更新）。
- 依赖：`cryptography` 打入便携 exe（PyInstaller）与 APK 构建链，需在发布流程验证。
