# SPEC · Mozunitor 安全架构（1.1.x）

> 本文件记录已实现的架构与不变量；改动安全相关代码前先读本文件与 `AGENTS.md`。

## 1. 威胁模型

1.0.0 把「回环」当作信任边界，导致三类对手中的两类未被覆盖：

| 对手 | 1.0.0 | 1.1.0 |
| --- | --- | --- |
| 局域网 / Tailnet 设备 | token 认证 | 设备配对 + TLS + 来源 CIDR 白名单 |
| 本机其他进程 / 用户 | 回环免鉴权、凭据明文 | 回环同样认证；口令只存 scrypt；本地脚本用 ACL 收紧的 token |
| 任意网页（CSRF） | 无 Origin/CSRF/Content-Type 校验 | 统一请求管线校验，Cookie 写请求必须带 CSRF 头 |

原则：**零隐式信任**、只处理局域网/同一 Tailnet、不接受公网请求、不做 UPnP/端口转发。

## 2. 三个平面

| 平面 | 入口 | 身份 | 默认 |
| --- | --- | --- | --- |
| 本地管理面 | 回环 listener（HTTP） | launch token（壳注入）/ 管理员口令 / 本地 token | 开 |
| 远程面板面 | 网络 listener（HTTPS） | 设备配对（配对码 → 设备 token）/ 管理员口令 | 关，显式开启 |
| 节点互联面 | 网络 listener | 节点配对（配对码 → 节点 token + 钉证书） | 关，显式配对 |

## 3. 请求管线（所有请求，顺序固定）

1. listener 判定；网络 listener 先查来源 CIDR，非白名单 403。
2. Host 校验：只接受该 listener 的地址集合。
3. 路由匹配：声明式 `ROUTES` 表；未知 404、方法不符 405；1.0.0 旧通道 410。
4. 认证：会话 Cookie / 本地 token / 设备 token / 节点 token / launch token；无隐式回环信任。
5. 授权：`read < write < admin`；本地专属路由另要求 listener=local。
6. CSRF：Cookie 认证的写请求必须带 `X-Mozunitor-CSRF`；Origin 必须同源；`Sec-Fetch-Site: cross-site` 403；Header 认证豁免。
7. Content-Type：JSON 端点必须 `application/json`，请求体上限 64 KB。
8. 限流：登录/配对按 IP 失败计数与锁定。
9. 审计：认证事件与写操作写 `logs/security.jsonl`（不含 token/口令）。
10. 响应头：CSP、nosniff、X-Frame-Options、Referrer-Policy、Cache-Control、Server 不带版本。

## 4. 身份与凭据

- 管理员口令：`hashlib.scrypt`（n=2^14、r=8、p=1、16 B salt），`compare_digest` 校验；首次启动只需设置口令（≥8 位），不引入一次性初始化码。
- 会话：服务端 `SessionStore`，Cookie 为 HMAC 签名；`HttpOnly + SameSite=Strict + Secure(HTTPS) + Path=/`；30 分钟滑动、最长 30 天；可吊销。管理员口令登录签发 admin 会话。
- launch token：壳启动时生成（仅内存），经 URL fragment 交给 WebView；不落盘、不进查询串。
- 本地 token：`.state/local-token`（ACL 收紧），经 `X-Mozunitor-Local-Token` 使用。
- 设备：配对码（5 分钟 TTL、用后即焚）→ 设备 token（`mozd_`），面板只存 SHA256；可列出与吊销。
- 节点：配对码 → 节点 token（`mozn_`），记录里只存入站 token 哈希、出站 token 单独落盘；对端证书指纹钉住。
- 密钥文件：`.state/` 下 token/证书私钥经 `icacls` 收紧；`.state/`、`logs/`、`services.json` 不入库。

## 5. 网络入口与 TLS

- 默认 `127.0.0.1:8090`（HTTP，不出机器）。
- 网络入口显式开启，两种模式：`lan`（绑定具体网卡，默认当前 LAN IP）与 `tailnet`（只绑 `100.64.0.0/10`）；均为 HTTPS，来源按 `allowed_cidrs` 白名单。
- 不使用 `0.0.0.0` 作为网络模式实现；Windows 网络类别为 Public 时拒绝开启。
- 自签证书：ECDSA P-256、SAN 覆盖主机名与绑定 IP，397 天；指纹 SHA256 在安全页展示，客户端接入时钉住。
- 证书/私钥在 `.state/tls/`；改绑定或轮换时重新生成，需重新配对设备/节点。

## 6. API v2 路由（摘要）

| 方法/路径 | scope | listener | 说明 |
| --- | --- | --- | --- |
| `GET /`、`/static/*` | 无 | any | 静态资源 |
| `GET /api/setup/status` | 无 | any | needs_setup / 节点名 / 版本 |
| `POST /api/setup/complete` | 无 | any | 设管理员口令（仅未初始化时；网络入口按白名单来源限流） |
| `POST /api/session/login` | 无 | any | 口令 → 会话（限流） |
| `POST /api/session/launch` | 无 | local | launch token → 会话 |
| `GET/POST /api/session*` | read | any | 会话信息 / 注销 |
| `GET /api/state`、`/api/node`、`/api/history` | read | any | 监控数据 |
| `POST /api/restart`、`/api/stop`、`/api/op` | write | any | 动作，CSRF |
| `GET/POST /api/settings`、`/api/service-settings` | read/write | any | 设置；`commands` 段 admin+local |
| `GET /api/security`、`/api/devices`、`/api/nodes` | admin/read | any | 安全状态、设备、节点 |
| `POST /api/security/network`、`/api/security/password`、`/api/nodes/pair`、`/api/nodes/revoke`、`/api/devices/revoke` | admin | local | 仅本机管理面 |
| `POST /api/pair/start`、`/api/nodes/pair/start` | admin | any | 生成一次性配对码 |
| `POST /api/forward/ticket` | read | any | 短 TTL 转发 ticket（CSRF） |
| `POST /api/pair/complete`、`/api/nodes/pair/complete` | 无 | network | 配对码换 token（限流） |
| 旧 `/api/auth`、`/api/credentials`、`?token=` | — | — | 410 Gone |

## 7. 配置 schema v2

```jsonc
{
  "listen": {
    "local": {"host": "127.0.0.1", "port": 8090},
    "network": {
      "enabled": false,
      "mode": "lan",
      "bind": "",
      "port": 8443,
      "allowed_cidrs": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12", "100.64.0.0/10"]
    }
  },
  "security": {"session_ttl_s": 1800, "session_max_age_s": 2592000,
               "login_window_s": 300, "login_max_failures": 5, "lockout_s": 300},
  "node": {"id": "...", "name": "..."},
  "peers": {"list": []},
  "relay": {"...": "..."}, "forwards": {"...": "..."},
  "intervals": {"...": "..."}, "ui": {"...": "..."},
  "groups": [], "services": []
}
```

启动迁移：只有 `listen.host/port` 的旧配置折算为 `listen.local`；`host` 非回环时迁移为网络模式并强制 HTTPS（启动时提示确认证书指纹）。旧 `.state/access-tokens.json`、`credentials.json` 不迁移，需重新初始化与配对。

## 8. 不变量（回归门禁）

- 回环未认证的 `/api/*` 必须 401；任何 `/api/*` 不经管线不得执行。
- 旧通道 410；`.state` 内无明文口令/访问 token；日志与响应不含 token。
- 网络入口必须显式开启且有 CIDR 白名单；Public 网络拒绝开启；非白名单来源 403。
- 未配对节点/设备 401/403；设备或节点吊销后立即失效。
- 被监控服务默认只读；写只经 `settings` 白名单，确认 + 审计。
- 既有功能（面板/详情/设置/ops/保活/中继）不回归；验收命令见 `AGENTS.md`。

## 9. 验收记录（1.1.x）

- `python tools/security_selftest.py`：147 项全 PASS（口令/会话/路由/CSRF/限流/审计/身份/配对/TLS/网络）。
- `python tools/security_http_selftest.py`：55 项全 PASS（隔离实例 + 真实 HTTPS listener；含双实例节点配对、mesh 拉取、未配对 401、吊销、网络入口初始化）。
- 浏览器冒烟：setup → 面板 → 刷新保持登录；设置页安全分节（网络/证书指纹/会话/设备/节点配对）无 JS 异常。
- 便携 exe：PyInstaller onefile 构建并在隔离目录启动（生成 services.json/.state/logs，回环 8090 正常）。
- forwards：改为短 TTL ticket。`POST /api/forward/ticket`（read + CSRF）签发 60 秒、限次、
  绑定服务与来源 CIDR 的 ticket；转发代理在首个请求核销并下发 HttpOnly Cookie 供子资源复用，
  无 ticket 一律 401；代理只绑网络入口 IP，不用 `0.0.0.0`。unit 147 项、HTTP 55 项全 PASS。
