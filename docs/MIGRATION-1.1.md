# MIGRATION · 1.0.0 → 1.1.0

1.1.0 是**破坏性**安全重构：旧的访问 token、`/api/auth`、`/api/credentials` 与回环免鉴权全部移除。
升级后需要重新初始化面板并重新配对节点。

## 1. 启动与初始化

1. 启动面板（壳内窗口会用 launch token 自动登录；无桌面机器直接开浏览器）。
2. 在门禁里设置管理员口令（至少 8 位）。本机可开 <http://127.0.0.1:8090/>，远端用网络入口
   `https://<bind>:8443/`（仅第一次初始化，之后只能登录）。
3. 初始化完成后用管理员口令登录即可；`/api/session` 会话 30 分钟滑动、最长 30 天。

## 2. 配置迁移

- 旧配置只有 `listen.host/port`：启动时折算为 `listen.local`。
- `listen.host` 非回环（如 `0.0.0.0`）会被迁移为 **HTTPS 网络入口**：
  - 自动生成自签证书，需要到「设置 → 安全」确认证书指纹；
  - 默认绑定当前 LAN IP、端口 8443、CIDR 白名单；按需改绑定与白名单。
- 旧 `.state/access-tokens.json`、`.state/credentials.json` 不再使用（建议删除，备份后处理）。
- 旧 `?token=` 书签全部失效；请改用登录后的会话。

## 3. 节点互联（mesh / 中继）

- 旧 `username/password` 节点凭据与 HMAC 证明已移除。
- 两台面板互相配对：在 A 生成节点配对码 → 在 B 的「安全 → 节点互联」填 A 的地址与配对码；B 侧会返回自己的 token，双向生效。
- 未配对节点访问 `/api/node` 一律 401；`peers.list` 里旧配置需要重新配对后才能拉到数据。

## 4. 安全入口变化

| 1.0.0 | 1.1.0 |
| --- | --- |
| `GET /?token=...`、`X-Mozunitor-Token` | 410；改用 launch/管理员口令登录 |
| `POST /api/auth` | 410；改用 `POST /api/session/login` |
| `GET/POST /api/credentials` | 410；管理员口令在首次初始化设置，安全页可改 |
| 回环免 token | 回环也要认证 |
| `listen.host=0.0.0.0` 明文 HTTP | 显式开启 HTTPS 网络入口 + CIDR 白名单 |

## 5. 已知限制

- `forwards` 改用短 TTL ticket：先在面板登录并 `POST /api/forward/ticket`（或在入口页按提示）签发，
  再带 `?mozu_ticket=<ticket>` 打开；ticket 60 秒内有效、绑定来源 CIDR，代理会把 ticket 下发成
  HttpOnly Cookie 供子资源复用。`relay`（SSH）与对端网络入口是另外两条通道。
- 自签证书首次访问浏览器有一次性警告；客户端接入时按证书指纹钉住。
