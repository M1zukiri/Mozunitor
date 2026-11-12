# NOTES · Mozunitor

## 当前状态（2026-11-13）

- 版本 **1.0.4**（公开基线 1.0.0；安全重构 P4 检查点）。开发分支 `refactor/security`，按
  `docs/SPEC-security-hardening.md` 执行；B 位目标 **1.1.0**。

## 进度记录

### 2026-11-13

- 切换开发基线：本仓库 clone 自 `github.com/M1zukiri/Mozunitor`（main 含 1.0.0 之后的 README 与
  Gradle wrapper 修正），从 `main` 新建分支 `refactor/security`。1.0.0 代码即旧内部 3.5.3 的脱敏快照，
  安全重构工单继续适用，版本体系改为 1.x；旧 3.5 仓库已冻结为存档（tag `v3.5.4-archive`）。
- 1.0.0 基线冒烟：隔离实例（临时配置，端口 8091）`GET /` 200、`GET /api/state` 200，后端启动正常。
- P1（C 位 **1.0.1**）：`mozunitor/security/` —— scrypt 口令、Ed25519 节点身份 + launch token / 本地
  token（含 ACL 收紧）、服务端会话（HMAC Cookie、滑动 TTL、吊销）、声明式路由表（scope / listener /
  CSRF / Content-Type）、Origin / Host / CSRF 校验、登录限流、安全审计（脱敏 JSONL）；
  `tools/security_selftest.py` **79 项全 PASS**。HTTP 管线尚未接入（P2）。
- P2（C 位 **1.0.2**）：HTTP 管线接入 —— 所有 `/api/*`（含回环）统一过 `SecurityState.authorize()`；
  旧 `?token=` / `/api/auth` / `/api/credentials` → 410；新增 `/api/setup/*`、`/api/session*`、
  `/api/security`、`/api/devices`；CSRF / Origin / Host / Content-Type 校验与安全响应头；壳经 URL
  片段注入 launch token。`tools/security_http_selftest.py` **21 项全 PASS**；Playwright 冒烟：
  setup → 面板 → 刷新会话保持、无 JS 异常。
- P3（C 位 **1.0.3**）：网络 listener + 自签 TLS —— `mozunitor/tls.py`（ECDSA P-256、
  SAN 覆盖主机名与绑定 IP、ACL 收紧、指纹）、`mozunitor/net/listeners.py`（模式/绑定/CIDR 校验、
  Windows 网络类别判定、Public 拒绝开启、`NetworkServer`）；`SecurityState` 增加网络来源校验、
  网络端口与 Host/Origin 适配；`/api/security` 返回网络状态与证书指纹，`POST /api/security/network`
  实现开关/改绑定/CIDR/轮换证书并写回 `listen.network`；设置页新增「安全」分节（网络开关、模式、
  绑定、CIDR、指纹、活动会话、改口令）；管理员口令登录签发 admin 会话。自检：unit **108 项**、
  HTTP **35 项** 全 PASS；Playwright：设置页安全分节可见、开启 HTTPS 后指纹展示、非白名单来源 403、
  配置写回验证通过。
- P4（C 位 **1.0.4**）：设备配对 —— `mozunitor/security/pairing.py`（一次性配对码 5 分钟 TTL、
  设备记录只存 token 哈希、吊销）；`SecurityState` 接受 `Authorization: Bearer` /
  `X-Mozunitor-Device-Token` 设备 token（read/write），配对与吊销写审计；`/api/devices`、
  `/api/pair/start`、`/api/pair/complete`、`/api/devices/revoke` 上线；设置页「安全」分节可生成
  配对码、查看与吊销设备。自检：unit **128 项**、HTTP **42 项** 全 PASS；Playwright：配对区可见、
  配对码生成展示、无 JS 异常。Android 端（扫码/钉证书/Keystore/多面板）与 P5、P6 未做。
