# NOTES · Mozunitor

## 当前状态（2026-11-13）

- 版本 **1.0.2**（公开基线 1.0.0；安全重构 P2 检查点）。开发分支 `refactor/security`，按
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
  setup → 面板 → 刷新会话保持、无 JS 异常。网络 listener / TLS / 安全页仍待 P3。
