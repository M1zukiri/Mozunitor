# NOTES · Mozunitor

## 当前状态（2026-11-13）

- 版本 **1.0.0**（公开发布基线）。开发分支 `refactor/security`，按 `docs/SPEC-security-hardening.md` 执行
  安全重构；C 位检查点从 1.0.1 起，B 位目标 **1.1.0**。
- 旧的内部 3.5 仓库已于 2026-11-13 冻结为存档（tag `v3.5.4-archive`），不再修改；本仓库从公开 1.0.0
  重新开始。

## 进度记录

### 2026-11-13

- 切换开发基线：本仓库 clone 自 `github.com/M1zukiri/Mozunitor`（main 含 1.0.0 之后的 README 与
  Gradle wrapper 修正），从 `main` 新建分支 `refactor/security`。1.0.0 代码即旧内部 3.5.3 的脱敏快照，
  安全重构工单继续适用，版本体系改为 1.x。
- 1.0.0 基线冒烟：隔离实例（临时配置，端口 8091）`GET /` 200、`GET /api/state` 200，后端启动正常。
- 待办：P1 security 包重做（检查点 1.0.1）。
