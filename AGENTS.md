# AGENTS.md · Mozunitor

<!-- profile
repo: M1zukiri/m1zukiri-profiles-md
modes: operations, engineering
stacks: python, flutter
platforms: windows
domains: -
contexts: -
-->

本地优先的 Windows 常驻服务监控面板 + Android 启动器。后端单文件、只用标准库；前端无构建；每台机器各跑一份，对等互联，没有中心节点。本仓库是公开产品树，开发基线 **1.0.0**。

全局基线见 `~/.dsh/AGENTS.md`（第 0 节是 profile 取用协议）。本文件只记本项目特有的硬约束与坑；本轮工单见 `docs/SPEC-security-hardening.md`，进度见 `NOTES.md`。

## 版本规则

- 版本 `A.B.C`：当前 **A=1 固定**；B 位在完成整个计划 / 新增功能 / 修 BUG 后升（安全重构完成 → **1.1.0**）；C 位是计划内的检查点（1.0.1、1.0.2…），由执行者自行标记，不单独收尾。
- `git tag vX.Y.Z` 是唯一权威；`monitor_server.py` 的 `server_version`、`app.py`、`mobile/pubspec.yaml` 同步更新。
- 提交用英文 conventional commits，一条对应一个可验收的交付结果。

## 技术约束

- 后端只用 Python 标准库；安全重构经明确许可引入 `cryptography`，仅用于 TLS 与密钥。
- 前端不加构建：`static/app.js` 是入口，`static/js/` 按职责拆 ES modules；`theme.css` 是 industrial-pixel-ui 主题副本，换皮只改它，`style.css` 只写本页布局。唯一破例是应用层 `app.py`（`pywebview` + `pystray` + `pillow`）。
- 探测固定走直连 opener，不走系统代理（否则代理状态混进探测结果）。
- `services.json` 是唯一配置入口；仓库里只放 `services.example.json`，真实配置不入库。

## 安全目标（执行中）

零隐式信任：**回环不再免鉴权**。所有请求经同一管线：listener 判定 → Host 校验 → 路由匹配 → 认证 → 授权（`read < write < admin`）→ CSRF → Content-Type → 限流 → 审计 → 安全响应头。

- 本地管理面、远程面板面（HTTPS + 设备配对）、节点互联面（节点 token）三套身份彼此独立。
- 网络模式显式开启，绑定具体网卡/`100.x` 地址 + CIDR 白名单，不用 `0.0.0.0`；当前网络为 Public 时拒绝开启。
- 口令只存 `scrypt` 哈希；token/会话密钥落盘时收紧 ACL；不写日志、不进查询串。
- 旧 `?token=`、`/api/auth`、`/api/credentials` 一律 410，不做兼容层。

## 只读边界

被监控服务可以读，任何情况下不写：

- `<LLMDEPLOY>`：`rag_server.py` 仅经 `ast` 解析取字面量常量。
- `<SILLYTAVERN>`：`config.yaml` 白名单标量、`settings.json` 连接视图、`data\access.log` 尾部。
- 被监控服务的自启动项与配置文件：不读不改。
- 不复制、不落盘、不硬编码密钥；含密钥的启动脚本一律调用其既有启动器。
- 日志白名单不得包含会原文回显 token 的日志文件。

例外仅限 `services.json` 里显式声明的 `settings` 白名单参数，经 `/api/service-settings` 写入（写前确认 + `actions.jsonl` 审计）；不写任何被监控服务的源码、启动脚本或自启动项。

## 架构要点

- 各端平权：每端只描述自己，用 `/api/node` 对等拉取。`/api/node` 是本节点自视角原子快照，`/api/state` 是聚合视图。
- 信息层级是**机器 → 级别（core / normal / optional）→ 服务**；`tier` 在 `services.json` 显式声明。
- 前端每 3 秒 `innerHTML` 重建 `#board`；进行中的操作记模块级 `INFLIGHT`，由每次重绘重新施加，不要只改 DOM。
- 保活参数：`DOWN_STREAK=3`、`BACKOFF=(60,120,300)`、`MAX_FAILS=5`；**「已恢复」的判定必须在「已暂停」之前**。
- 中继：本机 → `ssh -L` → 对端回环 listener → 服务；远端 listener 只绑 `127.0.0.1`，探针必须经中继（HTTP），不能只看本地 TCP。

## 平台实例

- `start-monitor-hidden.vbs` 必须保持 GBK/ANSI（路径含中文，存 UTF-8 会被 WSH 按 ANSI 误读）。
- `requirements.txt` 必须带 UTF-8 BOM（旧 pip 按 locale 解码，中文注释会崩）。
- 项目路径含非 ASCII 会让 Android 构建失败，`android.overridePathCheck=true` 只绕过配置阶段。
- 2026-11-12 曾出现 BSOD `0x154` 非预期重启（`volmgr` 161，dump 写入失败）；长跑前记录 uptime 与事件日志，重负载下载不要与浏览器实例并发。

## 测试与验收

- 每阶段先跑自测再提交：`python tools\security_selftest.py`（P1 起）、`python tools\security_http_selftest.py`（P2 起）必须 exit 0。
- 回归用隔离实例：`MOZU_CONFIG` / `MOZU_STATE_DIR` 指向 `temp/`，独立端口；不碰真实 `services.json`、不写真实运维日志。
- 重构完成前不重启生产面板实例。

## 文档分工

`README.md` 管使用；`docs/SPEC-security-hardening.md` 管本轮工单与设计依据；`NOTES.md` 管进度与待决；本文件管约束。

## 版本

当前 **1.0.1**（安全重构执行中；P1 检查点，B 位目标 1.1.0）。
