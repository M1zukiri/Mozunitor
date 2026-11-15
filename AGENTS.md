# AGENTS.md · Mozunitor

<!-- profile
repo: M1zukiri/m1zukiri-profiles-md
modes: operations, engineering
stacks: python
platforms: windows
domains: -
contexts: -
-->

Windows 桌面监控面板：托盘应用 + 本机 HTTP 服务 + 无构建前端；每台机器各跑一份，已配对节点互读状态，没有中心节点。公开仓库 `M1zukiri/Mozunitor`，当前 **1.1.5**（A=1 固定；A/B 只在用户要求升阶段时改，日常功能/修复走 C 位检查点：1.1.5、1.1.6…）。

全局基线见 `~/.dsh/AGENTS.md`（第 0 节 profile 取用协议）。本文件只记本项目硬约束与坑；使用说明见 `README.md`，设计依据与实测见 `docs/SPEC.md`，进度见 `NOTES.md`。

## 架构

- 后端 `monitor_server.py` + `mozunitor/`（`security/` 身份与鉴权、`net/listeners.py` 监听面、`tls.py` 证书），只用标准库；唯一外部依赖 `cryptography`（TLS 与密钥）。
- 入口 `app.py`：`pywebview` + `pystray` + `pillow`，后端同进程。Session 0 / SSH 等无交互桌面场景自动跳过窗口与托盘，只跑后端与对等互联（`has_interactive_desktop()` 的 `restype` 必须显式声明，否则判据静默失效）。
- 前端无构建：`static/app.js` 入口，`static/js/` 按职责拆 ES modules（服务图标在 `icons.js`，可被 `services.json` 的 `icon` 覆盖）；`theme.css` 是 industrial-pixel-ui 主题原样副本，不直接改；皮肤都由 `themes.css` 按 `html[data-theme]` 重映射 token（`themes.js` 管选择与本设备记忆），`style.css` 只写本页布局。
- 部署形态：单文件 exe（PyInstaller onefile）。代码与静态资源在 `_MEIPASS`，可写状态（`services.json`、`.state/`、`logs/`）落 exe 旁边；`ROOT` 是安装目录，`BUNDLE_DIR` 是解包目录，两者不可混用。

## 安全（1.1 起）

- 零隐式信任：回环也认证。所有 `/api/*` 走同一管线：listener 判定 → Host 校验 → 路由匹配 → 认证 → 授权（`read < write < admin`）→ CSRF → Content-Type → 限流 → 审计 → 安全响应头。
- 三套身份彼此独立：本地（launch token / 管理员口令 / `.state/local-token`）、设备（`mozd_`）、节点（`mozn_`）。
- 网络入口必须显式开启：`lan` 或 `tailnet`，绑具体地址 + CIDR 白名单，不用 `0.0.0.0`；网络类别为 Public 时拒绝开启。TLS 自签证书指纹可在安全页查看并被对端/客户端钉住。
- 初始化只设管理员口令（1.1.4 起没有 setup code）；完成后拒绝再次初始化。初始化与登录都按来源地址限流。
- 口令只存 `scrypt` 哈希；token 只存哈希；`.state/`、`logs/`、真实 `services.json` 不入库。旧 `?token=`、`/api/auth`、`/api/credentials` 一律 410，不做兼容层。
- forwards 用短 TTL ticket（60 s、限次、绑服务/目标端口/来源 CIDR）；转发代理只绑网络入口 IP，ticket 核销后下发 HttpOnly Cookie 供子资源复用。

## 配置与只读边界

- `services.json` 是唯一配置入口；仓库只放 `services.example.json`，真实配置不入库。
- 被监控服务默认只读。唯一例外：服务在 `services.json` 里显式声明的 `settings` 白名单参数，经 `/api/service-settings` 写入（写前确认 + `actions.jsonl` 审计）。
- `<LLMDEPLOY>` 的 `rag_server.py` 只经 `ast` 解析取字面量；`<SILLYTAVERN>` 只读白名单标量与连接视图；被监控服务的自启动项与配置文件不读不改。
- `logs` 白名单不得包含会原文回显 token 的日志（如 DSH 的 `web-*.log`、面板自己的 `panel.out/app.out`）。

## ops 与脚本

- 脚本操作声明在 `services.json` 的 `ops` 里，执行体在 `tools/ops/<service>/`；路径越界拒绝，扩展名只允许 `.ps1/.py/.cmd`，单次超时 30 s（上限 300 s），输出上限 256 KiB。
- 参数只经环境变量下发：`MOZU_SCRIPT_PATH`、`MOZU_ROOT`、`MOZU_SERVICE_ID`、`MOZU_SERVICE_NAME`、`MOZU_OP_ID`、`MOZU_NODE_ID`，未知表单字段为 `MOZU_FIELD_<NAME>`；op 声明里的 `env` 原样下发（配置态地址放这里，脚本里不留私有地址）。
- 打包后脚本在 `_MEIPASS`，安装根由 `MOZU_ROOT` 下发：脚本里的 `Get-MozuRoot` 必须先认它。
- 只有 `level: "write"` 的脚本才持重启锁；`format` 必须显式（解析失败如实报错，不静默回退）。
- 脚本里若拉起长驻服务，必须自己在脚本内经 WMI；直接 `Start-Process` 会进面板的 Job，面板一死就被带走（2026-09-17 事故）。

## 进程与启动

- 面板是拉起者：Job 继承、WMI 脱离、先杀守护进程再杀主目标；启动失败如实上报，端口仍被占就再杀一遍。
- 改环境变量对已在运行的父进程无效：启动器要自己显式 set 关键绑定变量，别依赖继承（2026-10-13 实测）。
- 单实例：命名互斥量 + `.state/app-ipc.json` 的 IPC；重复启动只唤起已有窗口。
- 生产部署：本机 `Mozunitor-prod\`（托盘 exe + `start-mozunitor.cmd` + 自启动快捷方式），M1K `D:\Mozunitor-prod\`（计划任务 `Mozunitor` 指向同一启动脚本）。真实 `services.json` 与 `.state` 只存在部署目录。

## 保活与中继

- 保活参数：`KEEPALIVE_DOWN_STREAK=3`、`KEEPALIVE_BACKOFF_S=(60,120,300)`、`KEEPALIVE_MAX_FAILS=5`；「已恢复」的判定必须在「已暂停」之前；状态经 `/api/state` 的 `item["keepalive"]` 暴露，`max_fails` 由后端下发，前端不写死。
- 中继：本机 → `ssh -L` → 对端回环 listener → 服务；远端 listener 只绑 `127.0.0.1`，探针必须经中继（HTTP），不能只看本地 TCP（`ssh -L` 会先接受连接再失败）。
- 节点互联：一次性配对码 → `mozn_` token → 双方证书指纹互钉；`peers.list` 只负责轮询清单，不承担鉴权。

## 构建与发布

- exe：`python tools\make_icon.py --ico temp\mozunitor.ico` 后用 `python -m PyInstaller --noconfirm --clean --onefile --windowed --name Mozunitor --icon "<绝对路径>\temp\mozunitor.ico" --add-data "<绝对路径>\static;static" --add-data "<绝对路径>\tools;tools" --add-data "<绝对路径>\services.example.json;." --exclude-module PyQt5 --exclude-module PyQt6 --exclude-module pygame --exclude-module tkinter --exclude-module matplotlib --exclude-module numpy --exclude-module pandas --exclude-module scipy app.py`。
- 图标母版只有 `mozunitor/branding.py` 的 16×16 `PATTERN`：窗口/托盘 ICO 由它运行时生成到 `.state/`（每次启动重写），favicon `static/icon.svg` 由 `tools/make_icon.py` 同源生成，改图标只改母版再重跑工具。`static/icon.svg` 不要手改。
- `--add-data` 必须用绝对路径：配 `--specpath` 改了 cwd 后相对路径会找不到。排除大模块后体积从 70 MB 降到 28 MB 左右。
- 发布：打 tag `vX.Y.Z` 并建 GitHub Release，资产只含 exe。当前网络下 `github.com:443` 不通，推送用 `ssh://git@ssh.github.com:443/M1zukiri/Mozunitor.git`（密钥 `~/.ssh/id_ed25519_github`）。
- 版本号同步点：`monitor_server.py` 的 `SERVER_VERSION`、`mozunitor/__init__.py` 的 `__version__`、两个 selftest 的横幅。

## 测试与验收

- 提交前必跑：`python tools\security_selftest.py`、`python tools\security_http_selftest.py` 都必须 exit 0；改过 `.ps1` 再跑 `python tools\check_bom.py`。
- 回归用隔离实例：`MOZU_CONFIG` / `MOZU_STATE_DIR` / `MOZU_ACTION_LOG` 指向 `temp/`（已 gitignore），独立端口；不碰真实 `services.json`、不写真实运维日志。
- 前端改动用 Playwright（本机 Edge）截图 1440×900 与 1280×720 对比，并检查无横向溢出。

## 平台坑

- PowerShell 脚本必须 UTF-8 BOM（无 BOM 会被按 ANSI 读，中文静默出错）；PowerShell 变量名不区分大小写，`[switch]` 参数与局部变量撞名会抛错。
- `requirements.txt` 必须带 UTF-8 BOM：旧 pip 按 locale 解码中文注释会崩溃。
- 本机与 M1K 的 SSH 走 BatchMode；远程执行 PowerShell 用 `-EncodedCommand`（base64 UTF-16LE）避免转义问题。
- 2026-11-12 曾 BSOD `0x154`（UNEXPECTED_STORE_EXCEPTION，dump 写入失败）；长跑前记录 uptime 与事件日志，重负载下载不要与浏览器实例并发。

## 文档分工

`README.md` 管使用；`docs/SPEC.md` 管设计依据与实测记录；`docs/MIGRATION-1.1.md` 管 1.0 → 1.1 升级；`NOTES.md` 按日期追加进度与历史；本文件管硬约束与坑。
