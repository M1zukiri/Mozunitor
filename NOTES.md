# NOTES · Mozunitor

## 当前状态（2026-11-13）

- 版本 **1.1.3**（B 位：安全重构 + ops 工具链 + 生产切换修复 + 无桌面远端初始化）。开发基线为公开 1.0.0。开发分支 `refactor/security`，按
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
  配对码生成展示、无 JS 异常。
- P5（C 位 **1.0.5**）：节点互联 —— `mozunitor/security/nodes.py`（节点配对记录、入站 token
  哈希、出站 token、钉证书指纹的 HTTP(S) 客户端）；`SecurityState` 接受节点 token（via=node、
  write 权限），`/api/nodes*` 与配对接口上线；mesh 拉取/转发改走节点 token + 指纹钉住，未配对
  一律 401；设置页「安全」分节可配对节点/生成节点配对码/解除；节点令牌替换掉已失效的用户名+HMAC
  通道。自检：unit **139 项**、HTTP **50 项** 全 PASS（含双实例配对后 mesh 拉取、未配对 401）。
  forwards 短 TTL ticket 仍待补；Android 客户端与 P6 未做。
- P4 客户端（C 位 **1.0.6**）：Android 端改为「配对码 → 设备 token」——`mobile/lib/main.dart`
  用 `dart:io` 的 `badCertificateCallback` 按 SHA256 指纹钉住自签证书，token 进
  secure storage（Keystore 不可用时回退应用私有存储并提示）；设置页改为面板地址 + 证书指纹 +
  配对码；清单数据优先用 Bearer token，失效时退回 `/api/session/login` 换会话（应用内 WebView
  需要 Cookie）。`dart analyze` 无问题。
- 构建阻塞：仓库路径含非 ASCII 时 AOT 阶段 `gen_snapshot` 读路径变乱码直接失败（AGENTS 记载的
  已知坑，`android.overridePathCheck` 只绕过配置阶段）。把 `mobile/` 复制到纯 ASCII 临时目录后
  AOT 能过，但本机 gradle `assembleRelease`/`assembleDebug` 长时间停滞（持续低 CPU、无产物）；
  APK 构建与真机安装验证挪到 P6，换纯 ASCII 工作路径或干净构建环境再跑。

### 2026-11-13 · P6（B 位 **1.1.0** 完成）

- 版本升到 **1.1.0**（B 位）：`monitor_server`/`mozunitor.__version__`/手机端 pubspec 同步，
  新增 `docs/SPEC.md`（架构与不变量）、`docs/MIGRATION-1.1.md`、工单归档
  `docs/archive/SPEC-security-hardening.md`，README 更新为新认证模型。
- 构建与验证：便携 exe（PyInstaller onefile，约 67 MB）在隔离目录启动通过（生成
  services.json/.state/logs，回环 8090 `needs_setup=true`）；Android debug APK 真机验证通过
  （配对 → 设备 token → 面板数据；吊销后 401）。release APK 需在纯 ASCII 路径构建，见下方已知限制。
- 已知限制：APK release 构建依赖纯 ASCII 工作路径与干净 gradle 环境。

### 2026-11-13 · 1.1.1（forwards ticket 收尾）

- `forwards` 改为短 TTL ticket：`POST /api/forward/ticket` 签发（60 秒、限次、绑定服务与来源
  CIDR），代理只绑网络入口 IP；首个请求核销后把 ticket 下发为 HttpOnly Cookie，子资源复用；
  无 ticket 401。运行时开启网络入口也会拉起转发代理（按端口幂等）。
- 自检：unit **147 项**、HTTP **55 项** 全 PASS（新增转发 ticket 生命周期与真实代理访问）。

**1.1.1 发布产物**（纯 ASCII 路径重建）：
- `Mozunitor-1.1.1-portable.exe` 28,139,772 B，
  sha256 `15bd713e1b2fe84f043193264945b20bd2f2184a15dba7fb826a647985116f5c`
  （exe 体积因排除未用的 PyQt5/pygame/tkinter 等模块从 70 MB 降到 28 MB；隔离目录启动验证
  `version: Mozunitor/1.1.1`）。
- `Mozunitor-1.1.1.apk` 51,393,858 B，
  sha256 `9067caf0dc26530f14f512ac3a963b08e5a5856a685d695bd8460ce6c8af846a`
  （versionName=1.1.1，真机安装通过）。
- 产物在 `temp/release-1.1.1/`；GitHub Release 上传仍需仓库 token，留给用户完成。

### 2026-11-13 · M1K ↔ 本机节点互联实测（1.1.1）

- 部署方式：M1K 用其 Windows Python 3.11（已装 cryptography）+ 同版本源码到
  `D:\Mozunitor-1.1-test`，由 WMI 拉起的 `start-test.cmd` 保持进程不被 SSH 会话回收；
  本机用公开树源码 + 临时 state（`temp/mesh`）。M1K 旧面板仍在 `0.0.0.0:8090`，未动。
- 测试端口：本机 local 8092 / tailnet `100.85.213.22:8443`；M1K local 8091 / tailnet
  `100.79.202.6:8444`，均 `allowed_cidrs: 100.64.0.0/10`。
- 节点配对成功（一次性配对码 → 节点 token；TLS 自签证书指纹钉住），双向 mesh 拉取验证：
  本机 `/api/state` 看到 M1K 在线、M1K `/api/state` 看到本机在线，双方 `/api/nodes` 均含对端。
- 未改防火墙与自启动；8444/8091 只是测试端口。远程 GUI（托盘/窗口）在这条路径上未验证，
  本次只跑后端。

### 2026-11-13 · 1.1.0 首次构建（历史记录）
- 发布产物（1.1.0，重建于纯 ASCII 路径）：
  - `Mozunitor-1.1.0-portable.exe` 70,670,860 B，
    sha256 `d39d044c4428d91fa285a62ceffbf9f7f1478794b1cfeeed8e80c61feb0aee67`
    （隔离目录启动验证：version `Mozunitor/1.1.0`，回环 8090 `needs_setup=true`）。
  - `Mozunitor-1.1.0.apk` 51,393,862 B，
    sha256 `c9ffd7449364d7d877b356d2b631a99c556a0dd4dc62afa5fcc6fbf5e41a008f`
    （versionName=1.1.0，真机安装启动通过）。
  - 产物在 `temp/release-1.1.0/`（不在版本库内）；GitHub Release 上传需要仓库凭据，
    本机未配置 token，留给用户在网页/`gh` 完成。
- 构建注意：exe 直接用 PyInstaller 默认路径即可；APK release 必须纯 ASCII 工作路径，
  先 `flutter pub get` 一次，之后用 `--no-pub` 避免反复联网解析。
### 2026-11-14 · 1.1.x 公开树补回 ops 工具链（exe 实测）

- `app.py` 启动取端口改用 `monitor_server.LOCAL_PORT`：旧写法只认 `listen.port`，而设置页
  保存网络配置后 `listen` 变成 `{local, network}`，exe 会因此静默退出（窗口化无控制台）。
- 从存档树移植到公开树：`tools/ops/`（7 个脚本）、`tools/update.py`、
  `tools/reload_panel.py`、`tools/check_bom.py`。脱敏与适配：
  - `m1k-bonsai/status.ps1` 不再写死地址，改读 `MOZU_BONSAI_BASE`；`services.json` 的 op
    声明可带 `env`，由 `run_script_op` 下发给脚本。
  - `_panel-lib.ps1` 的 `Get-MozuRoot` 优先 `MOZU_ROOT`（打包后脚本在临时解包目录）。
  - `update.py` 更新源改为公开仓库 URL，版本正则兼容 `SERVER_VERSION` 写法；
    `reload_panel.py` 读 `listen.local.port`，就绪判据改 `GET /`。
- 实测（源码实例 8096 + 打包 exe 各一轮）：`/api/state` 正常下发 5 个服务的 ops；
  `flclash net`、`sillytavern diag`、`m1k-ollama vram`、`m1k-bonsai status` 均返回 sections，
  连不上时如实报错；`panel status` 走通 `update.py --status`（本机代理关闭时正确报远端不可达）。
- 已知限制：exe 安装目录没有 `tools/update.py` 与 `tools/reload_panel.py`，打包版
  `panel status` 会如实报找不到脚本；exe 下的「自更新/重载」需要单独设计 —— 单文件 exe
  应下载 Release 资产，而不是同步源码文件。
- `tools/check_ops.py` 未移植（依赖旧前端夹具与 Edge/Playwright，与新前端不匹配）；
  `check_bom.py` 已可用，7 个 ops 脚本 BOM 全 OK。安全自测仍全 PASS（147 / 55）。
### 2026-11-14 · 1.1.x 生产首启演练（exe，8090/8443）

- 正式目录 `Mozunitor-prod`（exe + 真实 21 服务配置），配置显式走 tailnet 入口：
  local `127.0.0.1:8090`、network `100.85.213.22:8443`、CIDR `100.64.0.0/10`；
  转发 8102–8105 绑定 tailnet 地址。演练时暂时清空 peers、关闭 relay、去掉 keepalive，
  避免触发 M1K 侧服务拉起。
- 实测：本地/HTTPS 均 200；未登录 `/api/state` 401；8000 段外的转发端口无 ticket 401；
  `POST /api/forward/ticket` 签票后带 `?mozu_ticket=` 可代理到 gemini（返回模型列表）。
  21 服务、4 组、tier 统计与真实运维配置一致；`/api/state` 里 7 个脚本 op 全部在列。
- 演练中发现并修复：本机 WLAN 属「公用网络」，旧 `listen.host=0.0.0.0` 迁移会挑到
  10.71.158.223（Public）→ `ensure_allowed` 拒绝开网络入口，但旧代码仍把网络配置报成
  已启用、且提前开了转发代理端口。修复：迁移时优先选非 Public 地址（LAN 不可用退到
  tailnet）；启动失败时真正关闭网络配置，并改为在网络入口起好之后才开转发代理。
  154/55 两类安全自测仍全 PASS。
- 首启初始化已完成（管理员口令由用户在窗口内设置）；证书指纹
  `BE:8A:0F:53:F7:14:8D:58:01:2F:31:0E:50:FC:7A:2D:40:6B:DF:15:21:26:57:70:59:A2:F7:CF:BE:82:00:F9`。
- 待办：重建 1.1.2 exe（含 app.py / 迁移 / ops 修复）、恢复 relay 与 keepalive、
  按 1.1 节点配对重新接入 M1K、配自启动与旧面板退役。
### 2026-11-15 · 本机转正式生产 + M1K 预演实例

- 本机生产实例 `Mozunitor-prod`：新 exe（含 app.py / 迁移 / ops 修复）+ 真实配置，
  local `127.0.0.1:8090`、network `100.85.213.22:8443`、转发 8102–8105；
  管理员口令已由用户设置，证书指纹
  `BE:8A:0F:53:F7:14:8D:58:01:2F:31:0E:50:FC:7A:2D:40:6B:DF:15:21:26:57:70:59:A2:F7:CF:BE:82:00:F9`。
- 启动项：开始菜单启动快捷方式 `Mozunitor.lnk` 已从存档树 `start-monitor-hidden.vbs`
  改指 `Mozunitor-prod\start-mozunitor.cmd`。旧计划任务 `Mozunitor-Backup` 仍指向存档树。
- relay 与 keepalive 已恢复：5 条中继（11434/11435/8000/18090/19387）全部建立隧道并纳入保活；
  `m1k-bonsai`、`m1k-hust` 也在保活列表。上游服务没起时探测如实显示 down。
- M1K 预演实例：exe 与配置已上传 `D:\Mozunitor-prod`（旧面板 `D:\Mozunitor` 未动），
  暂用 local 8092 / tailnet `100.79.202.6:8444`，13 个服务加载正常，
  证书指纹 `9D:2F:42:03:E7:E1:14:70:B6:34:84:5F:1D:29:08:6D:03:3B:42:B7:81:CC:74:21:55:0D:23:BB:E5:10:4A:C9`，
  初始化口令待用户在浏览器完成。
- 下一步：M1K 完成初始化 → 双向节点配对 → 停旧面板、换到 8090/8443、恢复 relay 监听、
  配自启动；再重建 1.1.2 发布（APK 待手机恢复后补）。
### 2026-11-15 · 1.1.2：节点指纹互钉 + 双机生产切换

- 版本 1.1.2（B 位）：节点配对时双方都记录对端证书指纹 —— 此前只有发起方记录，
  接收方记录是空的，等于少一重校验。
- 本机生产实例换成 1.1.2 exe；M1K 由旧源码面板切到 1.1.2 exe：
  - 旧面板进程已停；计划任务 `Mozunitor` 改为 `cmd.exe /c "D:\Mozunitor-prod\start-mozunitor.cmd"`。
  - 新配置：local `127.0.0.1:8090`、network tailnet `100.79.202.6:8443`，
    relay listeners 21434/21435/28000/29387（127.0.0.1），保活 `hust`。
- 双向节点配对成功并互钉指纹：本机记录 M1K `9D:2F:42:03:…:10:4A:C9`，M1K 记录本机
  `BE:8A:0F:53:…:00:F9`；双向 `/api/state` 对端 online=true，M1K 13 个服务、
  本机 26 项（含 5 条中继）正常。
- M1K 首启初始化待用户在浏览器完成（setup code `M1KSETUP`）；本机已完成。
- 发布产物 `Mozunitor-1.1.2-portable.exe` 28,189,559 B，
  sha256 `422009f6870cdaf5c41f99825f62944fb2be4dc7455c0e3c37c4b9a936330bae`。
- 待办：APK 1.1.2（手机端 ticket + 真机验证）、M1K 初始化口令、旧目录与备份任务收尾。
### 2026-11-15 · 1.1.3：无桌面机器允许从网络入口完成初始化

- 问题：`/api/setup/status` 与 `/api/setup/complete` 原来限定 loopback，M1K 这类无桌面
  机器的浏览器只能走 tailnet 网络入口 → 初始化状态读不到、登录报「尚未完成初始化」，
  用户卡在登录页无法完成首启。
- 处理：初始化流程允许网络入口（`authz` 里 listener 由 local 改 any），
  `complete_setup` 按来源地址限流（与登录同机制），网络入口下发的会话记为 network
  且 Cookie 带 Secure；初始化完成后重复调用仍返回 409。
- 自测同步更新：core 全 PASS、http 全 PASS（新增「网络初始化状态可读 / 完成后拒绝再次初始化」）。
- 1.1.2 发布资产不含此修复，留给 1.1.3 一起发（APK 仍待手机恢复）。

**1.1.3 发布产物**（2026-11-15）：
- `Mozunitor-1.1.3-portable.exe` 28,189,892 B，
  sha256 `9d197cf95b45c07fab49ad359f1b1db3dfcf04743d2d4ad01296857d8e3e7504`；
  本机与 M1K 生产实例均已换成该版本。
- Release: https://github.com/M1zukiri/Mozunitor/releases/tag/v1.1.3（仅 exe，APK 待手机恢复）。
