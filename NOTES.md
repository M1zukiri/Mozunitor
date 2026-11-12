# NOTES · Mozunitor

## 当前状态（2026-11-13）

- 版本 **1.1.1**（B 位：安全重构完成 + forwards ticket）。开发基线为公开 1.0.0。开发分支 `refactor/security`，按
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
