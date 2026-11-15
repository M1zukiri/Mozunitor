# Mozunitor

一个本地优先的 Windows 常驻服务监控面板：托盘常驻，浏览器/内嵌窗口查看本机与已配对对端节点的
服务状态，卡片式操作，支持分级告警、服务参数调整与 SSH 中继。


## 特性

- **两台机器的统一面板**：每台机器各跑一份，通过 `/api/node` 对等拉取，没有中心节点。
- **机器 → 级别 → 服务**：`core` 异常红色横幅并自动展开，`normal` 只给组头计数，`optional`
  不统计在线、默认折叠。
- **真操作**：重启 / 终止 / 打开服务入口 / 查看服务自己声明的面板；动作写入
  `logs/actions.jsonl`。
- **分级保活**：掉线服务自动拉起，连续失败退避并暂停，不刷屏。
- **服务参数**：只对 `services.json` 里声明的 `settings` 白名单参数开放写入（酒馆连接、RAG 温度、
  Ollama 加载默认值等），写前确认、写后审计。
- **Mozunitor 中继**：本机 → SSH → 对端 Mozunitor → 对端服务，远端监听只绑回环；
  面板 API 也走同一条 SSH 通道。
- **零隐式信任（1.1.0）**：回环也要认证；设备/节点用一次性配对码换 token，token 只存哈希；
  网络入口必须显式开启（HTTPS + 自签证书 + CIDR 白名单），设备/节点按证书指纹钉住。
  旧 `?token=`、`/api/auth`、`/api/credentials` 已移除，升级步骤见 [迁移说明](docs/MIGRATION-1.1.md)。

## 下载

在 [Releases](https://github.com/M1zukiri/Mozunitor/releases) 下载：

| 产物 | 说明 |
| --- | --- |
| `Mozunitor-1.1.4-portable.exe` | Windows 便携版，双击运行，不写注册表、不需要安装 |

> 便携版首次运行时会在 exe 旁边生成 `services.json`（来自 `services.example.json`）以及
> `.state/`、`logs/`；首次打开 <http://127.0.0.1:8090/> 设置管理员口令即可完成初始化
> （壳内窗口会自动登录）。请先按需编辑 `services.json` 里的服务与探针。
>
> 面板默认只监听 `127.0.0.1:8090`。需要局域网/Tailnet 访问时，在「设置 → 安全」开启 HTTPS 网络入口：
> 绑定具体网卡与端口（默认 8443）、设置 CIDR 白名单。

## 从源码运行

```powershell
python -m pip install -r requirements.txt
copy services.example.json services.json   # 首次
python app.py
```

浏览器打开 <http://127.0.0.1:8090/>；托盘图标在任务栏溢出区。

也可以只跑后端（无托盘/窗口，适合服务器或调试）：

```powershell
python monitor_server.py
```

## 配置

`services.json` 是唯一需要改的配置。最小结构：

```json
{
  "listen": {
    "local": {"host": "127.0.0.1", "port": 8090},
    "network": {"enabled": false, "mode": "lan", "bind": "", "port": 8443,
                "allowed_cidrs": ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
                                  "100.64.0.0/10"]}
  },
  "node": {"id": "local-node", "name": "本机"},
  "groups": [{"id": "local", "title": "本机服务"}],
  "services": [
    {
      "id": "my-service",
      "name": "我的服务",
      "group": "local",
      "tier": "normal",
      "probe": {"kind": "tcp", "host": "127.0.0.1", "port": 8080}
    }
  ]
}
```

- `probe.kind`：`tcp` / `http` / `process` / `task`。
- `tier`：`core` / `normal` / `optional`。
- `restart` / `stop`：声明如何重启或终止；不配 `stop` 就不显示终止按钮。
- `settings`：显式声明可写参数，详见 `services.example.json`。
- `listen.local` 是本机回环入口（仅 HTTP）；`listen.network` 是 HTTPS 网络入口，默认关闭，
  也可以在设置页开停与改白名单。
- 对端节点先在两端「节点互联」互相配对，再在 `peers.list` 里配置地址；把服务从对端暴露到本机
  用 `relay` 段（只绑回环，SSH 入口）。

## 构建

**便携版 exe**（PyInstaller，需在 Windows 上执行）：

```powershell
python -m pip install pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --windowed --name Mozunitor `
  --add-data "static;static" --add-data "tools;tools" `
  --add-data "services.example.json;." app.py
```

完整命令（含体积优化用的 `--exclude-module`）与发布流程见 `AGENTS.md`。

## 安全说明

- 默认只监听回环；回环也要认证（launch/管理员口令/本地 token）。
- 网络访问必须显式开启 HTTPS 网络入口，来源受 CIDR 白名单限制，Public 网络拒绝开启。
- 管理员口令只存 scrypt 哈希；设备/节点 token 只存 SHA256；自签证书指纹可在安全页查看。
- 首次启动只需设置管理员口令（1.1.4 起没有 setup code）。
- 被监控服务默认只读；唯一例外是 `settings` 声明的白名单参数，写前确认并审计。
- 中继远端 listener 只绑 `127.0.0.1`，SSH 是唯一入口。
- 不要把 `.state/`、`logs/`、`services.json`（如含真实地址/凭据）提交到仓库。

## 目录

```
app.py                    托盘 + 内嵌窗口入口
monitor_server.py         后端：采集、HTTP API、访问控制（仅标准库）
static/                   前端（无构建，ES modules）
mozunitor/                安全/TLS/网络 listener 等子模块
tools/                    采集脚本、ops 脚本与安全自检
docs/SPEC.md              安全架构与不变量
docs/MIGRATION-1.1.md     1.0.0 → 1.1.0 迁移说明
services.example.json     配置模板
```

## 许可证

MIT，见 [LICENSE](LICENSE)。
