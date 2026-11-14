# 创建时间: 2026-10-12 13:10:00
# 用途: Ternary Bonsai 2 27B 的运行状态 —— 模型是否驻留显存、冷启动与卸载计数、空闲倒计时。
#       这个服务是按需加载的：卡片绿色只说明监督进程在，模型到底有没有占显存要看这张表。
# 只读: 只调用监督进程自己的诊断端点。该端点不触发加载、也不刷新活动时间，
#       所以面板轮询它不会让模型无法空闲卸载（/health 会，不能拿来当探针）。
# 输出: format=sections

$ErrorActionPreference = 'SilentlyContinue'
# 监督进程地址由服务的 op 声明经 MOZU_BONSAI_BASE 下发；缺省按本机/中继上的地址。
$base = if ($env:MOZU_BONSAI_BASE) { $env:MOZU_BONSAI_BASE.TrimEnd('/') } else { 'http://127.0.0.1:8081' }

try {
    $st = Invoke-RestMethod "$base/supervisor/status" -TimeoutSec 10
} catch {
    $err = @{ sections = @(@{ kind = 'notes'; title = ''; items = @(
        @{ level = 'warn'; text = "取不到 $base/supervisor/status：" + ($_.Exception.Message -split "`n")[0] } ) }) }
    $err | ConvertTo-Json -Depth 10 -Compress
    exit 0
}

$loaded = [bool]$st.modelLoaded
$idle = [int]$st.idleSeconds
$limit = [int]$st.idleUnloadSeconds

$rows = @(
    @{ cells = @('模型是否驻留显存',
                 @{ t = $(if ($loaded) { '是' } else { '否' }); hot = $loaded },
                 $(if ($loaded) { 'llama-server 跑在 18080，占约 11.9 GiB' } else { '监督进程在，收到请求才加载' })) },
    @{ cells = @('正在冷启动', $(if ($st.loading) { '是' } else { '否' }), '冷启动约 5 秒（mmap 5.5 GiB 权重）') },
    @{ cells = @('进行中的请求', @{ t = "$($st.inFlight)" }, '有请求在飞时绝不卸载，避免生成中途丢掉 KV cache') },
    @{ cells = @('空闲时间', @{ t = "$idle s" }, "超过 $limit 秒且无进行中请求就卸载模型并释放显存") },
    @{ cells = @('累计请求 / 冷启动 / 卸载', @{ t = "$($st.requests) / $($st.boots) / $($st.unloads)" }, '') },
    @{ cells = @('上下文 / KV 类型', @{ t = "$($st.ctx) / $($st.kvType)" }, '') },
    @{ cells = @('监听 / 上游端口', @{ t = "$($st.listenPort) / $($st.upstreamPort)" }, '') }
)

$sections = @(
    @{ kind = 'table'; title = 'Bonsai 2 27B 运行状态'; cols = @('项', '值', '说明'); rows = $rows },
    @{ kind = 'notes'; title = ''; items = @(
        @{ level = 'info'; text = ('模型文件：' + $st.model) },
        @{ level = 'info'; text = '模型未驻留时首次请求要等约 5 秒冷启动；空闲卸载会丢掉 KV cache，长对话重新 prefill 需要时间。' }
    ) }
)

@{ sections = $sections } | ConvertTo-Json -Depth 10 -Compress
