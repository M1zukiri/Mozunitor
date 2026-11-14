# 创建时间: 2026-10-09 04:50:00
# 用途: M1zukiri 的显存算术 —— 对每个已加载模型，按 /api/show 的架构参数算 KV/token，
#       与权重相加后判断 12 GB 显存之外要落多少内存。
#       这张表是项目里反复踩的地方（见 AGENTS.md）：KV 只吃显存剩下的部分，
#       其余落内存，而 OLLAMA_MAX_LOADED_MODELS=2 意味着两个模型可能同时驻留。
#       KV/token 必须按架构参数算，不能凭感觉估 —— 所以这个脚本现算，不写死数字。
# 只读: 只调用 Ollama 的 HTTP 接口，不读也不写任何文件、不改任何设置。
# 地址由面板经 MOZU_MODELS_API 下发（取自服务的 models_api），脚本里不留第二份硬编码地址。
# 输出: format=sections

$ErrorActionPreference = 'SilentlyContinue'
$base = $env:MOZU_MODELS_API
$vramGB = 12.0          # RTX 3060

function Get-Info($info, $suffix) {
    $p = $info.PSObject.Properties | Where-Object { $_.Name -like "*$suffix" } | Select-Object -First 1
    if (-not $p) { return $null }
    $v = $p.Value
    if ($v -is [array]) { return $v[0] }     # head_count_kv 可能是逐层的数组
    return $v
}

try {
    $ps = Invoke-RestMethod "$base/api/ps" -TimeoutSec 15
} catch {
    $err = @{ sections = @(@{ kind = 'notes'; title = ''; items = @(
        @{ level = 'warn'; text = "取不到 $base/api/ps：" + ($_.Exception.Message -split "`n")[0] } ) }) }
    $err | ConvertTo-Json -Depth 10 -Compress
    exit 0
}

$rows = @()
foreach ($m in @($ps.models)) {
    $name = $m.name
    $ctx = [int64]$m.context_length
    $weights = [int64]$m.size
    try {
        $show = Invoke-RestMethod "$base/api/show" -Method Post -TimeoutSec 20 `
            -ContentType 'application/json' -Body (@{ name = $name } | ConvertTo-Json -Compress)
        $info = $show.model_info
    } catch { $info = $null }

    $layers = Get-Info $info 'block_count'
    $kvh = Get-Info $info 'head_count_kv'
    $kl = Get-Info $info 'key_length'
    $vl = Get-Info $info 'value_length'

    if ($layers -and $kvh -and $kl -and $vl -and $ctx -gt 0) {
        # q8_0 的 KV cache ≈ 每元素 1 字节；这就是 OLLAMA_KV_CACHE_TYPE 的作用
        $perToken = [double]$layers * [double]$kvh * ([double]$kl + [double]$vl) * 1.0
        $kvBytes = $perToken * $ctx
        $total = $weights + $kvBytes
        $kvTxt = '{0:N1} GB' -f ($kvBytes / 1GB)
        $totTxt = '{0:N1} GB' -f ($total / 1GB)
        $need = [Math]::Max(0, $total - ($vramGB * 1GB))
        $verdict = if ($total -le $vramGB * 1GB) { '全部进显存' } else { '需落内存 {0:N1} GB' -f ($need / 1GB) }
        $rows += @{ cells = @(
            $name,
            @{ t = '{0:N2} MB' -f ($perToken / 1MB) },
            @{ t = $kvTxt },
            @{ t = '{0:N1} GB' -f ($weights / 1GB) },
            @{ t = $totTxt; hot = ($total -gt $vramGB * 1GB) },
            @{ t = $verdict; hot = ($total -gt $vramGB * 1GB) }
        ) }
    } else {
        $rows += @{ cells = @(
            $name, @{ t = '—'; dim = $true }, @{ t = '—'; dim = $true },
            @{ t = '{0:N1} GB' -f ($weights / 1GB) },
            @{ t = '—'; dim = $true },
            @{ t = '架构参数不全，算不出 KV'; dim = $true }
        ) }
    }
}

if ($rows.Count -eq 0) {
    $rows = @(@{ cells = @('（当前没有已加载的模型）', '', '', '', '', '') })
}

$sections = @(
    @{ kind = 'table'; title = '已加载模型的显存算术（显存按 12 GB 计）';
       cols = @('模型', 'KV/token', 'KV 占用', '权重', '权重+KV', '结论'); rows = $rows },
    @{ kind = 'notes'; title = ''; items = @(
        @{ level = 'info'; text = 'KV/token = 层数 × KV heads × (key 长度 + value 长度) × 每元素字节；q8_0 的 KV cache 约 1 字节/元素。' },
        @{ level = 'info'; text = '显存先被权重占掉，KV 只吃剩下的，其余全部落内存。两个模型同时驻留时上表的两行会叠加。' }
    ) }
)

@{ sections = $sections } | ConvertTo-Json -Depth 10 -Compress
