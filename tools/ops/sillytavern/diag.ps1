# 创建时间: 2026-10-09 04:45:00
# 用途: 酒馆的接口连通性自检 —— 逐端点探测并如实报告状态码与耗时。
#       本机酒馆有两个已知的坑（见项目 AGENTS.md）：jQuery AJAX 不带 X-CSRF-Token 时
#       /api/* 会 403，而 SPA 会把启动期注册的全局 AJAX 钩子清掉。这个脚本把"哪个端点
#       通、哪个被拒、各花多久"摊开，用来区分"服务没起来"与"接口被挡了"。
# 只读: 只发 HTTP 请求，不读也不写任何文件。
# 输出: format=sections，故 stdout 必须是 { "sections": [...] }

$ErrorActionPreference = 'SilentlyContinue'
$base = 'http://127.0.0.1:8001'

$rows = @()
foreach ($path in @('/', '/version', '/api/settings/get', '/api/ping')) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $code = -1
    $note = ''
    try {
        $r = Invoke-WebRequest -Uri ($base + $path) -TimeoutSec 8 -UseBasicParsing
        $code = [int]$r.StatusCode
    } catch {
        if ($_.Exception.Response) {
            $code = [int]$_.Exception.Response.StatusCode
            if ($code -eq 401) { $note = '需要认证（服务端 basicAuth）' }
            elseif ($code -eq 403) { $note = '被 CSRF 挡下（缺 X-CSRF-Token）' }
            elseif ($code -eq 404) { $note = '该端点不存在' }
        } else {
            $note = '连不上：' + ($_.Exception.Message -split "`n")[0]
        }
    }
    $sw.Stop()
    $rows += @{ cells = @(
        $path,
        @{ t = "$code"; hot = ($code -ne 200) },
        @{ t = "$([int]$sw.ElapsedMilliseconds) ms" },
        @{ t = $note; dim = [string]::IsNullOrEmpty($note) }
    ) }
}

$sections = @(
    @{ kind = 'table'; title = "接口探测 · $base"; cols = @('端点', '状态码', '耗时', '说明'); rows = $rows },
    @{ kind = 'notes'; title = ''; items = @(
        @{ level = 'info'; text = '401 是服务端 basicAuth（面板自身的探测只打根路径，看不出这一层）；403 才是 CSRF。' }
    ) }
)

@{ sections = $sections } | ConvertTo-Json -Depth 10 -Compress
