# 2026-10-12  Mozunitor 检查更新（只读）
#
# 把 `tools/update.py --status` 的计划原样呈现出来：目标版本、会改哪些文件、哪些本端文件
# 刻意不动。只读、不落盘、不重启 —— 与 self-update.ps1 是两件事。
#
# 慢（要 fetch 一次镜像仓库），所以配置里标 lazy：点了才跑，别在选中服务时就卡住界面。
$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot '_panel-lib.ps1')

$root = Get-MozuRoot
$py = Find-MozuPython
if (-not $py) {
    Out-MozuSections @(@{ kind = 'notes'; items = @(
        @{ tone = 'warn'; text = '找不到可用的 python（试过 $env:MOZU_PYTHON / python / py）。' }) })
    exit 1
}

$update = Join-Path $root 'tools\update.py'
$out = & $py.exe $update --status 2>&1 | Out-String
$code = $LASTEXITCODE

$notes = @()
if ($code -eq 0) {
    $notes += @{ tone = 'info'; text = '--status 只报告，什么也没改。要真的落盘并重启，用「自更新并重启」。' }
} else {
    $notes += @{ tone = 'warn'; text = "update.py --status 退出码 $code（0=正常，2/3/4/5 的含义见 docs/AGENTS-protocols.md）" }
}

Out-MozuSections @(
    @{ kind = 'kv'; title = '环境'; rows = @(
        @{ label = '本端'; value = $env:MOZU_NODE_ID },
        @{ label = '安装根'; value = $root },
        @{ label = 'python'; value = "$($py.exe) $($py.ver)" }) },
    @{ kind = 'text'; title = '更新计划'; text = $out.Trim() },
    @{ kind = 'notes'; items = $notes }
)
exit 0
