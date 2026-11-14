# 2026-10-12  Mozunitor 自更新 / 重启面板（面板自身那两个写操作的入口）
#
# 用法（两条都由 services.json 的 ops 声明；人手也能直接跑）：
#   powershell -File self-update.ps1                  # 看 MOZU_OP_ID 分派：selfupdate / reload
#   powershell -File self-update.ps1 -Worker          # 真正干活：落盘 + 重启（脱离后由 WMI 调起）
#   powershell -File self-update.ps1 -Reload          # 只重启，不落盘
#
# **为什么必须脱离**：这两件事都要先杀掉面板，而面板正是拉起本脚本的父进程。子进程留在
# 面板的 Job 里，面板一死就把它一起带走（2026-09-17 事故的同一类）。所以入口被调用时立刻
# 用 WMI 起一份独立的自己，原进程马上返回 —— WMI 创建的进程挂在 WmiPrvSE 下。
#
# 分工：入口只负责「下发」并立刻返回（面板的 op 超时是 30 秒）；干活的是 -WorkerMode /
# -ReloadOnly，它把每一步写进 logs\self-update.log —— WMI 进程没有控制台，不落盘就什么也看不见。
#
# **开关名与局部变量名不能撞**：PowerShell 变量名不区分大小写，而 `[switch]` 参数带类型约束 ——
# `$reload = Join-Path ...` 在 `param([switch]$Reload)` 的脚本里会抛
# 「Cannot convert value "System.String" to type "System.Management.Automation.SwitchParameter"」，
# 赋值不生效，变量保持 $true，于是 python 收到「True」当脚本路径。所以这里开关叫
# -WorkerMode / -ReloadOnly，局部变量叫 $updatePy / $reloadPy。
param(
    [switch]$WorkerMode,
    [switch]$ReloadOnly
)

$ErrorActionPreference = 'Continue'
. (Join-Path $PSScriptRoot '_panel-lib.ps1')

$root = Get-MozuRoot
$log = Get-MozuLog -Root $root

if (-not $WorkerMode -and -not $ReloadOnly) {
    # ---- 入口：按 op 名选模式，WMI 起一份脱离的干活进程 ----
    $mode = '-WorkerMode'
    if ($env:MOZU_OP_ID -eq 'reload') { $mode = '-ReloadOnly' }

    $py = Find-MozuPython
    if (-not $py) {
        Out-MozuSections @(@{ kind = 'notes'; items = @(
            @{ tone = 'warn'; text = '找不到可用的 python（试过 $env:MOZU_PYTHON / python / py），未下发。' }) })
        exit 1
    }
    $pid2 = Start-MozuDetached -ScriptPath $PSCommandPath -ExtraArgs $mode -Root $root
    if (-not $pid2) {
        Out-MozuSections @(@{ kind = 'notes'; items = @(
            @{ tone = 'warn'; text = 'WMI 下发失败，未启动（面板自己没有权限起进程？）' }) })
        exit 1
    }
    Write-MozuLog $log "dispatched $mode pid=$pid2 python=$($py.exe) $($py.ver)"
    $what = if ($mode -eq '-ReloadOnly') { '重启面板' } else { '自更新（落盘 + 重启）' }
    Out-MozuSections @(
        @{ kind = 'kv'; title = '已下发'; rows = @(
            @{ label = '动作'; value = $what },
            @{ label = '方式'; value = 'WMI 脱离面板 —— 面板中途死掉也会走完' },
            @{ label = '工作进程'; value = "pid $pid2" },
            @{ label = 'python'; value = "$($py.exe) $($py.ver)" },
            @{ label = '日志'; value = $log }) },
        @{ kind = 'notes'; items = @(
            @{ tone = 'info'; text = '面板会在流程末尾重启，这个页面随后要重新加载。进度看上面的日志文件（详情里的「日志」面板）。' }) }
    )
    exit 0
}

# ---- 干活：log 里记每一步，退出码也记 ----
$tag = if ($ReloadOnly) { 'reload' } else { 'selfupdate' }
Write-MozuLog $log "$tag start (pid=$PID, root=$root)"
$py = Find-MozuPython
if (-not $py) {
    Write-MozuLog $log 'ERROR: 找不到 python，什么也没做'
    exit 1
}

if (-not $ReloadOnly) {
    $updatePy = Join-Path $root 'tools\update.py'
    Write-MozuLog $log "apply: $($py.exe) $updatePy --apply"
    $out = & $py.exe $updatePy --apply 2>&1 | Out-String
    $code = $LASTEXITCODE
    foreach ($l in ($out -split "`r?`n")) { if ($l.Trim()) { Write-MozuLog $log "  apply| $($l.Trim())" } }
    Write-MozuLog $log "apply exit=$code"
    if ($code -ne 0) {
        # 落盘没成功就不重启 —— 重启一个半新半旧的安装没有任何好处，保持现状更好查。
        Write-MozuLog $log 'apply 未成功，跳过重启，保持现状'
        exit $code
    }
}

$reloadPy = Join-Path $root 'tools\reload_panel.py'
Write-MozuLog $log "reload: $($py.exe) $reloadPy"
$out2 = & $py.exe $reloadPy 2>&1 | Out-String
$code2 = $LASTEXITCODE
foreach ($l in ($out2 -split "`r?`n")) { if ($l.Trim()) { Write-MozuLog $log "  reload| $($l.Trim())" } }
Write-MozuLog $log "$tag done (reload exit=$code2)"
exit $code2
