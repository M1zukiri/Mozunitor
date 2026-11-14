# Mozunitor 面板自身那几个 op 的共用函数（被同一目录下的脚本 dot-source）。
#
# 为什么这些动作必须先脱离：自更新与重启面板都要**先杀掉面板**，而面板正是拉起本脚本的
# 父进程。子进程留在面板的 Job 里，面板一死就把它带走（2026-09-17 事故的同一类：DSH 退出时
# 面板、酒馆、隧道、RAG 四个一起消失）。所以入口脚本一律先用 WMI 起一份独立的自己，
# 原进程立刻返回 —— WMI 创建的进程挂在 WmiPrvSE 下，面板怎么死都不影响它。
# 这是 AGENTS.md「脚本里若要拉起长驻服务，必须自己在脚本内经 WMI」的又一次应用。

function Get-MozuRoot {
    # 打包进 exe 时脚本在临时解包目录，安装根由面板经 MOZU_ROOT 下发
    if ($env:MOZU_ROOT) { return $env:MOZU_ROOT }
    # tools/ops/panel/ -> 往上三层就是安装根
    return (Resolve-Path (Join-Path $PSScriptRoot '..\..\..')).Path
}

function Get-MozuLog {
    param([string]$Root, [string]$Name = 'self-update.log')
    $dir = Join-Path $Root 'logs'
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    return (Join-Path $dir $Name)
}

function Write-MozuLog {
    param([string]$Path, [string]$Message)
    $line = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    Add-Content -Path $Path -Value $line -Encoding UTF8
}

function Find-MozuPython {
    # 更新与重启工具只用标准库，任何 python 3 都能跑；但这个脚本自己没有 python，
    # 只能从 PATH 找，找不到就如实报错（不猜路径）。
    foreach ($cand in @($env:MOZU_PYTHON, 'python', 'py')) {
        if (-not $cand) { continue }
        try {
            $v = (& $cand -V 2>&1 | Out-String).Trim()
            if ($LASTEXITCODE -eq 0 -and $v) { return @{ exe = $cand; ver = $v } }
        } catch { }
    }
    return $null
}

function Start-MozuDetached {
    # 经 WMI 起一份脱离的 powershell 脚本，返回 pid（失败返回 0）。
    param([string]$ScriptPath, [string]$ExtraArgs, [string]$Root)

    $cmd = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + $ScriptPath + '"'
    if ($ExtraArgs) { $cmd += ' ' + $ExtraArgs }
    # ShowWindow=0 是 STARTUPINFO 级别的隐藏：不加会在桌面上闪一个控制台窗口。
    $si = (Get-CimInstance Win32_ProcessStartup -ErrorAction SilentlyContinue |
           ForEach-Object { $_.ShowWindow = 0; $_ })
    try {
        if ($si) {
            $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
                CommandLine = $cmd; CurrentDirectory = $Root; ProcessStartupInformation = $si }
        } else {
            $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
                CommandLine = $cmd; CurrentDirectory = $Root }
        }
        return [int]$r.ProcessId
    } catch {
        return 0
    }
}

function Out-MozuSections {
    # format: sections 要求 stdout 恰好是一段 JSON。解析失败时后端会如实报错，
    # 所以这里不做任何兜底拼接。
    param($Sections)
    $json = [pscustomobject]@{ sections = @($Sections) } | ConvertTo-Json -Depth 8 -Compress
    Write-Output $json
}
