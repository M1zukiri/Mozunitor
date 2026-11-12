# ============================================================
# Created: 2026-09-17 20:23:23
# Purpose: Sample local listening TCP ports and per-process resource
#          usage, emit one JSON object on stdout for monitor_server.py.
#          Read-only: never starts, stops, or writes anything.
# 2026-10-12: -CmdNames 里点名的进程额外带一列命令行；-TaskNames 里点名的计划任务带状态。
# ============================================================
param([string]$CmdNames = '', [string]$TaskNames = '')

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

$ports = New-Object System.Collections.ArrayList
$listenPids = @{}
foreach ($c in (Get-NetTCPConnection -State Listen)) {
    $owner = [int]$c.OwningProcess
    $listenPids[$owner] = $true
    [void]$ports.Add([pscustomobject]@{
        port = [int]$c.LocalPort
        addr = [string]$c.LocalAddress
        pid  = $owner
    })
}

$procs = New-Object System.Collections.ArrayList
# 命令行只有 CIM 拿得到（Get-Process 没这一列），而进程名会撞车：M1K 上有六个 python.exe。
# **只查 -CmdNames 点名的那些名字** —— CIM 明显比 Get-Process 慢，整表换掉得不偿失；
# 没人点名时这里一个查询都不发，采集行为与以前完全一致。
$cmdMap = @{}
foreach ($n in ($CmdNames -split ',' | Where-Object { $_ })) {
    $exe = if ($n -like '*.*') { $n } else { "$n.exe" }
    foreach ($c in (Get-CimInstance Win32_Process -Filter "Name='$exe'" -EA SilentlyContinue)) {
        if ($c.CommandLine) { $cmdMap[[int]$c.ProcessId] = [string]$c.CommandLine }
    }
}
foreach ($p in (Get-Process)) {
    # 端口占用者一律保留，即使内存很小（postgres 主进程正是这种情况）；
    # **点名查过命令行的进程也一律保留** —— 那种常驻小脚本（HUST 自动登录只 ping）
    # 常常进不了体积门槛，被滤掉的结果是探针永远报「进程不存在」。
    # 一条语句判完，不用反引号续行 —— 远端那份是同源代码，必须能整段经 SSH 执行。
    $keep = $listenPids.ContainsKey([int]$p.Id) -or $cmdMap.ContainsKey([int]$p.Id) -or ($p.WorkingSet64 -ge 10MB)
    if (-not $keep) { continue }
    $cpu = -1.0
    try { $cpu = [double]$p.TotalProcessorTime.TotalSeconds } catch { }
    $start = ''
    try { $start = $p.StartTime.ToString('o') } catch { }
    $path = ''
    try { $path = [string]$p.Path } catch { }
    [void]$procs.Add([pscustomobject]@{
        pid   = [int]$p.Id
        name  = [string]$p.ProcessName
        mem   = [int]($p.WorkingSet64 / 1MB)
        cpu   = [math]::Round($cpu, 3)
        start = $start
        path  = $path
        cmd   = [string]$cmdMap[[int]$p.Id]
    })
}

# 点名的计划任务：状态与上次结果。**任务状态跨会话可读，而别人会话进程的 CommandLine 读不到**
# —— HUST 自动登录由计划任务拉起、跑在会话 0，面板在会话 1，按命令行判会永远报「不存在」。
$tasks = @()
foreach ($n in ($TaskNames -split ',' | Where-Object { $_ })) {
    $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
    if ($t) {
        $info = Get-ScheduledTaskInfo -TaskName $n -ErrorAction SilentlyContinue
        $lr = $null
        if ($info) { $lr = [int]$info.LastTaskResult }
        $tasks += [pscustomobject]@{ name = [string]$t.TaskName; state = [string]$t.State; last_result = $lr }
    }
}

$payload = [pscustomobject]@{
    time  = (Get-Date).ToString('o')
    cores = [int]$env:NUMBER_OF_PROCESSORS
    ports = $ports
    procs = $procs
    tasks = $tasks
    # 诊断用：点名了哪些进程名、真取到多少条命令行。那一列空了要能一眼看出是哪一头的事
    # （面板没把名字传下来，还是 CIM 没查到）。
    cmd_names  = [string]$CmdNames
    cmd_probed = $cmdMap.Count
}
[Console]::Out.Write(($payload | ConvertTo-Json -Depth 3 -Compress))
