# ============================================================
# Created: 2026-09-17 20:23:23
# Purpose: Sampled on peer through SSH by monitor_server.py.
#          Emits one JSON object with listening ports, process
#          resource usage, and the DSH scheduled-task state.
#          Read-only: never starts, stops, or writes anything.
# 2026-10-12: $MozuCmdNames 里点名的进程额外带一列命令行、$MozuTaskNames 里点名的计划任务
#          带状态。本脚本是整段经 SSH 执行的、没有参数可传，所以这两个变量由调用方前置赋值。
# ============================================================
if (-not $MozuCmdNames) { $MozuCmdNames = '' }
if (-not $MozuTaskNames) { $MozuTaskNames = '' }
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
# 只查 $MozuCmdNames 点名的名字（命令行只有 CIM 拿得到，整表换掉得不偿失）。
$cmdMap = @{}
foreach ($n in ($MozuCmdNames -split ',' | Where-Object { $_ })) {
    $exe = if ($n -like '*.*') { $n } else { "$n.exe" }
    foreach ($c in (Get-CimInstance Win32_Process -Filter "Name='$exe'" -EA SilentlyContinue)) {
        if ($c.CommandLine) { $cmdMap[[int]$c.ProcessId] = [string]$c.CommandLine }
    }
}
foreach ($p in (Get-Process)) {
    # 端口占用者一律保留，即使内存很小；**点名查过命令行的进程也一律保留** —— 名字被配置点过名
    # 就说明有服务在意它，而那种常驻小脚本（HUST 自动登录只 ping）常常进不了体积门槛，
    # 被滤掉的结果是探针永远报「进程不存在」。
    # 判据写成一条语句而不是反引号续行：本脚本是**整段经 SSH 送过去执行的**，续行在传输里
    # 不可靠（2026-10-12 实测：加了一处续行，远端采集直接失败，表现为「远程不可达」）。
    $keep = $listenPids.ContainsKey([int]$p.Id) -or $cmdMap.ContainsKey([int]$p.Id) -or ($p.WorkingSet64 -ge 20MB)
    if (-not $keep) { continue }
    $cpu = -1.0
    try { $cpu = [double]$p.TotalProcessorTime.TotalSeconds } catch { }
    [void]$procs.Add([pscustomobject]@{
        pid  = [int]$p.Id
        name = [string]$p.ProcessName
        mem  = [int]($p.WorkingSet64 / 1MB)
        cpu  = [math]::Round($cpu, 3)
        cmd  = [string]$cmdMap[[int]$p.Id]
    })
}

$task = [pscustomobject]@{ name = 'DeepSeek Harness Web'; state = 'unknown'; lastResult = $null; lastRun = '' }
$t = Get-ScheduledTask -TaskName 'DeepSeek Harness Web' -ErrorAction SilentlyContinue
if ($t) {
    $task.state = [string]$t.State
    $info = Get-ScheduledTaskInfo -TaskName 'DeepSeek Harness Web' -ErrorAction SilentlyContinue
    if ($info) {
        $task.lastResult = $info.LastTaskResult
        if ($info.LastRunTime) { $task.lastRun = $info.LastRunTime.ToString('o') }
    }
}

$models = @()
try {
    $resp = Invoke-WebRequest -Uri 'http://127.0.0.1:11434/api/tags' -UseBasicParsing -TimeoutSec 6
    $models = ($resp.Content | ConvertFrom-Json).models | ForEach-Object { [string]$_.name }
} catch { }

# 点名的计划任务（同 collect_local.ps1）：任务状态跨会话可读，别人会话进程的命令行读不到。
$tasks = @()
foreach ($n in ($MozuTaskNames -split ',' | Where-Object { $_ })) {
    $t = Get-ScheduledTask -TaskName $n -ErrorAction SilentlyContinue
    if ($t) {
        $info = Get-ScheduledTaskInfo -TaskName $n -ErrorAction SilentlyContinue
        $lr = $null
        if ($info) { $lr = [int]$info.LastTaskResult }
        $tasks += [pscustomobject]@{ name = [string]$t.TaskName; state = [string]$t.State; last_result = $lr }
    }
}

$payload = [pscustomobject]@{
    time   = (Get-Date).ToString('o')
    cores  = [int]$env:NUMBER_OF_PROCESSORS
    ports  = $ports
    procs  = $procs
    task   = $task
    tasks  = $tasks
    models = $models
    # 诊断用（同 collect_local.ps1）：点名了哪些名字、真取到多少条命令行。
    cmd_names  = [string]$MozuCmdNames
    cmd_probed = $cmdMap.Count
}
[Console]::Out.Write(($payload | ConvertTo-Json -Depth 3 -Compress))
