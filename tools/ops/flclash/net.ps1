# 创建时间: 2026-10-09 04:47:00
# 用途: FlClash 的网络自检 —— 系统代理开关与绕过名单、相关进程监听的端口。
#       面板自身的探测固定走直连、不走系统代理（这是有意的：否则"FlClash 挂没挂"会混进
#       别的服务的探测结果）。所以要看代理到底开没开、绕过了哪些地址，只能单独摊开。
# 只读: 读注册表的 Internet Settings 与端口表，不改任何设置。
# 输出: format=sections

$ErrorActionPreference = 'SilentlyContinue'

$reg = Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings'
$on = ($reg.ProxyEnable -eq 1)
$proxyRows = @(
    @{ cells = @('系统代理', @{ t = $(if ($on) { '已开启' } else { '未开启' }); hot = (-not $on) },
                 @{ t = "$($reg.ProxyEnable)"; dim = $true }) },
    @{ cells = @('代理地址', @{ t = "$($reg.ProxyServer)" }) },
    @{ cells = @('绕过名单', @{ t = "$($reg.ProxyOverride)"; dim = $true }) }
)

# 哪些进程像代理：名字里带 clash / mihomo 的都算上（FlClash 的实际进程名可能变）
$procs = Get-Process | Where-Object { $_.ProcessName -match 'clash|mihomo' }
$portRows = @()
foreach ($p in $procs) {
    $conns = Get-NetTCPConnection -State Listen -OwningProcess $p.Id -ErrorAction SilentlyContinue
    if (-not $conns) {
        $portRows += @{ cells = @($p.ProcessName, @{ t = '（没有监听端口）'; dim = $true }, @{ t = "$($p.Id)" }) }
        continue
    }
    foreach ($c in $conns) {
        $portRows += @{ cells = @(
            $p.ProcessName,
            @{ t = "$($c.LocalAddress):$($c.LocalPort)" },
            @{ t = "$($p.Id)" }
        ) }
    }
}
if ($portRows.Count -eq 0) {
    $portRows = @(@{ cells = @('（未发现代理进程）', @{ t = ''; dim = $true }, @{ t = '' }) })
}

$sections = @(
    @{ kind = 'table'; title = '系统代理'; cols = @('项', '值', '原始'); rows = $proxyRows },
    @{ kind = 'table'; title = '代理进程监听的端口'; cols = @('进程', '监听', 'PID'); rows = $portRows },
    @{ kind = 'notes'; title = ''; items = @(
        @{ level = 'info'; text = '面板的探测固定直连、不走系统代理；这里看到的是系统层面的设置，两者不一致是正常的。' }
    ) }
)

@{ sections = $sections } | ConvertTo-Json -Depth 10 -Compress
