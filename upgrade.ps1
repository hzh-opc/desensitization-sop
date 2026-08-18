# 信息脱敏上云 SOP —— 手动升级（Windows）
# 用法：在 PowerShell 中执行  .\upgrade.ps1 [参数...]  （参数与 upgrade.py 一致）
# 例：   .\upgrade.ps1                 # 检查更新，有则 下载→校验→应用
#        .\upgrade.ps1 --check         # 仅检查是否有更新
#        .\upgrade.ps1 --dry-run       # 下载+校验但不替换
$ErrorActionPreference = "Stop"

$Dir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$Py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $Py) { $Py = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $Py) {
    Write-Host "[FAIL] 未找到 python / py，请先安装 Python 3.10+ 并将其加入 PATH。" -ForegroundColor Red
    exit 1
}

& $Py (Join-Path $Dir upgrade.py) @args
