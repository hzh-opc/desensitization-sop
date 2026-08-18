# 信息脱敏上云 SOP —— 一键安装（Windows）
# 用法：在 PowerShell 中执行  .\install.ps1 [参数...]  （参数与 install.py 一致）
# 例：   .\install.ps1                 # 自动检测工具 + 从 GitHub 安装
#        .\install.ps1 --tool claude   # 指定 Claude Code
$ErrorActionPreference = "Stop"

$Dir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$Py = (Get-Command python -ErrorAction SilentlyContinue).Source
if (-not $Py) { $Py = (Get-Command py -ErrorAction SilentlyContinue).Source }
if (-not $Py) {
    Write-Host "[FAIL] 未找到 python / py，请先安装 Python 3.10+ 并将其加入 PATH。" -ForegroundColor Red
    exit 1
}

& $Py (Join-Path $Dir install.py) @args
