#!/bin/sh
# 信息脱敏上云 SOP —— 一键安装（macOS / Linux）
# 用法： ./install.sh [参数...]   （参数与 install.py 一致）
# 例：   ./install.sh                 # 自动检测工具 + 从 GitHub 安装
#        ./install.sh --tool claude   # 指定 Claude Code
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "[FAIL] 未找到 python3 / python，请先安装 Python 3.8+。"
  exit 1
fi

exec "$PY" "$DIR/install.py" "$@"
