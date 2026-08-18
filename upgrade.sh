#!/bin/sh
# 信息脱敏上云 SOP —— 手动升级（macOS / Linux）
# 用法： ./upgrade.sh [参数...]   （参数与 upgrade.py 一致）
# 例：   ./upgrade.sh                 # 检查更新，有则 下载→校验→应用
#        ./upgrade.sh --check         # 仅检查是否有更新
#        ./upgrade.sh --dry-run       # 下载+校验但不替换
set -e

DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "[FAIL] 未找到 python3 / python，请先安装 Python 3.10+。"
  exit 1
fi

exec "$PY" "$DIR/upgrade.py" "$@"
