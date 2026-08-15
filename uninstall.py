#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
信息脱敏上云 SOP —— 卸载脚本
===================================================================
跨平台 (Windows / macOS / Linux)，兼容 WorkBuddy / OpenClaw / Claude Code / Codex。

功能：
  1. 自动检测当前 AI 工具，定位其 skills 目录与记忆/指令文件；
  2. 卸载技能：删除 skills 目录下的 desensitization-sop 文件夹；
  3. 从记忆/指令文件中移除“任务执行前通用敏感信息检测闸门”常驻规则；
  4. 卸载前可自动备份（--backup-dir），默认 dry-run 预览、需 --yes 确认后才真正删除。

安全设计：
  - 默认只打印“将要删除什么”（dry-run），不实际删除任何东西；
  - 仅删除技能自身文件夹，绝不递归删除系统/用户父目录；
  - 删除前先备份（除非 --no-backup），删除后再次校验；
  - 幂等：技能目录已不存在 / 规则已不存在时，安全跳过；
  - 不触碰原始敏感数据（仅操作技能与记忆配置）。

用法：
  python3 uninstall.py                       # 自动检测工具，dry-run 预览
  python3 uninstall.py --yes                 # 确认后真正卸载（含备份）
  python3 uninstall.py --tool claude --yes   # 指定工具
  python3 uninstall.py --skills-dir /p --memory-file /p --yes   # 精确指定目标
  python3 uninstall.py --keep-memory         # 不处理记忆文件中的常驻规则
  python3 uninstall.py --no-backup --yes     # 不备份直接删除

退出码：0 = 全部通过（或已无需卸载）；非 0 = 存在失败项（详见末尾汇总）。
"""

import argparse
import os
import re
import shutil
import sys
from pathlib import Path

# --------------------------------------------------------------------------- #
# 常量配置
SKILL_NAME = "desensitization-sop"

# 各 AI 工具：技能目录 + 记忆/指令文件（用于移除“常驻规则”）
# 注：Codex / OpenClaw 的记忆文件路径为业界常见约定的最佳实践，
#     具体以对应工具最新版为准；如不符可用 --memory-file 覆盖。
TOOL_CONFIG = {
    "workbuddy": {
        "label": "WorkBuddy",
        "skills_dir": "~/.workbuddy/skills",
        "memory_file": "~/.workbuddy/MEMORY.md",
    },
    "claude": {
        "label": "Claude Code",
        "skills_dir": "~/.claude/skills",
        "memory_file": "~/.claude/CLAUDE.md",
    },
    "codex": {
        "label": "OpenAI Codex",
        "skills_dir": "~/.codex/skills",
        "memory_file": "~/.codex/codex.md",
    },
    "openclaw": {
        "label": "OpenClaw",
        "skills_dir": "~/.openclaw/skills",
        "memory_file": "~/.openclaw/AGENTS.md",
    },
}

# 常驻规则移除标记：用子串匹配（覆盖安装器写入的“## 标题块”与
# 手工维护的“- **子弹**”两种形态），稳健、不依赖精确字符串。
RULE_MARKER = "任务执行前通用敏感信息检测闸门"

# 备份时忽略的项（避免拷贝巨型 venv / 缓存 / 仓库元数据）
COPY_IGNORE = {".venv", "__pycache__", ".git", "node_modules"}


# --------------------------------------------------------------------------- #
# 辅助函数
def expand(p):
    return Path(os.path.expanduser(str(p)))


def log(msg, level="INFO"):
    icon = {
        "INFO": "·",
        "OK": "✅",
        "WARN": "⚠️ ",
        "FAIL": "❌",
        "DRY": "🔍",
    }.get(level, "·")
    print("  %s %s" % (icon, msg))


def banner(msg):
    print("\n" + "=" * 64)
    print(msg)
    print("=" * 64)


def detect_tool():
    """按常见环境变量/可执行文件猜测当前工具（仅用于默认定位，可用 --tool 覆盖）。"""
    env = os.environ
    if env.get("WORKBUDDY") or env.get("WORKBUDDY_HOME") or Path.home().joinpath(
            ".workbuddy").exists():
        return "workbuddy"
    if env.get("CLAUDECODE") or Path.home().joinpath(".claude").exists():
        return "claude"
    if Path.home().joinpath(".codex").exists():
        return "codex"
    if Path.home().joinpath(".openclaw").exists():
        return "openclaw"
    return "workbuddy"


def copy_ignore(dir_, names):
    return {n for n in names if n in COPY_IGNORE}


def backup_skill(skill_dir: Path, backup_dir: Path):
    """把技能目录备份到 backup_dir/SKILL_NAME（忽略 venv/缓存）。返回目标路径或 None。"""
    if not skill_dir.exists():
        return None
    dest = backup_dir / SKILL_NAME
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(skill_dir, dest, ignore=copy_ignore)
    return dest


def remove_rule(memory_file: Path, skip=False):
    """从记忆文件中移除常驻规则块（幂等）。返回 (ok, detail)。"""
    if skip:
        return True, "通过 --keep-memory"
    memory_file = expand(memory_file)
    try:
        if not memory_file.exists():
            return True, "记忆文件不存在，跳过"
        content = memory_file.read_text(encoding="utf-8")
        if RULE_MARKER not in content:
            return True, "常驻规则不存在，跳过（幂等）"
        lines = content.split("\n")
        out = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if RULE_MARKER in line:
                # 删除该标记行，并吃掉其后续“续行”（段落正文，非新单元）
                i += 1
                while i < len(lines):
                    nxt = lines[i]
                    if nxt.strip() == "":
                        break
                    if nxt.startswith("#") or nxt.startswith("- ") or nxt.startswith(">"):
                        break
                    i += 1
                continue
            out.append(line)
            i += 1
        new_content = "\n".join(out)
        # 收敛多余空行，避免残留大段空白
        new_content = re.sub(r"\n{3,}", "\n\n", new_content).strip() + "\n"
        memory_file.write_text(new_content, encoding="utf-8")
        return True, "已移除常驻规则：%s" % memory_file
    except Exception as e:  # noqa: BLE001
        return False, "移除失败：%s" % e


# --------------------------------------------------------------------------- #
# 主流程
def main():
    ap = argparse.ArgumentParser(
        description="卸载 desensitization-sop 技能（跨平台，安全优先）")
    ap.add_argument("--tool", choices=list(TOOL_CONFIG.keys()), default=None,
                    help="指定 AI 工具（默认自动检测）")
    ap.add_argument("--skills-dir", default=None,
                    help="覆盖技能目录（默认取工具的 skills 目录）")
    ap.add_argument("--memory-file", default=None,
                    help="覆盖记忆/指令文件路径（默认取工具的记忆文件）")
    ap.add_argument("--backup-dir", default=None,
                    help="卸载前备份技能到此目录（默认 <skills_dir>/../.desen_uninstall_backup）")
    ap.add_argument("--yes", "-y", action="store_true",
                    help="确认执行真正的删除（默认仅 dry-run 预览）")
    ap.add_argument("--dry-run", action="store_true",
                    help="仅预览将要执行的操作，不实际删除（默认行为）")
    ap.add_argument("--keep-memory", action="store_true",
                    help="不处理记忆文件中的常驻规则")
    ap.add_argument("--no-backup", action="store_true",
                    help="卸载前不备份技能目录")
    args = ap.parse_args()

    # 解析目标位置
    tool = args.tool or detect_tool()
    cfg = TOOL_CONFIG.get(tool, TOOL_CONFIG["workbuddy"])
    skills_dir = expand(args.skills_dir) if args.skills_dir else expand(cfg["skills_dir"])
    memory_file = expand(args.memory_file) if args.memory_file else expand(cfg["memory_file"])
    skill_dir = skills_dir / SKILL_NAME

    banner("信息脱敏上云 SOP · 卸载（目标工具：%s）" % cfg["label"])
    log("技能目录：%s" % skill_dir)
    log("记忆文件：%s" % memory_file)

    doing = args.yes and not args.dry_run
    if not doing:
        banner("🔍 DRY-RUN 预览（不删除任何文件；加 --yes 真正执行）")
        if skill_dir.exists():
            n = sum(1 for _ in skill_dir.rglob("*"))
            log("将删除技能目录：%s（含 %d 项）" % (skill_dir, n), "DRY")
        else:
            log("技能目录不存在，无需删除：%s" % skill_dir, "DRY")
        if not args.keep_memory:
            if memory_file.exists() and RULE_MARKER in memory_file.read_text(encoding="utf-8", errors="ignore"):
                log("将从记忆文件移除常驻规则块：%s" % memory_file, "DRY")
            else:
                log("记忆文件中无常驻规则，无需处理", "DRY")
        log("备份目录（默认，除非 --no-backup）：%s" %
            (args.backup_dir or str((skills_dir.parent / ".desen_uninstall_backup"))), "DRY")
        print("\n提示：以上仅为预览。确认无误后运行：")
        print("  python3 uninstall.py%s --yes" %
              ("" if args.tool else " --tool %s" % tool))
        return 0

    # ---- 正式执行 ----
    ok_all = True

    # 1) 备份（先于删除）
    if not args.no_backup and skill_dir.exists():
        backup_dir = expand(args.backup_dir) if args.backup_dir \
            else (skills_dir.parent / ".desen_uninstall_backup")
        banner("步骤 1 / 3 · 卸载前备份")
        dest = backup_skill(skill_dir, backup_dir)
        if dest:
            log("已备份到：%s" % dest, "OK")
        else:
            log("技能目录不存在，跳过备份", "WARN")
    else:
        if args.no_backup:
            log("已指定 --no-backup，跳过备份", "WARN")

    # 2) 删除技能目录
    banner("步骤 2 / 3 · 删除技能目录")
    if skill_dir.exists():
        try:
            shutil.rmtree(skill_dir)
            if not skill_dir.exists():
                log("已删除：%s" % skill_dir, "OK")
            else:
                log("删除后目录仍存在：%s" % skill_dir, "FAIL")
                ok_all = False
        except Exception as e:  # noqa: BLE001
            log("删除失败：%s" % e, "FAIL")
            ok_all = False
    else:
        log("技能目录已不存在，无需删除：%s" % skill_dir, "OK")

    # 3) 移除记忆中的常驻规则
    banner("步骤 3 / 3 · 移除常驻规则")
    ok, detail = remove_rule(memory_file, skip=args.keep_memory)
    log("常驻规则：%s" % detail, "OK" if ok else "FAIL")
    if not ok:
        ok_all = False

    # 校验
    banner("校验")
    if not skill_dir.exists():
        log("技能目录已干净移除", "OK")
    else:
        log("技能目录仍存在", "FAIL")
        ok_all = False
    if not args.keep_memory:
        if memory_file.exists():
            leftover = RULE_MARKER in memory_file.read_text(encoding="utf-8", errors="ignore")
            log("常驻规则已移除" if not leftover else "常驻规则仍残留",
                "OK" if not leftover else "FAIL")
            if leftover:
                ok_all = False
        else:
            log("记忆文件不存在（规则自然不存在）", "OK")

    banner("结果")
    if ok_all:
        print("✅ 卸载完成，技能已干净移除。")
        return 0
    print("❌ 卸载存在未决项，请检查上方 [FAIL]。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
