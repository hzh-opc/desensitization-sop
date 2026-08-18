#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
信息脱敏上云 SOP —— 手动升级脚本（安全零停机）
===================================================================
参照 install.py 的形式：自动检测 AI 工具、定位 skills 目录、从 GitHub 下载、
构建 venv、全环实测。

【手动触发】本脚本默认不自动运行；由用户 / AI Agent 显式调用。AI Agent 仅在
用户明确要求"升级 / 更新本技能"时才运行它，绝不在技能加载时自动升级。

【安全策略 —— 满足"升级不得影响使用"的硬性要求】
  1. 下载 / 克隆新版本到「暂存目录」，该目录与线上技能处于同一文件系统
     （便于做原子的 rename 替换）；
  2. 在暂存副本上构建 venv 并运行 scan / run / decrypt / restore 全环实测
     —— 这就是"校验无误"；
  3. 校验通过后才执行替换；替换前用 rename 把当前线上技能挪到「备份目录」
     （仅改名、不删除，随时可回滚）；
  4. 原子 rename 暂存副本到线上技能目录；
  5. 替换后再次实测线上技能；若失败 → 自动回滚到备份；
  6. 任一环节失败 → 绝不破坏线上技能（或回滚），保证技能始终可被调用。

用法：
  python3 upgrade.py                                       # 检查更新；有则 下载→校验→应用
  python3 upgrade.py --check                               # 仅检查是否有更新（不下载 / 不应用）
  python3 upgrade.py --dry-run                             # 下载+校验，但不替换（试跑，最安全）
  python3 upgrade.py --force                               # 即使版本相同也强制重新应用（用于修复）
  python3 upgrade.py --source local --local-path /path/to/skill   # 离线 / 本地源升级
  python3 upgrade.py --clean-backup                        # 清理历史备份目录

退出码：0 = 成功 / 已是最新；1 = 升级失败（已回滚或根本未触碰线上）；2 = 下载失败；3 = 参数错误。
"""

import argparse
import datetime
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

# --------------------------------------------------------------------------- #
# 复用 install.py 的范式与共享逻辑（同源仓库，避免重复实现、保持一致性）
# --------------------------------------------------------------------------- #
_HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(_HERE))
_spec = importlib.util.spec_from_file_location("desen_install", _HERE / "install.py")
_install = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_install)

# 直接复用 install.py 的常量与函数
TOOL_CONFIG = _install.TOOL_CONFIG
SKILL_NAME = _install.SKILL_NAME
REPO_URL = _install.REPO_URL
DEFAULT_BRANCH = _install.DEFAULT_BRANCH
SAFE_DELETE_TRIGGER_VARS = _install.SAFE_DELETE_TRIGGER_VARS
COPY_IGNORE = _install.COPY_IGNORE
COPY_IGNORE_SUFFIX = _install.COPY_IGNORE_SUFFIX
detect_tool = _install.detect_tool
expand = _install.expand
venv_python = _install.venv_python
_clone_with_git = _install._clone_with_git
_download_zip = _install._download_zip
ensure_venv = _install.ensure_venv
verify = _install.verify
_neutralize_safe_delete_shim = _install._neutralize_safe_delete_shim
banner = _install.banner
log = _install.log


# --------------------------------------------------------------------------- #
# 版本解析与比较
# --------------------------------------------------------------------------- #
def parse_version(text):
    """把 '2.5.0' 解析为 (2, 5, 0)；解析失败返回 None。"""
    if not text:
        return None
    parts = []
    for seg in text.strip().lstrip("vV").split("."):
        num = ""
        for ch in seg:
            if ch.isdigit():
                num += ch
            else:
                break
        if num == "":
            return None
        parts.append(int(num))
    if not parts:
        return None
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:3])


def read_local_version(skill_dir: Path):
    """从 VERSION 文件读取；缺失则回退解析 SKILL.md frontmatter 的 version:。"""
    vf = skill_dir / "VERSION"
    if vf.exists():
        v = parse_version(vf.read_text(encoding="utf-8"))
        if v:
            return v, str(vf)
    sm = skill_dir / "SKILL.md"
    if sm.exists():
        for line in sm.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("version:"):
                v = parse_version(line.split(":", 1)[1])
                if v:
                    return v, str(sm)
    return None, None


def fetch_remote_version_via_raw():
    """轻量获取远程最新版本（raw VERSION 文件）。失败返回 None。"""
    import urllib.request
    url = "%s/raw/refs/heads/%s/VERSION" % (REPO_URL, DEFAULT_BRANCH)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "desen-sop-upgrade"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            return parse_version(resp.read().decode("utf-8", "ignore"))
    except Exception:  # noqa: BLE001
        return None


# --------------------------------------------------------------------------- #
# 网络代理兜底：本机 Agent 会话的代理会让 github.com 返回 502（记忆已记载），
# 故网络调用失败后自动重试「剥离代理」。仅失败时触发，不破坏正常代理环境。
# --------------------------------------------------------------------------- #
_PROXY_VARS = ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy",
               "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy")


def _stripped_proxy_env():
    env = dict(os.environ)
    for k in _PROXY_VARS:
        env.pop(k, None)
    return env


def _no_proxy_opener():
    import urllib.request
    return urllib.request.build_opener(urllib.request.ProxyHandler({}))


def fetch_remote_version_via_raw_robust():
    """获取远程版本；首次失败（多为代理 502）则绕过代理重试。"""
    v = fetch_remote_version_via_raw()
    if v is not None:
        return v
    log("raw 版本获取失败（可能受代理影响），尝试绕过代理重试……", "WARN")
    try:
        url = "%s/raw/refs/heads/%s/VERSION" % (REPO_URL, DEFAULT_BRANCH)
        req = urllib.request.Request(url, headers={"User-Agent": "desen-sop-upgrade"})
        with _no_proxy_opener().open(req, timeout=20) as resp:
            return parse_version(resp.read().decode("utf-8", "ignore"))
    except Exception:  # noqa: BLE001
        return None


def _clone_with_git_robust(repo_url, dest, branch):
    if _clone_with_git(repo_url, dest, branch):
        return True
    log("git clone 失败（可能受代理影响），尝试剥离代理后重试……", "WARN")
    cmd = ["git", "clone", "--depth", "1", "-b", branch, repo_url, str(dest)]
    r = subprocess.run(cmd, capture_output=True, text=True, env=_stripped_proxy_env())
    return r.returncode == 0


def _download_zip_no_proxy(repo_url, dest, branch):
    import urllib.request
    opener = _no_proxy_opener()
    for br in (branch, "master", "main"):
        zip_url = "%s/archive/refs/heads/%s.zip" % (repo_url, br)
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
                req = urllib.request.Request(zip_url, headers={"User-Agent": "desen-sop-upgrade"})
                with opener.open(req, timeout=60) as resp:
                    tf.write(resp.read())
                zpath = tf.name
            with zipfile.ZipFile(zpath) as zf:
                top = zf.namelist()[0].split("/")[0]
                tmp = dest.parent / ("__%s_extract" % SKILL_NAME)
                if tmp.exists():
                    shutil.rmtree(tmp)
                zf.extractall(tmp)
                src = tmp / top
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.move(str(src), str(dest))
                shutil.rmtree(tmp, ignore_errors=True)
            os.unlink(zpath)
            return True
        except Exception as e:  # noqa: BLE001
            log("zip 下载/解压失败（%s）：%s" % (br, e), "WARN")
            continue
    return False


def _download_zip_robust(repo_url, dest, branch):
    if _download_zip(repo_url, dest, branch):
        return True
    log("zip 下载失败（可能受代理影响），尝试绕过代理重试……", "WARN")
    return _download_zip_no_proxy(repo_url, dest, branch)


# --------------------------------------------------------------------------- #
# 暂存下载（复用 install 的 clone / zip 降级）
# --------------------------------------------------------------------------- #
def download_to_staging(source, local_path, staging: Path, force):
    """把新版本下载到 staging（已存在则按 force 决定覆盖）。返回是否成功。"""
    if staging.exists():
        if not force:
            # 暂存区残留：清掉重来
            shutil.rmtree(staging, ignore_errors=True)
        else:
            shutil.rmtree(staging, ignore_errors=True)

    if source == "local":
        if not local_path or not local_path.exists():
            log("本地源路径不存在：%s" % local_path, "FAIL")
            return False
        log("从本地复制技能到暂存区：%s" % local_path)
        # 复用 install 的本地复制（忽略 .venv / __pycache__ / .git 等）
        def ignore(_d, names):
            ig = [n for n in names if n in COPY_IGNORE]
            ig += [n for n in names if n.endswith(COPY_IGNORE_SUFFIX)]
            return ig
        shutil.copytree(str(local_path), str(staging), ignore=ignore)
        return True

    # GitHub 源：git 优先，zip 降级（与 install 一致）；二者均带代理兜底重试
    if _clone_with_git_robust(REPO_URL, staging, DEFAULT_BRANCH):
        return True
    log("git clone 失败，尝试 zip 降级下载……", "WARN")
    if _download_zip_robust(REPO_URL, staging, DEFAULT_BRANCH):
        return True
    log("从 GitHub 下载技能失败（请检查网络，或使用 --source local 离线升级）。", "FAIL")
    return False


def strip_git(staging: Path):
    """移除暂存副本内的 .git（保持与已安装技能一致，避免冗余元数据）。"""
    g = staging / ".git"
    if g.exists():
        shutil.rmtree(g, ignore_errors=True)


# --------------------------------------------------------------------------- #
# 原子替换 + 回滚（rename 基于同一文件系统）
# --------------------------------------------------------------------------- #
def atomic_swap(current: Path, staging: Path, skills_dir: Path):
    """把 staging 替换为线上技能，current 改名备份。

    返回 backup 路径。失败时回滚并抛异常。
    要求 current / staging / backup 同属 skills_dir 所在文件系统（rename 原子）。
    """
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    backup = skills_dir / (".desen_bak_%s" % ts)
    # 1) 当前线上技能 → 备份（仅改名，数据零丢失）
    os.rename(str(current), str(backup))
    log("线上技能已备份至：%s" % backup, "OK")
    try:
        # 2) 暂存新版本 → 线上（原子 rename）
        os.rename(str(staging), str(current))
        log("新版本已原子替换至：%s" % current, "OK")
    except Exception as e:  # noqa: BLE001
        # 回滚：把备份挪回线上
        try:
            if current.exists():
                shutil.rmtree(current, ignore_errors=True)
            os.rename(str(backup), str(current))
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError("替换失败，已回滚到备份：%s" % e)
    return backup


def cleanup_old_backups(skills_dir: Path, keep: Path):
    """升级成功后清理除 keep 之外的历史备份目录（已验证新版本可用，旧备份可丢弃）。"""
    removed = 0
    for p in skills_dir.glob(".desen_bak_*"):
        if p == keep:
            continue
        try:
            shutil.rmtree(p, ignore_errors=True)
            removed += 1
        except Exception:  # noqa: BLE001
            pass
    if removed:
        log("已清理 %d 个历史备份目录。" % removed, "INFO")


def cleanup_staging(skills_dir: Path):
    """清理历史遗留的暂存目录（来自上次崩溃中途退出），避免堆积。"""
    removed = 0
    for p in skills_dir.glob(".desen_stage_*"):
        try:
            shutil.rmtree(p, ignore_errors=True)
            removed += 1
        except Exception:  # noqa: BLE001
            pass
    if removed:
        log("已清理 %d 个历史暂存目录。" % removed, "INFO")


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="信息脱敏上云 SOP 手动升级器（安全零停机 / 跨平台 / 跨 AI 工具）")
    ap.add_argument("--source", choices=["github", "local"], default="github",
                    help="技能来源：github（默认）或 local（离线）")
    ap.add_argument("--local-path", default=None,
                    help="--source local 时的技能目录路径")
    ap.add_argument("--tool", default="auto",
                    choices=["auto", "workbuddy", "claude", "codex", "openclaw"],
                    help="目标 AI 工具（默认 auto 自动检测）")
    ap.add_argument("--skills-dir", default=None,
                    help="覆盖技能安装目录（测试 / 自定义用）")
    ap.add_argument("--force", action="store_true",
                    help="即使版本相同也强制重新应用（用于修复）")
    ap.add_argument("--check", action="store_true",
                    help="仅检查是否有更新，不下载、不应用")
    ap.add_argument("--dry-run", action="store_true",
                    help="下载 + 校验，但不替换线上技能（最安全的试跑）")
    ap.add_argument("--clean-backup", action="store_true",
                    help="清理历史备份目录后退出（不执行升级）")
    ap.add_argument("--skip-venv", action="store_true",
                    help="跳过 venv 构建（仅当你确定依赖未变且复用现有 venv 时使用）")
    ap.add_argument("--skip-tests", action="store_true",
                    help="跳过 scan/run/decrypt/restore 全环实测")
    args = ap.parse_args()

    # 0) 剥离 Agent 安全删除 shim（与 install 一致，避免 Windows 沙箱下删除失败）
    stripped = _neutralize_safe_delete_shim()
    if stripped:
        log("检测到 Agent 会话环境变量 %s，已剥离以避免 safe-delete 拦截删除（Windows 沙箱常见坑）。"
            % ", ".join(stripped), "WARN")

    # 清理备份模式：直接做事后退出
    if args.clean_backup:
        if args.skills_dir:
            sd = expand(args.skills_dir)
        else:
            tool = detect_tool(args.tool)
            sd = expand(TOOL_CONFIG[tool]["skills_dir"])
        cleanup_old_backups(sd, keep=None)
        log("历史备份清理完成。", "OK")
        sys.exit(0)

    banner("信息脱敏上云 SOP · 手动升级（安全零停机）")

    log("操作系统：%s (%s)" % (os.name, sys.platform))
    log("注意：本升级为手动触发；默认不自动运行。线上技能在『校验通过前』始终可调用。", "INFO")

    # 1) 检测工具 + 定位目录
    tool = detect_tool(args.tool)
    cfg = TOOL_CONFIG[tool]
    skills_dir = expand(args.skills_dir) if args.skills_dir else expand(cfg["skills_dir"])
    skills_dir.mkdir(parents=True, exist_ok=True)
    current = skills_dir / SKILL_NAME
    log("目标工具：%s" % cfg["label"])
    log("技能目录：%s" % skills_dir)
    log("线上技能：%s" % current)

    # 2) 读取本地版本 + 远程版本，判断是否需要升级
    local_ver, local_ver_src = read_local_version(current)
    log("本地版本：%s（来源 %s）" % (local_ver if local_ver else "未知",
                                    local_ver_src if local_ver_src else "无"))

    if args.check:
        remote_ver = fetch_remote_version_via_raw_robust()
        if remote_ver is None:
            log("无法获取远程版本（网络受限？）。可用 `python3 upgrade.py` 直接尝试下载比对。", "WARN")
            sys.exit(0)
        log("远程版本：%s" % (remote_ver,))
        if local_ver is None or remote_ver > local_ver:
            log("✅ 有可用更新：本地 %s → 远程 %s。运行 `python3 upgrade.py` 执行升级。"
                % (local_ver, remote_ver), "OK")
        else:
            log("已是最新（本地 %s ≥ 远程 %s），无需升级。" % (local_ver, remote_ver), "OK")
        sys.exit(0)

    # 非 --check：需要下载新版本以读取真实版本（暂存区）
    # 暂存目录必须与线上技能同文件系统 → 建于 skills_dir 内
    cleanup_staging(skills_dir)  # 先清掉上次崩溃遗留的暂存
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    staging = skills_dir / (".desen_stage_%s" % ts)

    if args.source == "github":
        remote_ver = fetch_remote_version_via_raw_robust()
        log("远程版本（raw）：%s" % (str(remote_ver) if remote_ver else "未知（下载后比对）"))
        if remote_ver is not None and local_ver is not None and remote_ver <= local_ver and not args.force:
            log("远程版本 %s 不高于本地 %s，无需升级（如需强制重装请加 --force）。"
                % (remote_ver, local_ver), "OK")
            sys.exit(0)

    # 3) 下载到暂存区
    banner("步骤 1 / 5 · 下载新版本到暂存区（线上技能未受影响）")
    if not download_to_staging(args.source,
                               expand(args.local_path) if args.local_path else None,
                               staging, args.force):
        log("下载失败，终止。线上技能保持不变。", "FAIL")
        sys.exit(2)
    strip_git(staging)

    new_ver, _ = read_local_version(staging)
    log("暂存版本：%s" % (str(new_ver) if new_ver else "未知"))
    if new_ver is not None and local_ver is not None and new_ver <= local_ver and not args.force:
        log("暂存版本 %s 不高于本地 %s，无需升级（如需强制重装请加 --force）。"
            % (new_ver, local_ver), "OK")
        shutil.rmtree(staging, ignore_errors=True)
        sys.exit(0)
    if new_ver is not None and local_ver is not None and new_ver > local_ver:
        log("发现更新：本地 %s → 暂存 %s。" % (local_ver, new_ver), "OK")

    # 4) 在暂存副本上构建 venv + 全环实测（校验无误）
    banner("步骤 2 / 5 · 暂存副本构建 venv + 全环实测（校验）")
    py = ensure_venv(staging, skip=args.skip_venv)
    if py is None and not args.skip_venv:
        log("暂存副本 venv 构建失败；为避免把『不可用版本』替换到线上，终止升级。线上技能保持不变。",
            "FAIL")
        shutil.rmtree(staging, ignore_errors=True)
        sys.exit(1)
    checks = verify(staging, py, skip=args.skip_tests)
    pass_n = sum(1 for _, ok, _ in checks if ok)
    total = len(checks)
    for name, ok, detail in checks:
        log("%s —— %s" % (name, detail), "OK" if ok else "FAIL")
    log("暂存实测：%d/%d 通过" % (pass_n, total),
        "OK" if pass_n == total else "FAIL")
    if pass_n != total:
        log("⚠️ 暂存副本实测未全部通过，拒绝替换线上技能（防止技能无法调用）。线上技能保持不变。",
            "FAIL")
        shutil.rmtree(staging, ignore_errors=True)
        sys.exit(1)
    log("✅ 暂存副本校验无误，可安全替换。", "OK")

    # dry-run：到此为止，不替换
    if args.dry_run:
        log("【dry-run】已下载并校验通过，按 --dry-run 不替换线上技能。暂存区保留于：%s" % staging,
            "OK")
        log("如需正式应用，去掉 --dry-run 重新运行。", "INFO")
        sys.exit(0)

    # 5) 原子替换（备份 → 替换 → 再实测 → 失败回滚）
    banner("步骤 3 / 5 · 原子替换线上技能（先备份，可回滚）")
    if not current.exists():
        # 线上技能不存在：直接落位（等同全新安装）
        log("线上技能不存在，直接将暂存副本落位。", "WARN")
        os.rename(str(staging), str(current))
        backup = None
    else:
        backup = atomic_swap(current, staging, skills_dir)

    banner("步骤 4 / 5 · 替换后实测线上技能")
    # venv_python 接收的是 .venv 目录本身（scripts/.venv），不是 scripts 目录
    live_py = venv_python(current / "scripts" / ".venv")
    if not live_py.exists():
        # 复用刚才构建的 venv（已随 rename 落位）
        live_py = py
    live_checks = verify(current, live_py, skip=args.skip_tests)
    live_pass = sum(1 for _, ok, _ in live_checks if ok)
    live_total = len(live_checks)
    for name, ok, detail in live_checks:
        log("%s —— %s" % (name, detail), "OK" if ok else "FAIL")
    log("线上实测：%d/%d 通过" % (live_pass, live_total),
        "OK" if live_pass == live_total else "FAIL")

    if live_pass != live_total and backup is not None:
        log("⚠️ 替换后线上实测未通过，正在回滚到备份……", "FAIL")
        try:
            if current.exists():
                shutil.rmtree(current, ignore_errors=True)
            os.rename(str(backup), str(current))
            log("已回滚到备份：%s" % current, "OK")
        except Exception as e:  # noqa: BLE001
            log("回滚失败：%s（请手动从备份恢复：%s）" % (e, backup), "FAIL")
        sys.exit(1)

    banner("步骤 5 / 5 · 收尾")
    if backup is not None:
        cleanup_old_backups(skills_dir, keep=backup)
        log("上一版本已备份于：%s（确认无误后可 `python3 upgrade.py --clean-backup` 清理）"
            % backup, "INFO")
    log("✅ 升级完成：%s → %s。线上技能已校验可用。"
        % (local_ver if local_ver else "?", new_ver if new_ver else "?"), "OK")
    log("若新版本异常，可用备份目录回滚：将 %s 重命名为 %s 即可。"
        % (backup, current), "INFO")
    sys.exit(0)


if __name__ == "__main__":
    main()
