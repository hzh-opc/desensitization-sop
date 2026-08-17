#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
信息脱敏上云 SOP —— 一键安装脚本
===================================================================
跨平台 (Windows / macOS / Linux)，兼容 WorkBuddy / OpenClaw / Claude Code / Codex。

功能：
  1. 自动检测当前 AI 工具，定位其 skills 目录与记忆/指令文件；
  2. 从 GitHub (https://github.com/hzh-opc/desensitization-sop) 下载并安装技能
     （git clone 优先，失败自动降级为 zip 下载；亦支持 --local 离线安装）；
  3. 自动检测 / 创建 Python 虚拟环境 (.venv) 并安装依赖；
  4. 实测脚本是否正常运行：scan / run(hybrid) / decrypt / restore 全环验证；
  5. 把“任务执行前自动敏感信息检测”设为常驻规则（幂等写入记忆文件）。

用法：
  python3 install.py                      # 默认：自动检测工具 + 从 GitHub 安装
  python3 install.py --tool claude        # 指定目标工具
  python3 install.py --source local --local-path /path/to/skill   # 离线/本地安装
  python3 install.py --force              # 强制覆盖已安装技能
  python3 install.py --skip-venv --skip-tests   # 仅下载技能 + 写常驻规则

退出码：0 = 全部通过；非 0 = 存在失败项（详见末尾汇总）。
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

# --------------------------------------------------------------------------- #
# 常量配置
# --------------------------------------------------------------------------- #
SKILL_NAME = "desensitization-sop"
REPO_URL = "https://github.com/hzh-opc/desensitization-sop"
DEFAULT_BRANCH = "main"  # 若 main 不存在，安装器会再尝试 master

# 各 AI 工具：技能目录 + 记忆/指令文件（用于写入“常驻规则”）
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

# 常驻规则（幂等插入，以 RULE_MARKER 去重）
RULE_MARKER = "## 任务执行前通用敏感信息检测闸门"
RULE_BLOCK = (
    "## 任务执行前通用敏感信息检测闸门（常驻规则）\n"
    "执行任何任务前，若任务输入可能含敏感信息（文本 / 文件 / 数据库 / 知识库 / 代码等任一形态），"
    "须先自动检测；\n"
    "检出敏感 → 本地脱敏后再执行任务，未检出 → 直接执行、零额外负担。\n"
    "配套技能：`desensitization-sop`（已安装，自动触发上云前自查与任务后审计）。\n"
)

# 复制技能时忽略的项（避免拷贝巨型 venv / 缓存 / 仓库元数据）
COPY_IGNORE = {".venv", "__pycache__", ".git", "node_modules"}
COPY_IGNORE_SUFFIX = (".pyc", ".pyo", ".DS_Store")

# 测试样例（含可直接被正则识别的标识，无需 --names 也能命中）
SAMPLE_NAME = "张伟"
SAMPLE_TEXT = (
    "员工: 张伟\n"
    "身份证: 110101199001011234\n"
    "手机: 13800138000\n"
    "工资卡: 6222021234567890123\n"
    "邮箱: zhangwei@example.com\n"
)


# --------------------------------------------------------------------------- #
# 日志
# --------------------------------------------------------------------------- #
def log(msg, kind="INFO"):
    prefix = {
        "INFO": "[INFO] ",
        "OK":   "[ OK ] ",
        "FAIL": "[FAIL] ",
        "WARN": "[WARN] ",
        "STEP": "[STEP] ",
    }.get(kind, "")
    print("%s%s" % (prefix, msg), flush=True)


def banner(title):
    print("\n" + "=" * 64)
    print("  " + title)
    print("=" * 64, flush=True)


# --------------------------------------------------------------------------- #
# 路径工具
# --------------------------------------------------------------------------- #
def expand(p):
    return Path(os.path.expanduser(p)).expanduser()


def venv_python(venv_dir: Path) -> Path:
    if os.name == "nt":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


# --------------------------------------------------------------------------- #
# 工具检测
# --------------------------------------------------------------------------- #
def detect_tool(explicit):
    if explicit and explicit != "auto":
        return explicit
    # 1) 环境变量优先（CI / 容器 / 手动指定）
    env = os.environ.get("AI_TOOL", "").strip().lower()
    if env in TOOL_CONFIG:
        return env
    # 2) 按已知主目录存在性推断（顺序即优先级）
    for key in ("workbuddy", "claude", "codex", "openclaw"):
        cfg = TOOL_CONFIG[key]
        if expand(cfg["skills_dir"]).exists() or expand(cfg["memory_file"]).exists():
            return key
    # 3) 都未安装：默认按 WorkBuddy 约定安装
    log("未检测到任何已安装的 AI 工具，将按 WorkBuddy 约定安装。", "WARN")
    return "workbuddy"


# --------------------------------------------------------------------------- #
# 下载 / 安装技能本体
# --------------------------------------------------------------------------- #
def _clone_with_git(repo_url, dest: Path, branch):
    cmd = ["git", "clone", "--depth", "1", "-b", branch, repo_url, str(dest)]
    log("尝试 git clone：%s (branch=%s)" % (repo_url, branch))
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode == 0


def _download_zip(repo_url, dest: Path, branch):
    for br in (branch, "master", "main"):
        zip_url = "%s/archive/refs/heads/%s.zip" % (repo_url, br)
        log("尝试 zip 下载：%s" % zip_url)
        try:
            with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
                req = urllib.request.Request(zip_url, headers={"User-Agent": "desen-sop-installer"})
                with urllib.request.urlopen(req, timeout=60) as resp:
                    tf.write(resp.read())
                zpath = tf.name
            with zipfile.ZipFile(zpath) as zf:
                # 找到顶层目录（形如 desensitization-sop-main）
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


def _copy_local(local_path: Path, dest: Path):
    def ignore(_dir, names):
        ignored = []
        for n in names:
            if n in COPY_IGNORE:
                ignored.append(n)
            elif n.endswith(COPY_IGNORE_SUFFIX):
                ignored.append(n)
        return ignored

    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(str(local_path), str(dest), ignore=ignore)
    return True


def install_skill(source, local_path, dest: Path, force):
    if dest.exists():
        if not force:
            log("技能已存在于 %s，跳过下载（如需覆盖请加 --force）。" % dest, "OK")
            return True
        log("检测到已安装技能，--force 将覆盖。", "WARN")

    if source == "local":
        if not local_path or not local_path.exists():
            log("本地源路径不存在：%s" % local_path, "FAIL")
            return False
        log("从本地复制技能：%s" % local_path)
        return _copy_local(local_path, dest)

    # GitHub 源：git 优先，zip 降级
    if _clone_with_git(REPO_URL, dest, DEFAULT_BRANCH):
        return True
    log("git clone 失败，尝试 zip 降级下载……", "WARN")
    if _download_zip(REPO_URL, dest, DEFAULT_BRANCH):
        return True
    log("从 GitHub 下载技能失败（请检查网络，或使用 --source local 离线安装）。", "FAIL")
    return False


# --------------------------------------------------------------------------- #
# 虚拟环境 + 依赖
# --------------------------------------------------------------------------- #
def _find_uv():
    """在 PATH 与常见安装位置中查找 uv 可执行文件（不依赖 PATH 是否显式配置）。"""
    candidates = [
        "uv",
        os.path.expanduser("~/.local/bin/uv"),
        os.path.expanduser("~/.cargo/bin/uv"),
        "/usr/local/bin/uv",
        "/opt/homebrew/bin/uv",
    ]
    for c in candidates:
        if c == "uv":
            p = shutil.which("uv")
        else:
            p = c if os.path.isfile(c) else None
        if p:
            return p
    return None


def _write_minimal_pyproject(desenstool: Path):
    """desenstool 尚未声明为 uv 工程时，写入最小 pyproject.toml。

    之后由 `uv add` 追加具体依赖，使 desenstool 成为标准的 uv 工程。
    """
    desenstool.mkdir(parents=True, exist_ok=True)
    (desenstool / "pyproject.toml").write_text(
        '[project]\n'
        'name = "desensitization-tool"\n'
        'version = "0.1.0"\n'
        'description = "信息脱敏上云 SOP 本地脱敏工具"\n'
        'requires-python = ">=3.10,<3.14"\n'
        'dependencies = []\n'
        '\n'
        '[tool.uv]\n'
        'package = false\n',
        encoding="utf-8",
    )


def ensure_venv(skill_dir: Path, skip=False):
    """返回 venv 的 python 路径；失败返回 None。

    依赖管理统一使用 uv（优先），尽量用 `uv add` 声明并安装依赖：
      - desenstool 必须是 uv 工程（含 pyproject.toml）；已存在则保留既有声明、不覆盖；
      - `uv add <deps>` 会把依赖写入 pyproject.toml 并安装进 desenstool/.venv
        （uv 自动创建 .venv，无需 venv 自带 pip，兼容“python -m venv 不含 pip”的精简 Python）；
      - 回退路径：python -m venv + ensurepip / get-pip.py，再 pip install -r requirements.txt。
    """
    desenstool = skill_dir / "desenstool"
    vd = desenstool / ".venv"
    py = venv_python(vd)

    if skip:
        if py.exists():
            log("跳过 venv 创建，复用已有：%s" % py, "OK")
            return py
        log("跳过 venv 创建，但未找到已有 venv：%s" % vd, "FAIL")
        return None

    uv = _find_uv()
    req = skill_dir / "requirements.txt"

    # 1) 确保 desenstool 是 uv 工程（pyproject.toml）；已存在则不覆盖
    if not (desenstool / "pyproject.toml").exists():
        _write_minimal_pyproject(desenstool)
        log("已为 desenstool 写入最小 pyproject.toml（uv 工程）。", "OK")

    # 2) 优先用 uv add 安装依赖（无需 venv 自带 pip）
    if uv:
        # 与 requirements.txt / desenstool/pyproject.toml 保持一致：
        # 基础抽取/解密库 + v2.4 起纯本地 OCR（rapidocr + onnxruntime + pypdfium2，
        # 模型随 wheel 捆绑、完全离线）。
        deps = ["cryptography", "python-docx", "openpyxl", "python-pptx",
                "pypdfium2", "pikepdf", "msoffcrypto-tool",
                "rapidocr", "onnxruntime"]
        log("使用 uv 安装依赖（uv add，可能需联网，请稍候）……")
        env = dict(os.environ)
        r = subprocess.run([uv, "add"] + deps, cwd=str(desenstool),
                           capture_output=True, text=True, env=env)
        if r.returncode != 0:
            # 依赖可能已在 pyproject 中（uv add 幂等）；失败时退一步 uv sync
            log("uv add 失败，尝试 uv sync：%s"
                % (r.stderr.strip() or r.stdout.strip()), "WARN")
            r2 = subprocess.run([uv, "sync"], cwd=str(desenstool),
                                capture_output=True, text=True, env=env)
            if r2.returncode != 0:
                log("uv sync 失败：%s" % (r2.stderr.strip() or r2.stdout.strip()), "FAIL")
            else:
                log("依赖同步完成（uv sync）。", "OK")
        else:
            log("依赖安装完成（uv add）。", "OK")
        if py.exists():
            return py
        log("uv 未生成 .venv：%s" % vd, "FAIL")
        # 继续走下方 pip 回退

    # 3) 回退：python -m venv 创建 + ensurepip / get-pip.py 引导 + pip install -r requirements.txt
    if not req.exists():
        log("未找到 requirements.txt：%s" % req, "FAIL")
        return None

    if not vd.exists():
        log("创建虚拟环境：%s" % vd)
        r = subprocess.run([sys.executable, "-m", "venv", str(vd)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            log("venv 创建失败：%s" % r.stderr.strip(), "FAIL")
            return None
    else:
        log("虚拟环境已存在：%s" % vd, "OK")

    if os.name == "nt":
        pip_exe = vd / "Scripts" / "pip.exe"
    else:
        pip_exe = vd / "bin" / "pip"
    if not pip_exe.exists():
        log("venv 内无 pip，尝试 ensurepip 引导……", "WARN")
        b = subprocess.run([str(py), "-m", "ensurepip", "--upgrade", "--default-pip"],
                           capture_output=True, text=True)
        if b.returncode != 0 or not pip_exe.exists():
            try:
                getpip = tempfile.NamedTemporaryFile(suffix=".py", delete=False).name
                urllib.request.urlretrieve("https://bootstrap.pypa.io/get-pip.py", getpip)
                subprocess.run([str(py), getpip], capture_output=True, text=True)
                os.unlink(getpip)
            except Exception as e:  # noqa: BLE001
                log("pip 引导失败：%s" % e, "FAIL")
                return None
    r = subprocess.run([str(py), "-m", "pip", "install", "-r", str(req), "--upgrade"],
                       capture_output=True, text=True)
    if r.returncode != 0:
        log("依赖安装失败：%s" % (r.stderr.strip() or r.stdout.strip()), "FAIL")
        log("提示：脚本基础模式（文本/代码）仅需 cryptography；"
            "Office 抽取需 python-docx/openpyxl/python-pptx，PDF 抽取/渲染需 pypdfium2，"
            "本地 OCR 需 rapidocr + onnxruntime。", "WARN")
        return None
    log("依赖安装完成。", "OK")
    return py


# --------------------------------------------------------------------------- #
# 实测验证：scan / run / decrypt / restore 全环
# --------------------------------------------------------------------------- #
def run_check(py: Path, script: Path, args, **kw):
    cmd = [str(py), str(script)] + args
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    return r


def verify(skill_dir: Path, py: Path, skip=False):
    """返回 [(名称, 是否通过, 详情), ...]。"""
    if skip or py is None:
        return [("脚本实测（已跳过）", True, "通过 --skip-tests")]

    script = skill_dir / "desenstool" / "desensitize.py"
    if not script.exists():
        return [("脚本存在性", False, "找不到 %s" % script)]

    results = []
    tmp = Path(tempfile.mkdtemp(prefix="desen_verify_"))
    try:
        sample = tmp / "sample.txt"
        sample.write_text(SAMPLE_TEXT, encoding="utf-8")
        names = tmp / "names.txt"
        names.write_text(SAMPLE_NAME + "\n", encoding="utf-8")

        des = tmp / "desensitized"
        keys = tmp / ".desensitize_keys"

        # 1) scan：脚本能正常运行并识别 PII
        r = run_check(py, script, ["scan", str(sample)])
        ok = (r.returncode == 0) and (len(r.stdout.strip()) > 0)
        results.append(("scan 正常运行", ok,
                         "rc=%d，输出 %d 字节" % (r.returncode, len(r.stdout)) if ok
                         else (r.stderr.strip() or r.stdout.strip())[:200]))

        # 2) run(hybrid)：生成脱敏副本 + 加密映射表，且原始明文被掩码
        r = run_check(py, script,
                      ["run", str(sample), "--mode", "hybrid",
                       "--out", str(des), "--keys", str(keys),
                       "--names", str(names)])
        des_file = des / "sample.txt"
        masked = des_file.exists() and ("110101199001011234" not in des_file.read_text(encoding="utf-8"))
        has_token = des_file.exists() and ("⟦T" in des_file.read_text(encoding="utf-8"))
        ok = (r.returncode == 0) and masked and has_token
        results.append(("run(hybrid) 脱敏 + 掩码", ok,
                         "副本已生成、明文已掩码、含唯一令牌" if ok
                         else "rc=%d masked=%s token=%s" % (r.returncode, masked, has_token)))

        # 3) decrypt：映射表可逆（含原始值，无多对一歧义）
        mapping = tmp / "mapping.json"
        r = run_check(py, script, ["decrypt", "--keys", str(keys), "--out", str(mapping)])
        reversible = False
        if mapping.exists():
            data = json.loads(mapping.read_text(encoding="utf-8"))
            flat = [it for items in data.values() for it in items]
            reversible = any(it.get("original") == "110101199001011234" for it in flat)
        ok = (r.returncode == 0) and reversible
        results.append(("decrypt 可逆性", ok,
                         "映射表含原始身份证、可唯一还原" if ok
                         else "rc=%d 映射可逆=%s" % (r.returncode, reversible)))

        # 4) restore：回填副本与原始逐字节一致（全环闭环）
        restored = tmp / "restored"
        r = run_check(py, script,
                      ["restore", "--keys", str(keys),
                       "--input", str(des), "--out", str(restored)])
        rest_file = restored / "sample.txt"
        roundtrip = rest_file.exists() and (rest_file.read_bytes() == sample.read_bytes())
        ok = (r.returncode == 0) and roundtrip
        results.append(("restore 回填闭环", ok,
                         "回填副本与原始逐字节一致" if ok
                         else "rc=%d roundtrip=%s" % (r.returncode, roundtrip)))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return results


# --------------------------------------------------------------------------- #
# 常驻规则写入
# --------------------------------------------------------------------------- #
def install_rule(memory_file: Path, skip=False):
    if skip:
        return True, "通过 --skip-rule"
    memory_file = expand(memory_file)
    try:
        memory_file.parent.mkdir(parents=True, exist_ok=True)
        content = memory_file.read_text(encoding="utf-8") if memory_file.exists() else ""
        if RULE_MARKER in content:
            return True, "常驻规则已存在，跳过（幂等）"
        sep = "" if not content or content.endswith("\n") else "\n"
        with memory_file.open("a", encoding="utf-8") as f:
            f.write(sep + "\n" + RULE_BLOCK)
        return True, "已写入：%s" % memory_file
    except Exception as e:  # noqa: BLE001
        return False, "写入失败：%s" % e


# --------------------------------------------------------------------------- #
# 主流程
# --------------------------------------------------------------------------- #
def main():
    ap = argparse.ArgumentParser(
        description="信息脱敏上云 SOP 一键安装器（跨平台 / 跨 AI 工具）")
    ap.add_argument("--source", choices=["github", "local"], default="github",
                    help="技能来源：github（默认）或 local（离线）")
    ap.add_argument("--local-path", default=None,
                    help="--source local 时的技能目录路径")
    ap.add_argument("--tool", default="auto",
                    choices=["auto", "workbuddy", "claude", "codex", "openclaw"],
                    help="目标 AI 工具（默认 auto 自动检测）")
    ap.add_argument("--skills-dir", default=None,
                    help="覆盖技能安装目录（测试 / 自定义用）")
    ap.add_argument("--memory-file", default=None,
                    help="覆盖常驻规则写入的文件（测试 / 自定义用）")
    ap.add_argument("--force", action="store_true",
                    help="覆盖已安装的技能目录")
    ap.add_argument("--skip-venv", action="store_true", help="跳过虚拟环境创建")
    ap.add_argument("--skip-rule", action="store_true", help="跳过常驻规则写入")
    ap.add_argument("--skip-tests", action="store_true", help="跳过脚本实测")
    args = ap.parse_args()

    banner("信息脱敏上云 SOP · 一键安装")

    # 0) 环境信息
    log("操作系统：%s (%s)" % (platform.system(), platform.release()))
    log("Python：%s" % sys.version.split()[0])

    # 1) 检测工具
    tool = detect_tool(args.tool)
    cfg = TOOL_CONFIG[tool]
    skills_dir = expand(args.skills_dir) if args.skills_dir else expand(cfg["skills_dir"])
    memory_file = expand(args.memory_file) if args.memory_file else expand(cfg["memory_file"])
    log("目标工具：%s" % cfg["label"])
    log("技能目录：%s" % skills_dir)
    log("记忆/指令文件：%s" % memory_file)

    skills_dir.mkdir(parents=True, exist_ok=True)
    dest = skills_dir / SKILL_NAME

    # 2) 安装技能本体
    banner("步骤 1 / 4 · 下载并安装技能")
    if not install_skill(args.source, expand(args.local_path) if args.local_path else None,
                         dest, args.force):
        log("技能安装失败，终止。", "FAIL")
        sys.exit(2)

    # 3) 虚拟环境 + 依赖
    banner("步骤 2 / 4 · 虚拟环境与依赖")
    py = ensure_venv(dest, skip=args.skip_venv)
    if py is None and not args.skip_venv:
        log("虚拟环境/依赖准备失败；后续实测可能受限。", "WARN")

    # 4) 实测验证
    banner("步骤 3 / 4 · 脚本实测验证")
    checks = verify(dest, py, skip=args.skip_tests)
    pass_n = 0
    for name, ok, detail in checks:
        log("%s —— %s" % (name, detail), "OK" if ok else "FAIL")
        pass_n += 1 if ok else 0
    total = len(checks)
    log("实测：%d/%d 通过" % (pass_n, total), "OK" if pass_n == total else "WARN")

    # 5) 常驻规则
    banner("步骤 4 / 4 · 写入常驻规则")
    ok, detail = install_rule(memory_file, skip=args.skip_rule)
    log("常驻规则：%s" % detail, "OK" if ok else "FAIL")

    # 汇总
    banner("安装汇总")
    log("技能目录：%s" % dest)
    log("Python venv：%s" % (py if py else "（未创建/跳过）"))
    log("脚本实测：%d/%d 通过" % (pass_n, total))
    log("常驻规则：%s" % ("已写入" if ok else "失败"))
    log("调用示例：%s desenstool/desensitize.py scan <文件>"
        % (str(py) if py else "python"), "INFO")

    all_ok = (py is not None or args.skip_venv) and (pass_n == total) and ok
    if all_ok:
        log("✅ 全部完成，技能已就绪。", "OK")
        sys.exit(0)
    else:
        log("⚠️ 存在未通过项，请查看上方明细。", "WARN")
        sys.exit(1)


if __name__ == "__main__":
    main()
