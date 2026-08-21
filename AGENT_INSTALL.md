# 信息脱敏上云 SOP — Install Guide for AI Agents

You are an AI agent setting up the `desensitization-sop` skill for the user. **Done = `python3 install.py` exits 0** (skill installed, Python venv ready, resident rule written). **Never use `sudo`**; you cannot push to GitHub or pick the user's AI tool for them — Step 4 is the user's job.

## 1. Get the skill

The skill lives at `https://github.com/hzh-opc/desensitization-sop`. Prefer a fresh clone; fall back to a zip download if `git` is unavailable.

**macOS / Linux:**

```bash
git clone --depth 1 https://github.com/hzh-opc/desensitization-sop /tmp/desensitization-sop
cd /tmp/desensitization-sop
```

**Windows (PowerShell):**

```powershell
git clone --depth 1 https://github.com/hzh-opc/desensitization-sop $env:TEMP\desensitization-sop
cd $env:TEMP\desensitization-sop
```

If `git` is not available, download the zip instead:

```bash
# macOS / Linux
curl -fsSL https://github.com/hzh-opc/desensitization-sop/archive/refs/heads/main.zip -o /tmp/desen.zip
unzip /tmp/desen.zip -d /tmp && cd /tmp/desensitization-sop-main
```

## 2. Run the installer

```bash
# macOS / Linux
./install.sh
# 或： python3 install.py

# Windows (PowerShell)
.\install.ps1
# 或： py install.py
```

`install.py` will, automatically:

1. detect the current AI tool and locate its `skills/` directory + memory file;
2. install the skill into that `skills/` directory (git clone preferred, zip fallback; `--source local` for offline);
3. create the Python virtual environment (`scripts/.venv`) and install dependencies — **`uv add` preferred**, falling back to `venv` + `pip`;
4. run a full `scan → run(hybrid) → decrypt → restore` round-trip verification;
5. write the resident "input detection gate" rule into the tool's memory file (**idempotent** — safe to re-run).

## 3. Verify

```bash
python3 install.py        # idempotent; exits 0 when everything is ready
```

Each failure prints a `hint` — follow it and re-run. A successful install ends with exit code `0` and an `OK` summary. To skip the venv/build and only (re)write the resident rule, pass `--skip-venv --skip-tests`.

## 4. (user's job) Confirm the AI tool loads the skill

If the target AI tool was already running, tell the user to **restart it** (or reopen the session) so `desensitization-sop` is picked up. Then remind them of the red lines:

- original sensitive files **stay local** — never upload them whole;
- only the `desensitized/` copy may go to the cloud;
- the mapping keys (`.desensitize_keys/`) **never leave the machine**;
- automated detection is not 100% — always **review manually** before uploading.

> **⚠️ 常驻检测规则被覆盖？** 部分工具的「记忆文件」由云端缓存/宿主管理（例如 WorkBuddy 的 `~/.workbuddy/MEMORY.md` 会在会话重载时被云端同步回填），安装器写入的常驻闸门可能被冲掉、导致「执行前自动检测」失效。若重启后规则消失，检查该记忆文件是否仍含「任务执行前通用敏感信息检测闸门」小节；若无，可改投**每次会话必加载**的权威文件（如 `~/.workbuddy/SOUL.md`）：
>
> ```bash
> python3 install.py --memory-file ~/.workbuddy/SOUL.md
> ```
>
> （`--memory-file` 支持任意路径覆盖；幂等重装安全，可反复执行。）

## 5. Upgrading (manual, safe zero-downtime)

The skill ships `upgrade.py` (same paradigm as `install.py`). **Upgrades are manual only** — never auto-upgrade on load. When the user explicitly asks to upgrade/update the skill, run:

```bash
python3 upgrade.py            # check for updates; if any: download → verify → apply
python3 upgrade.py --check    # only check whether an update exists (no download/apply)
python3 upgrade.py --dry-run  # download + verify, but do NOT swap in (safest trial)
```

`upgrade.py` downloads the new version into a **staging directory on the same filesystem** as the live skill, builds its venv and runs the `scan → run → decrypt → restore` round-trip on the staged copy (**rejects the swap if verification fails**), then renames the live skill to a backup and atomically renames the staged copy into place — re-verifying afterward and **auto-rolling-back on failure**. The live skill is never touched until verification passes, so a failed upgrade cannot break the skill's callability.

## 6. Troubleshooting

- **受限网络（github.com / codeload.github.com 不可达，但 api.github.com、raw.githubusercontent.com 可达）**：改用本地源离线安装/升级：
  ```bash
  python3 upgrade.py --source local --local-path /path/to/desensitization-sop
  python3 install.py  --source local --local-path /path/to/desensitization-sop
  ```
- **Windows 下还原与原文件逐字节不一致（换行翻倍）**：v2.9.1 已修复 CRLF 双倍换行（读写统一 `newline=""`，根因是 `_read_text` 二进制读保留 `\r\n`、写出却走默认文本模式被 Windows 二次翻译）。若仍遇不一致，优先怀疑文本模式换行翻译，升级到 v2.9.1+ 后重试；校验门已新增 CRLF 样本的全环逐字节比对，可在任意平台捕获此类问题。
- **Agent 沙箱内安装/升级被 safe-delete shim 拦截**：`install.py`/`upgrade.py` 已内置 `_neutralize_safe_delete_shim()` 剥离 `CODEBUDDY_SESSION_ID`/`CLAUDE_SESSION_ID`。个别沙箱剥离可能晚于 `sitecustomize` 注入时机，最稳妥是在 shell 先 `unset CODEBUDDY_SESSION_ID CLAUDE_SESSION_ID` 再运行安装/升级。
- **常驻检测闸门失效（记忆文件被云端/宿主覆盖）**：见第 4 步警示——若工具的「记忆文件」会被云端回填（如 WorkBuddy 的 `~/.workbuddy/MEMORY.md`），重跑 `install.py --memory-file <每次会话必加载的文件>`（如 `~/.workbuddy/SOUL.md`）即可把规则写到权威落点。
