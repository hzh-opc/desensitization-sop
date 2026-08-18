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

## 5. Upgrading (manual, safe zero-downtime)

The skill ships `upgrade.py` (same paradigm as `install.py`). **Upgrades are manual only** — never auto-upgrade on load. When the user explicitly asks to upgrade/update the skill, run:

```bash
python3 upgrade.py            # check for updates; if any: download → verify → apply
python3 upgrade.py --check    # only check whether an update exists (no download/apply)
python3 upgrade.py --dry-run  # download + verify, but do NOT swap in (safest trial)
```

`upgrade.py` downloads the new version into a **staging directory on the same filesystem** as the live skill, builds its venv and runs the `scan → run → decrypt → restore` round-trip on the staged copy (**rejects the swap if verification fails**), then renames the live skill to a backup and atomically renames the staged copy into place — re-verifying afterward and **auto-rolling-back on failure**. The live skill is never touched until verification passes, so a failed upgrade cannot break the skill's callability.
