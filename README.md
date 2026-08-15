# 信息脱敏上云 SOP（AI Agent 上云前 / 上云后闭环）

![License](https://img.shields.io/github/license/hzh-opc/desensitization-sop?style=flat-square)
![Release](https://img.shields.io/github/v/release/hzh-opc/desensitization-sop?style=flat-square)
![Python](https://img.shields.io/badge/python-%3E%3D3.9-blue?style=flat-square)

> **一句话**：当你用 WorkBuddy / Claude / Codex / GPT 等云端大模型处理本地文本、文件、数据库、代码时，本 SOP 与配套技能帮你 **先把敏感信息在本地脱敏、只把脱敏副本上云**，且全过程可溯源、留审计、可本地复核。
>
> **配套技能**：`desensitization-sop`（WorkBuddy 技能，自动执行「上云前自查」与「任务后审计汇总」）
> **本仓库三份文件分工**：
> - `SKILL.md`：**自动加载的执行规范**（11 项上云前自查 + 审计模板），AI Agent 每次调用必走；
> - `reference.md`：**按需读取的操作详述**（合规依据、分级判定、六步流程、精度影响、场景专项、工具选型、脚本说明、附录），不自动加载；
> - `README.md`：本文件，**GitHub 项目说明**。

---

## 这是什么 / 为什么需要

个人、政府部门或企事业单位用云端 AI 处理本地数据时，内容可能携带**个人标识、财务/审计/投研数据、密钥 Token** 等敏感信息。直接上传 = 敏感信息外泄。

本 SOP 在「用 AI 提效」与「防敏感信息外泄」之间取得可控平衡，核心原则：

- **原始敏感文件永远留本地，绝不整份上传**；
- **本地分级脱敏后**，仅脱敏副本可上云；
- 全过程**可溯源、留审计、可本地复核**；
- 云端记忆 / 知识库**禁存敏感原文**。

技能 `desensitization-sop` 在每次 AI 任务「上云前」自动执行脱敏自查（任一项不过即中止并提示），「任务后」自动生成审计汇总，形成闭环。

### 核心能力

| 能力 | 说明 |
|---|---|
| 三级风险判定 | 高 / 中 / 低，对接 GB/T 37964、JR/T 0197、GB/T 45574 等标准 |
| 六步脱敏流程 | 识别 → 定方法 → 执行 → 验证 → 审计 → 上云 |
| 映射表安全 | 重识别钥匙（映射表）与副本**分离 + AES 加密 + 最小权限** |
| 红线拦截 | 证券/投研内幕信息红线；财务/审计涉密禁传公共 AI；数值「去标识不扭曲」 |
| 代码密钥扫描 | 账号/密码/API Key/Token/私钥自动扫描与脱敏确认 |
| 任务后审计 | 自动生成 11 项审计汇总（追加至 `desensitize_audit.md`） |

---

## 快速上手

```bash
# 1) 扫描：看看本地文件里有哪些敏感字段（不生成任何文件）
python desenstool/desensitize.py scan ./data/ --recursive

# 2) 脱敏：生成脱敏副本 + 加密映射表（默认 hybrid 模式）
python desenstool/desensitize.py run ./data/ \
    --out ./desensitized --keys ./.desensitize_keys --mode hybrid

# 3) 上云：只把 ./desensitized 里的副本发给大模型；.desensitize_keys 永不外传
# 4) 任务后审计（基于 run 报告自动生成 11 项审计文档）
python desenstool/desensitize.py audit --report ./desensitize_report.json

# 5) 本地复核 / 回填：用映射表解密或还原实名（均在本地，无需上云）
python desenstool/desensitize.py decrypt --keys ./.desensitize_keys
python desenstool/desensitize.py restore --keys ./.desensitize_keys --input ./desensitized --out ./restored
```

> 子命令：`scan`（报告命中）/ `run`（脱敏+映射表）/ `decrypt`（本地解密映射表）/ `restore`（回填为含原值内部文档）/ `audit`（自动审计文档）。
> 脱敏模式默认 `hybrid`（语义掩码+唯一令牌，无歧义恢复且保留字段语义）；另有 `mask` / `token` / `redact`。
> 中文识别增强：`--cn-enhance`（本地离线，识别中文姓名/地址/机构名）。详见下方「文档导航」。

---

## 让 Agent 帮你安装（推荐）

不想手敲命令？把本仓库交给任意兼容的 AI Agent（WorkBuddy / Claude / Codex / OpenClaw 等），让它照 [`AGENT_INSTALL.md`](AGENT_INSTALL.md) 自动完成「下载技能 → 安装到 `skills/` 目录 → 建 Python 虚拟环境装依赖 → 跑通 `scan`/`run`/`decrypt`/`restore` 全环验证 → 写入常驻检测规则」。你只需在最后按提示确认 AI 工具重新加载技能即可。

**① 复制下面这段，直接粘贴给你的 AI Agent：**

```
请按 https://github.com/hzh-opc/desensitization-sop/blob/main/AGENT_INSTALL.md 的说明，把 desensitization-sop 技能安装到当前 AI 工具的 skills 目录：克隆仓库 → 运行 install.py（自动检测工具、建 Python 虚拟环境装依赖、跑通 scan→run→decrypt→restore 全环验证、写入常驻检测规则）→ 验证安装。完成后告诉我需要重启/重载哪个 AI 工具以加载技能。
```

**② Agent 在后台实际执行的等效命令（供你了解，无需手动执行）：**

```bash
# 1) 克隆本仓库
git clone https://github.com/hzh-opc/desensitization-sop.git /tmp/desensitization-sop

# 2) 运行安装脚本（自动适配当前 AI 工具并建立虚拟环境）
python /tmp/desensitization-sop/install.py

# 3) 验证（脚本已自动跑通全环；如需手动复验）
python /tmp/desensitization-sop/desenstool/desensitize.py scan --help
```

> 若当前 AI 工具已运行，安装完成后请按 Agent 提示**重启它（或重开会话）**以加载 `desensitization-sop`。

## 一键安装（跨平台 / 跨 AI 工具）

仓库内置 `install.py`（纯标准库，无第三方依赖），支持 **Windows / macOS / Linux**，并自动适配 **WorkBuddy / OpenClaw / Claude Code / Codex**：

| 步骤 | 动作 |
|---|---|
| 1 | 自动检测当前 AI 工具，定位其 `skills/` 目录与记忆/指令文件 |
| 2 | 从 GitHub（`https://github.com/hzh-opc/desensitization-sop`）下载并安装技能（git 优先，失败自动降级 zip；亦支持 `--source local` 离线安装） |
| 3 | 自动检测 / 创建 Python 虚拟环境（`desenstool/.venv`）并安装依赖（**优先 `uv add`**；无 uv 时回退 `venv`+`pip`） |
| 4 | 实测脚本是否正常运行：`scan` → `run(hybrid)` → `decrypt` → `restore` 全环验证 |
| 5 | 把「任务执行前自动敏感信息检测」设为**常驻规则**（幂等写入记忆文件） |

### 运行方式

```bash
# macOS / Linux
./install.sh
# 或 python3 install.py

# Windows (PowerShell)
.\install.ps1
# 或 py install.py
```

### 常用参数

```bash
python3 install.py                         # 默认：自动检测工具 + 从 GitHub 安装
python3 install.py --tool claude           # 指定目标工具
python3 install.py --source local --local-path /path/to/skill   # 离线/本地安装
python3 install.py --force                 # 覆盖已安装技能
python3 install.py --skip-venv --skip-tests  # 仅下载技能 + 写常驻规则
```

> 退出码 `0` = 全部通过；非 `0` = 存在失败项（详见脚本末尾汇总）。
> Codex / OpenClaw 的记忆文件路径为业界常见约定（`.codex/codex.md` / `.openclaw/AGENTS.md`），如与所用版本不符，可用 `--memory-file` / `--skills-dir` 覆盖。

---

## 卸载（跨平台 / 跨 AI 工具）

仓库内置 `uninstall.py`（纯标准库，无第三方依赖），与 `install.py` 对称，支持相同工具与平台。

| 安全特性 | 说明 |
|---|---|
| 默认 dry-run | 不加 `--yes` 只预览「将删除什么」，**不实际删除任何文件** |
| 仅删技能自身 | 只删除 `skills/desensitization-sop` 目录，绝不递归父目录 |
| 卸载前备份 | 默认先备份到 `<skills_dir>/../.desen_uninstall_backup`（可用 `--backup-dir` / `--no-backup` 调整） |
| 移除常驻规则 | 从记忆/指令文件中移除「任务执行前通用敏感信息检测闸门」常驻规则（幂等，兼容 `##` 标题块与 `- **` 子弹两种形态） |
| 幂等 | 技能目录已不存在 / 规则已不存在时，安全跳过 |

### 运行方式

```bash
# 1) 先预览（推荐第一步，确认目标无误）
python3 uninstall.py
# 或指定工具：python3 uninstall.py --tool claude

# 2) 确认无误后真正卸载（含备份）
python3 uninstall.py --yes
```

### 常用参数

```bash
python3 uninstall.py                         # dry-run 预览（默认）
python3 uninstall.py --tool claude --yes     # 指定工具并卸载
python3 uninstall.py --skills-dir /p --memory-file /p --yes  # 精确指定目标
python3 uninstall.py --keep-memory           # 不处理记忆文件中的常驻规则
python3 uninstall.py --no-backup --yes       # 不备份直接删除（慎用）
```

> 退出码 `0` = 卸载干净（或原本就无需卸载）；非 `0` = 存在失败项（详见脚本末尾汇总）。
> 重装：用 `install.py --source local --local-path <备份目录>/desensitization-sop` 即可从备份恢复。

---

## 文档导航

| 文档 | 何时读 |
|---|---|
| `README.md`（本文件） | 项目介绍、署名许可、安装卸载、快速上手、FAQ |
| `SKILL.md` | **AI Agent 自动加载**：执行规范、11 项上云前自查清单、审计模板、脚本调用入口 |
| `reference.md` | 边界场景按需 `Read`：合规依据、三级风险判定、准标识符重识别、六步流程、精度影响对照、场景专项、工具选型、脚本完整说明、附录 |

`reference.md` 章节索引：目标与原则 · 背景与原思路修订 · 合规依据（引用来源）· §0 输入检测闸门 · §1 关键概念 · §2 敏感信息分类分级 · §3 脱敏操作流程（六步）· §4 脱敏对 AI 任务精度的影响 · §5 场景专项要求 · §6 工具与技术选型 · 配套一键脱敏本地脚本 · §7 应急、改进与附录。

---

## 能力边界与重要声明（必读）

> **红线**：脱敏副本可上云，原始文件与映射表（重识别钥匙）留本地且分离；自动化识别非 100%，**禁止「一键脱敏即上云」，必须人工复核** skip manifest 中列出的未处理文件。

1. **自动化识别非 100% 召回（尤其中文姓名/住址）**，脱敏后必须人工复核。脚本内置离线中文增强（`--cn-enhance`），但仍可能漏报/误报（如「赵钱孙先生」可能误识为姓名、「北京大学」可能误识为机构）。
2. **以下形态脚本不直接处理**，会在扫描/脱敏末尾输出 **skip manifest（未处理清单）并给出可执行提醒，绝不会静默放过**：
   - 影像/图片（.png/.jpg/…）：脚本不做 OCR，须先本地 OCR 转文本；
   - 纯图片型/扫描件 PDF（无文本层）：抽到空文本即提醒先本地 OCR；
   - 加密文档（加密 PDF / 加密 Office）：提醒先本地解密后再纳入；
   - 其他未知二进制：提醒转文本/OCR/解密后再纳入。
3. **可逆脱敏 ≠ 匿名化**：本 SOP 的本地映射表方案属于「去标识化」，在法律上**仍是个人信息**；映射表/密钥一旦与副本同泄，等于原始数据泄露，故必须分离、加密、最小权限。
4. **本 SOP 为可落地操作规范，非法律意见**。具体合规要求请以 PIPL、数据安全法及主管部门最新规定为准。

---

## 常见问题（FAQ）

**Q1. 这不是多此一举？我直接把数据发给 AI 不就行了？**
A. 本地文件可能含身份证号、手机号、银行卡、密钥 Token、财务报表等敏感信息。直传 = 把敏感数据交给不可信的云端 LLM。本 SOP 让你的「个人标识/密钥」留在本地，只把脱敏副本送出去，分析结论不受影响（数值精度保留）。

**Q2. 脱敏后 AI 还能正常分析吗？精度会丢吗？**
A. 对绝大多数任务**基本无损**。标识符类脱敏（掩码/令牌）只去掉「真实身份」，保留数值与关系结构；财务/持仓/金额按本 SOP 原则「去标识、不扭曲数值」——只去个人标识，绝不做泛化或随机化（那才会毁掉勾稽关系与估值）。详见 `reference.md` §4。

**Q3. 工具会联网吗？我的数据会离开本机吗？**
A. 不会。`desensitize.py` 纯本地运行，正则识别与 AES 加密均在本地；`--cn-enhance` 也是本地正则、无需下载模型。只有你**主动**把 `./desensitized/` 副本发给云端模型时数据才出本机，映射表永不离开本地。

**Q4. 需要 Python 什么版本？**
A. Python ≥ 3.9。脚本无 3.13 专属语法；推荐用 uv 管理依赖（`install.py` 会优先 `uv add`，无 uv 时回退 `venv`+`pip`）。

**Q5. 脱敏后还能还原吗？用于生成工资单/申报表怎么办？**
A. `hybrid`/`token`/`mask` 模式可逆：本地用 `decrypt` 查看映射表，或 `restore` 把脱敏副本**回填**为含原值的本地内部文档（用于工资单/申报表等需实名的交付物）。回填产物恢复为实名，仅限本地使用、勿随副本外传。`redact` 模式不可逆，不要用于需还原的数据。

**Q6. 一键安装会从哪下载？离线能用吗？**
A. 默认从 `https://github.com/hzh-opc/desensitization-sop` 下载（git clone 优先，失败降级 zip）。离线/内网环境用 `python3 install.py --source local --local-path /path/to/skill` 从已下载的技能目录安装。

**Q7. 图片/加密 PDF 怎么办？**
A. 脚本不处理图片、不破解加密、不做 OCR。它们会进入 skip manifest 并明确提醒你「先本地 OCR / 先本地解密」。处理完再重跑即可。

**Q8. 支持哪些 AI 工具？**
A. 技能本体兼容 WorkBuddy / OpenClaw / Claude Code / Codex（安装器会自动定位其 `skills/` 目录并写入常驻规则）。其他支持「技能目录 + 记忆文件」的 Agent 框架，可用 `--skills-dir` / `--memory-file` 覆盖路径。

**Q9. 自动化识别会不会漏掉敏感信息？**
A. 会。尤其中文姓名/地址在无语境时易漏报。所以本 SOP 强制「人工复核 + 禁止一键脱敏即上云」，并保留 skip manifest 让你逐一对未处理文件确认。

**Q10. 卸载会删我的原始数据吗？**
A. 不会。`uninstall.py` 只删 `skills/desensitization-sop` 目录与记忆文件中的常驻规则，绝不递归父目录、不触碰任何原始敏感数据。默认 dry-run 预览，确认后才删除。

---

## 署名与许可

| 项 | 内容 |
|---|---|
| 作者 / 维护者 | hzh.opc（Huang Zenghao，由 WorkBuddy 协助整理） |
| 仓库 | https://github.com/hzh-opc/desensitization-sop |
| 版本 | v2.3 · 2026-08-15 继 v2.2 三文件拆分后：① `--mode hybrid` 设为默认（语义掩码+唯一令牌，无歧义恢复且保留字段语义）；② 放宽数字类标识符边界（身份证/手机/银行卡/IP/车牌/护照可紧邻中文识别，如「手机138…」）；③ 修复代码密钥脱敏引号残留、redact 模式误报碰撞、自定义姓名 2 字整段打码等问题 |
| 原始思路 | 《脱敏资料的处理与生成台》 |
| 许可 | 见仓库根目录 [`LICENSE`](LICENSE)（本项目采用 **Apache License 2.0**，可自由使用、修改、分发；商用须保留版权与许可声明、标注修改、附 NOTICE）；**所引用的国家标准、行业标准以主管部门官方发布文本为准** |
| 文件结构 | `SKILL.md`：自动加载的执行规范；`reference.md`：按需读取的操作详述；`README.md`：本文件（GitHub 项目说明）；`AGENT_INSTALL.md`：「让 Agent 帮你安装」指引（agent 视角，照此自动完成安装配置）；`install.py`/`install.sh`/`install.ps1`/`uninstall.py`：跨平台一键安装/卸载；`desenstool/`：一键脱敏本地脚本 `desensitize.py` + **uv 工程**（`pyproject.toml` 声明依赖，由 `uv add` 安装 `cryptography / python-docx / openpyxl / python-pptx / pdfminer.six`），数据不出本机 |

---

*本 SOP 配套技能 `desensitization-sop` 在每次 AI 任务前自动执行上云前自查、任务后自动生成审计汇总；执行规范以 `SKILL.md` 为准。*
