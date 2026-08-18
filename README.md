# 信息脱敏上云 SOP（AI Agent 上云前 / 上云后闭环）

![License](https://img.shields.io/github/license/hzh-opc/desensitization-sop?style=flat-square)
![Release](https://img.shields.io/github/v/release/hzh-opc/desensitization-sop?style=flat-square)
![Python](https://img.shields.io/badge/python-%3E%3D3.9-blue?style=flat-square)

> **一句话**：当你用 WorkBuddy / Claude / Codex / GPT 等云端大模型处理本地文本、文件、数据库、代码时，本 SOP 与配套技能帮你 **先把敏感信息在本地脱敏、只把脱敏副本上云**，且全过程可溯源、留审计、可本地复核。
>
> **配套技能**：`desensitization-sop`（WorkBuddy 技能，自动执行「上云前自查」与「任务后审计汇总」）
> **本仓库三份文件分工**：
> - `SKILL.md`：**自动加载的执行规范**（12 项上云前自查 + 审计模板），AI Agent 每次调用必走；
> - `references/reference.md`：**按需读取的操作详述**（合规依据、分级判定、六步流程、精度影响、场景专项、工具选型、脚本说明、附录），不自动加载；
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
| 代码密钥扫描 | 账号/密码/API Key/Token/私钥自动扫描与脱敏确认；另识别 **JWT**、**HTML 内嵌密钥**、**SQL INSERT 位置参数口令**（按口令列名定位 VALUES 值）；docx 表格 / xlsx 批注 / GBK 编码文件均已纳入抽取（自动探测 GB18030，中文不乱码） |
| 清洗建议 | 针对小微业务随意填写：检测分隔/短位手机号、15 位旧身份证、订单号与银行卡区间重叠等**疑似未清洗形态**并输出 `⚠清洗建议`（scan 控制台 + run 报告 `cleaning_advice`）——**只提醒、不自动改**（fail-safe），提示先做字段级数据清洗再脱敏 |
| 生僻字/特殊字符优先 mask | 待脱敏信息含**生僻字**（CJK 扩展区/兼容区，如「㐀」）或**特殊字符**（emoji、符号等非常见字符）时，脚本**优先全掩码**（`*`），不保留含此类字符的首字/尾字（避免保留高识别度生僻字或破坏格式的特殊字符）；替换值一律用常见字符。**边界**：CJK 基本区内罕见字（如「爨」「龘」）不在自动判定范围，需人工复核 |
| 用户自定义脱敏映射 | `--mapping <文件>` 接受用户指定的「原始值→替换值」映射（JSON 或文本 `原始值=替换值`），**主动精确匹配**并替换为用户指定值（独立于识别正则，用户指定即视为需脱敏）；命中结果随加密映射表 `.desensitize_keys/` **本地加密保存、绝不外发**，可 `decrypt` 复核、`restore` 回填。⚠ 映射文件含敏感信息（原始值），严禁外传、仅本地使用 |
| 任务后审计 | 自动生成审计汇总（九节，对齐 12 项自查清单；追加至 `desensitize_audit.md`） |
| 显式声明豁免 | 默认全脱敏；仅当用户显式声明（提示词 `--assume-public` / 指定文件·文件夹 `--public-paths` / `.nodesens` 伴随清单）才跳过，且强制留痕（含 size/sha256）+ "请确认公开"警示；**不做文件名隐式推断**（sample/demo 等不再触发）；scan 仍检测豁免文件并告警。**不再自动识别并豁免公开主体**（上市公司亦有未公开信息，自动豁免易错漏） |
| 本地处理·无需外发豁免 | 仅本地处理、无需外发的信息（数据不出本机；或云端取「方法」本地处理「数据」）**不脱敏**——省工作量、免精度损失。三条护栏：合理访问权限 / 无外泄风险 / **不得与外发脱敏副本一起存放**（工作区自动隔离到 `07_本地处理不外发/`🚫）。**豁免以「不外发」为前提：本地处理中追加/生成的数据如需外发，须重新检验脱敏（外发即失效；多次外发每次检测+记录，已脱敏沿用原记录、未脱敏补充记录再外发）**。工具 `--local-only`（整体）/ `--local-paths`（指定路径），留痕 + 警示，绝不静默；与 `--assume-public`（公开可上云）严格区分 |
| 统一成果中心（工作区） | 各阶段加 `--workspace <目录>` 后，全部产物归拢到一处、用**清晰中文目录**命名（`03_脱敏副本/`✅可上云、`02_未脱敏副本/`🚫、`04_映射表_保密/`🚫、`06_审计与回填/`、`07_本地处理不外发/`🚫 等）；`run` 自动生成 `05_上云前自检报告.md`（OCR 副本 / 脱敏副本 / 本地不外发 / 公开豁免留痕**四处校对 + 确认闸门**）与 `成果索引`（可上云/保密/不外发标签）；`status --workspace <目录>` 随时回显索引。专为非专业人员设计，**不带 `--workspace` 则完全保持原默认行为**（向后兼容） |

---

## 快速上手

```bash
# 1) 扫描：看看本地文件里有哪些敏感字段（不生成任何文件）
python scripts/desensitize.py scan ./data/ --recursive

# 2) 脱敏：生成脱敏副本 + 加密映射表（默认 hybrid 模式）
python scripts/desensitize.py run ./data/ \
    --out ./desensitized --keys ./.desensitize_keys --mode hybrid

# 💡 推荐（非专业人员）：加 --workspace 把全部产物归拢到一处，并自动生成
#    《上云前自检报告》与《成果索引》，上云前一站式核对：
python scripts/desensitize.py run ./data/ --workspace ./工作区 --mode hybrid
#   → 产物在 ./工作区/（03_脱敏副本/ ✅可上云；05_上云前自检报告.md 上云前必读）
#   → 随时查看：python scripts/desensitize.py status --workspace ./工作区

# 3) 上云：只把脱敏副本（./desensitized 或 ./工作区/03_脱敏副本/）发给大模型；
#    映射表（.desensitize_keys / ./工作区/04_映射表_保密/）永不外传
# 4) 任务后审计（基于 run 报告自动生成审计文档：九节，对齐 12 项自查清单）
python scripts/desensitize.py audit --report ./desensitize_report.json

# 5) 本地复核 / 回填：用映射表解密或还原实名（均在本地，无需上云）
python scripts/desensitize.py decrypt --keys ./.desensitize_keys
python scripts/desensitize.py restore --keys ./.desensitize_keys --input ./desensitized --out ./restored
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
python /tmp/desensitization-sop/scripts/desensitize.py scan --help
```

> 若当前 AI 工具已运行，安装完成后请按 Agent 提示**重启它（或重开会话）**以加载 `desensitization-sop`。

## 一键安装（跨平台 / 跨 AI 工具）

仓库内置 `install.py`（纯标准库，无第三方依赖），支持 **Windows / macOS / Linux**，并自动适配 **WorkBuddy / OpenClaw / Claude Code / Codex**：

| 步骤 | 动作 |
|---|---|
| 1 | 自动检测当前 AI 工具，定位其 `skills/` 目录与记忆/指令文件 |
| 2 | 从 GitHub（`https://github.com/hzh-opc/desensitization-sop`）下载并安装技能（git 优先，失败自动降级 zip；亦支持 `--source local` 离线安装） |
| 3 | 自动检测 / 创建 Python 虚拟环境（`scripts/.venv`）并安装依赖（**优先 `uv add`**；无 uv 时回退 `venv`+`pip`） |
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

## 升级（手动 · 安全零停机）

技能自带 `upgrade.py`（纯标准库，无第三方依赖），与 `install.py` 同范式（自动检测 AI 工具、定位 `skills/` 目录、从 GitHub 下载、构建 venv、全环实测），并叠加**安全零停机**流程，防止"升级失败导致技能无法调用"：

| 安全阶段 | 说明 |
|---|---|
| 1. 下载到暂存区 | 新版本先下载到与线上技能**同一文件系统**的暂存目录；线上技能原封不动、始终可调用 |
| 2. 校验无误 | 在暂存副本上构建 venv 并跑通 `scan → run → decrypt → restore` 全环实测；任一不过 → **拒绝替换**，线上技能保持不变 |
| 3. 备份 + 原子替换 | 替换前把当前线上技能改名备份（不删除）；再以原子 `rename` 把暂存新版本落到线上 |
| 4. 替换后再实测 | 对线上技能再跑一轮全环实测；失败 → **自动回滚**到备份 |

> **手动触发**：升级**默认不自动运行**，由你 / AI Agent 显式调用（仅在用户明确要求升级时执行，绝不在技能加载时自动升级）。

### 运行方式

```bash
# macOS / Linux
./upgrade.sh
# 或 python3 upgrade.py

# Windows (PowerShell)
.\upgrade.ps1
# 或 py upgrade.py
```

### 常用参数

```bash
python3 upgrade.py                         # 检查更新；有则 下载→校验→应用
python3 upgrade.py --check                 # 仅检查是否有更新（不下载/不应用）
python3 upgrade.py --dry-run               # 下载+校验，但不替换（最安全试跑）
python3 upgrade.py --force                 # 即使版本相同也强制重装（用于修复）
python3 upgrade.py --source local --local-path /path/to/skill  # 离线/本地源升级
python3 upgrade.py --clean-backup          # 清理历史备份目录
```

> 退出码 `0` = 成功 / 已是最新；`1` = 升级失败（已回滚或根本未触碰线上）；`2` = 下载失败；`3` = 参数错误。
> 升级完成后，按工具提示**重启 / 重载 AI 工具**以加载新技能。

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
| `SKILL.md` | **AI Agent 自动加载**：执行规范、12 项上云前自查清单、审计模板、脚本调用入口 |
| `references/reference.md` | 边界场景按需 `Read`：合规依据、三级风险判定、准标识符重识别、六步流程、精度影响对照、场景专项、工具选型、脚本完整说明、附录 |

`references/reference.md` 章节索引：目标与原则 · 背景与原思路修订 · 合规依据（引用来源）· §0 输入检测闸门 · §1 关键概念 · §2 敏感信息分类分级 · §3 脱敏操作流程（六步）· §4 脱敏对 AI 任务精度的影响 · §5 场景专项要求 · §6 工具与技术选型 · 配套一键脱敏本地脚本 · §7 应急、改进与附录。

---

## 能力边界与重要声明（必读）

> **红线**：脱敏副本可上云，原始文件与映射表（重识别钥匙）留本地且分离；**密码、加密原文件、已解密未脱敏副本、原始图片 / OCR 文本同样严禁外传**；自动化识别非 100%，**禁止「一键脱敏即上云」，必须人工复核**预处理关卡与 skip manifest 中列出的未处理文件。

1. **自动化识别非 100% 召回（尤其中文姓名/住址）**，脱敏后必须人工复核。脚本内置离线中文增强（`--cn-enhance`），但仍可能漏报/误报（如「赵钱孙先生」可能误识为姓名、「北京大学」可能误识为机构）。
2. **加密文档、图片 / 图片型 PDF 等"需前置处理"的形态，由 `preprocess`（本地预处理关卡，v2.4 起**实际解密 / OCR**）统一处理并汇入确认单，绝不会静默放过**：
   - 影像/图片（.png/.jpg/…）：`preprocess` 用本地 **rapidocr + onnxruntime**（纯 pip 安装，模型随 wheel 捆绑，**完全离线**）识别为文本并落盘到 `ocr/`（**未脱敏、须校对**），确认单给出「不得外传」与校对提醒；OCR 库缺失时该项进入异常清单，由用户本地处理后发回；
   - 纯图片型/扫描件 PDF（无文本层）：pypdfium2 抽到空文本即识别为 `image_pdf`，`preprocess` 同样走本地 rapidocr（pypdfium2 渲染页面后识别；不再误判为已覆盖）；
   - 加密文档（加密 PDF / 加密 Office）：`preprocess` 用 **pikepdf / msoffcrypto-tool** 在**本地**解密，产出未加密副本到 `ready/`；缺密码/非标加密则进入异常清单，由用户本地处理后发回；
   - 其他未知二进制 / 抽取异常：归为异常清单，须逐条人工处理，防止后续流程跳过。
3. **可逆脱敏 ≠ 匿名化**：本 SOP 的本地映射表方案属于「去标识化」，在法律上**仍是个人信息**；映射表/密钥一旦与副本同泄，等于原始数据泄露，故必须分离、加密、最小权限。
4. **本 SOP 为可落地操作规范，非法律意见**。具体合规要求请以 PIPL、数据安全法及主管部门最新规定为准。

---

## 常见问题（FAQ）

**Q1. 这不是多此一举？我直接把数据发给 AI 不就行了？**
A. 本地文件可能含身份证号、手机号、银行卡、密钥 Token、财务报表等敏感信息。直传 = 把敏感数据交给不可信的云端 LLM。本 SOP 让你的「个人标识/密钥」留在本地，只把脱敏副本送出去，分析结论不受影响（数值精度保留）。

**Q2. 脱敏后 AI 还能正常分析吗？精度会丢吗？**
A. 对绝大多数任务**基本无损**。标识符类脱敏（掩码/令牌）只去掉「真实身份」，保留数值与关系结构；财务/持仓/金额按本 SOP 原则「去标识、不扭曲数值」——只去个人标识，绝不做泛化或随机化（那才会毁掉勾稽关系与估值）。详见 `references/reference.md` §4。

**Q3. 工具会联网吗？我的数据会离开本机吗？**
A. 不会。`desensitize.py` 纯本地运行，正则识别与 AES 加密均在本地；`--cn-enhance` 也是本地正则、无需下载模型。只有你**主动**把 `./desensitized/` 副本发给云端模型时数据才出本机，映射表永不离开本地。

**Q4. 需要 Python 什么版本？**
A. 标准（非 free-threaded）CPython **≥ 3.10 且 < 3.14**（onnxruntime 无 free-threaded wheel、3.14 支持未完备；`scripts/.python-version` 锁定 3.13）。推荐用 uv 管理依赖（`install.py` 会优先 `uv add`，无 uv 时回退 `venv`+`pip`）。

**Q5. 脱敏后还能还原吗？用于生成工资单/申报表怎么办？**
A. `hybrid`/`token`/`mask` 模式可逆：本地用 `decrypt` 查看映射表，或 `restore` 把脱敏副本**回填**为含原值的本地内部文档（用于工资单/申报表等需实名的交付物）。回填产物恢复为实名，仅限本地使用、勿随副本外传。`redact` 模式不可逆，不要用于需还原的数据。

**Q6. 一键安装会从哪下载？离线能用吗？**
A. 默认从 `https://github.com/hzh-opc/desensitization-sop` 下载（git clone 优先，失败降级 zip）。离线/内网环境用 `python3 install.py --source local --local-path /path/to/skill` 从已下载的技能目录安装。

**Q7. 图片 / 加密 PDF 怎么办？**
A. v2.4 起 `preprocess` **自动处理**：加密文档用 pikepdf / msoffcrypto-tool 在**本地**解密（密码通过 `--passwords-file` 提供，该文件本身严禁外传），图片 / 图片型 PDF 用本地 **rapidocr + onnxruntime**（纯 pip 安装、模型随 wheel 捆绑、**完全离线**，无需任何外部服务）识别为文本并落盘到 `ocr/`（**未脱敏、须你逐字校对**）。`preprocess` 会生成**确认单**（`desensitize_preprocess_summary.md`）：① 列出原始文件与未脱敏副本的保存/外发情况（均🚫禁止外传）；② 列出 OCR 文件供你校对；③ 详细列出预处理异常；④ 你确认无误后，带 `--preprocess-manifest` 跑 `run` 才会放行（异常未清则拒绝）。

**Q8. 支持哪些 AI 工具？**
A. 技能本体兼容 WorkBuddy / OpenClaw / Claude Code / Codex（安装器会自动定位其 `skills/` 目录并写入常驻规则）。其他支持「技能目录 + 记忆文件」的 Agent 框架，可用 `--skills-dir` / `--memory-file` 覆盖路径。

**Q9. 自动化识别会不会漏掉敏感信息？**
A. 会。尤其中文姓名/地址在无语境时易漏报。所以本 SOP 强制「人工复核 + 禁止一键脱敏即上云」，并保留 skip manifest 让你逐一对未处理文件确认。

**Q10. 卸载会删我的原始数据吗？**
A. 不会。`uninstall.py` 只删 `skills/desensitization-sop` 目录与记忆文件中的常驻规则，绝不递归父目录、不触碰任何原始敏感数据。默认 dry-run 预览，确认后才删除。

**Q11. Windows 上 `uv add` 报 `SAFE_DELETE_FAIL_CLOSED ... windows-sandbox-recycle-bin-unavailable` 怎么办？**
A. 这是在 **Agent 会话内**跑 `install.py` 时才会遇到的环境问题，不是技能本身的 bug。WorkBuddy / Claude 等 Agent 会在 Python 启动时经 `sitecustomize.py` 注入「安全删除」shim：`CODEBUDDY_SESSION_ID` / `CLAUDE_SESSION_ID` 存在时，所有删除被拦截进回收站（fail-closed）。Windows 沙箱无回收站，uv 构建 wheel（如 `rapidocr → omegaconf → antlr4-python3-runtime`）删除临时文件就会失败、导致整个 venv 依赖装不上。**新版 `install.py` 已自动剥离这两个环境变量**，一般无需手动处理；若你用的是尚未含此修复的旧版，手动 `unset CODEBUDDY_SESSION_ID CLAUDE_SESSION_ID`（PowerShell：`Remove-Item Env:\CODEBUDDY_SESSION_ID, Env:\CLAUDE_SESSION_ID`）后再跑即可，卸载/清理同理。

---

## 署名与许可

| 项 | 内容 |
|---|---|
| 作者 / 维护者 | hzh.opc（Huang Zenghao，由 WorkBuddy 协助整理） |
| 仓库 | https://github.com/hzh-opc/desensitization-sop |
| 版本 | v2.6.0 · 2026-08-18 **新增「本地处理·无需外发豁免」**：仅本地处理、无需外发的信息（数据不出本机；或云端取「方法」本地处理「数据」）**不脱敏**——省工作量、免精度损失。三条护栏：合理访问权限 / 无外泄风险 / **不得与外发脱敏副本一起存放**（工作区自动隔离到 `07_本地处理不外发/`🚫）；**豁免以「不外发」为前提——本地处理中追加/生成的数据如需外发须重新检验脱敏（外发即失效；多次外发每次检测+记录，已脱敏沿用原记录、未脱敏补充记录再外发）**。工具新增 `--local-only`（整体声明）/ `--local-paths`（指定文件·文件夹），报告留痕（含 size/sha256）+ 警示，**本地处理优先于公开**、scan 仍检测（fail-safe）。上云前自查清单 11 项→12 项、自检报告三处校对→四处校对。修复 `import hashlib` 缺失导致豁免留痕 sha256 恒为 None 的既有缺陷。另：**生僻字/特殊字符优先 mask**（含生僻字（CJK 扩展区/兼容区）或特殊字符（emoji 等非常见字符）的字段全掩码、不保留首字/尾字，替换值用常见字符；基本区罕见字需人工复核）；**用户自定义脱敏映射 `--mapping`**（用户指定「原始值→替换值」，主动精确替换、加密入库不外发） |
| 版本 | v2.5.0 · 2026-08-18 ① **移除"公开主体白名单自动豁免"与文件名/目录名哨兵词隐式推断**（`sample`/`demo`/`pub` 等常见命名、"公开"子串、`.public_root` 会被误判为公开而跳过脱敏，违反 fail-safe）；② 改为**显式声明豁免**：默认全脱敏，仅当用户显式声明（提示词 `--assume-public` / 指定文件·文件夹 `--public-paths` / 伴随清单 `.nodesens`·`desensitize_manifest.json`）才跳过，且强制留痕（含 size/sha256）+ "请确认公开"警示，绝不静默跳过；③ **新增统一成果中心（工作区）**：各阶段加 `--workspace` 后产物归拢一处、中文目录命名（`03_脱敏副本/`✅可上云 / `02_未脱敏副本/`🚫 / `04_映射表_保密/`🚫 等），`run` 生成 `05_上云前自检报告.md`（OCR/脱敏/豁免留痕四处校对+确认闸门），`status` 随时回显索引；④ **新增 `upgrade.py`/`upgrade.sh`/`upgrade.ps1` 手动安全升级**（暂存→校验→备份→原子替换→回滚，零停机，绝不自动运行）；⑤ **新增「先清洗再脱敏」提醒机制**（分隔/短位手机、15 位旧证、订单号与银行卡区间重叠等仅提醒不自动改）；⑥ 修复 docx 表格 / xlsx 批注 / GBK 编码 / JWT / HTML 内嵌密钥 / SQL INSERT 位置参数口令等抽取盲区 |
| 版本 | v2.4.2 · 2026-08-17 ① 目录/文件布局对齐 skill-creator 规范：`desenstool/`→`scripts/`、`reference.md`→`references/reference.md`、SKILL.md 补全 `agent_created: true`；② 功能与 v2.4 一致（`preprocess` 本地预处理关卡：自动解密加密文档（pikepdf / msoffcrypto-tool）+ 纯本地 OCR（rapidocr + onnxruntime，模型随 wheel 捆绑、完全离线），产出确认单（保存/外发清单、OCR 校对提醒、异常清单、run 闸门）；③ PDF 文本抽取由 pdfminer.six 换成 **pypdfium2**（与 OCR 渲染共用一库）；④ Python 版本明确为标准 CPython ≥3.10 且 <3.14；⑤ 全量回归测试通过（详见 `CHANGELOG.md`） |
| 原始思路 | 《脱敏资料的处理与生成台》 |
| 许可 | 见仓库根目录 [`LICENSE`](LICENSE)（本项目采用 **Apache License 2.0**，可自由使用、修改、分发；商用须保留版权与许可声明、标注修改、附 NOTICE）；**所引用的国家标准、行业标准以主管部门官方发布文本为准** |
| 文件结构 | `SKILL.md`：自动加载的执行规范；`references/reference.md`：按需读取的操作详述；`README.md`：本文件（GitHub 项目说明）；`AGENT_INSTALL.md`：「让 Agent 帮你安装」指引（agent 视角，照此自动完成安装配置）；`VERSION`：版本唯一来源（install / upgrade 共用）；`install.py`/`install.sh`/`install.ps1`/`uninstall.py`/`upgrade.py`/`upgrade.sh`/`upgrade.ps1`：跨平台一键安装 / 卸载 / **手动安全升级**；`scripts/`：一键脱敏本地脚本 `desensitize.py` + **uv 工程**（`pyproject.toml` 声明依赖，由 `uv add` 安装 `cryptography / python-docx / openpyxl / python-pptx / pypdfium2 / pikepdf / msoffcrypto-tool / rapidocr / onnxruntime`），数据不出本机 |

---

*本 SOP 配套技能 `desensitization-sop` 在每次 AI 任务前自动执行上云前自查、任务后自动生成审计汇总；执行规范以 `SKILL.md` 为准。*
