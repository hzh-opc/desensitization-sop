---
name: 信息脱敏上云 SOP
description: >-
  在执行任何可能接触敏感信息的任务之前（任务输入含文本/文件/数据库/知识库/代码等任一形态），
  自动检测输入是否含敏感信息（个人标识、财务/审计/投研数据、密钥 Token 等）；
  若检出 → 先本地脱敏再执行任务；若未检出 → 忽略、直接执行任务（零额外负担）。
  此外，当任务涉及将本地内容送至云端大模型（WorkBuddy 云端模型、OpenClaw、Claude、Codex、GPT 等）处理时，
  须在「上云前」自动执行脱敏自查，在「任务结束后」自动生成审计汇总。
  本文件仅含执行所必需的最小规则；判定依据、分级对照表、精度影响、工具部署等详述见同目录 reference.md（按需读取，不自动加载；GitHub 项目说明见 README.md）。
version: "2.3"
---

# 信息脱敏上云 SOP（AI Agent 上云前 / 上云后闭环）

> **版本** v2.3（2026-08-15） · **署名** hzh.opc（Huang Zenghao，由 WorkBuddy 协助整理） · **版权** Copyright 2026 hzh.opc，基于 [Apache License 2.0](LICENSE) 发布（保留声明、标注修改、附 NOTICE）。

核心方针（不可违背）：本地存储优先 · 最小必要 · 分类分级 · 脱敏后上云 · 可溯源 · 留审计 · 云端记忆禁存敏感信息。
**原始敏感文件永远留本地，绝不整份上传。**

## 触发与动作
- **触发条件 A（通用前置检测闸门）**：执行任何「任务输入可能接触敏感信息」的任务之前（输入含文本/文件/数据库/知识库/代码等任一形态），先跑一遍「输入检测闸门」；检出敏感 → 本地脱敏后继续任务，未检出 → 直接执行任务。
- **触发条件 B（上云专项，强制）**：任何把本地内容送云端模型处理之前；任务结束自动生成审计。
- **动作零（前置检测闸门）**：见下方「输入检测闸门」流程。
- **动作一（上云前，强制）**：逐项核对下方清单，任一项不通过 → **中止上云并提示用户**。
- **动作二（任务后，自动）**：向 `工作区/desensitize_audit.md` 追加审计记录（模板见下）。

## 输入检测闸门（任何任务执行前的第一步）
目标：**凡任务输入可能含敏感信息，先检测、按需脱敏，再执行任务；无敏感则直接执行，零额外负担。**
按输入形态选择检测方式（均本地、离线、数据不出本机）：
- **文本 / 聊天输入**：将待处理文本落地为临时文件后 `desensitize.py scan`；或按 reference.md §2 三级风险表快速判定。
- **文件（单文件 / 目录）**：`desensitize.py scan <文件或目录> --recursive`（支持文本/代码/Office/PDF/SQLite；图片/加密/纯图片 PDF 会进 skip manifest 并提醒）。
- **数据库 / 程序查询结果**：先在**本地**导出为文本（SQL dump / CSV / `sqlite3 .dump`），再 `scan`；切勿直接把查询结果原文外传。
- **知识库 / 网页抓取**：将抓取内容落地为文本后再 `scan`；同时遵守"云端记忆/知识库禁存敏感原文"（清单第 10 项）。

判定与分支：
- **检出敏感字段**（name/id_card/phone/bank_card/email/secret/中文 PII 等）→ 先用 `run --mode hybrid --names 姓名清单` 在**本地**生成脱敏副本（`desensitized/`）+ 加密映射表（`.desensitize_keys/`，密钥权限 600，与副本分离）；之后**用脱敏副本继续原任务**（任务若需回写实名，于本地用 `decrypt` 恢复映射表后回填，映射表永不离开本地）。
- **未检出** → 忽略，按任务原流程直接执行，不做任何脱敏。

> 闸门只做"检测 + 按需脱敏"，不阻断正常任务；自动化识别非 100%（中文尤弱），脱敏后仍需人工复核，禁止"一键脱敏即上云"。

## 动作一：上云前自查清单（11 项，逐项核对）
1. 原始敏感文件是否仍完整留本地、未整份上传？
2. 是否已逐份识别并标记敏感字段与级别（高/中/低，判定见 reference.md §2）？
3. 脱敏方法是否与级别匹配（高风险已剥离直接标识符 + 高风险准标识符）？
4. 脱敏副本是否仅来自 `工作区/desensitized/` 目录？
5. 映射表是否与副本分离、已加密（存 `工作区/.desensitize_keys/`，密钥不入库）？
6. **证券/投研**：是否扫描并拦截"内幕信息 / 未公开重大信息"？命中禁止上云。
7. **财务/审计**：是否落入"禁止输入公共 AI 平台"范围（底稿 / 涉密）？
8. **数值精度**：财务/持仓/金额是否保留精确值（仅去个人标识，未泛化/随机化）？
9. **代码**：是否检出并脱敏密钥/Token/API Key/账号密码，并经用户确认？
10. 云端记忆/知识库是否会被写入敏感原文？（必须禁存）
11. 是否需用户显式确认（拟上云的原始数据、含密钥代码等）？

> 自动化识别非 100% 召回（中文姓名/住址尤弱）：脚本已内置离线中文增强（`--cn-enhance`，识别中文姓名/地址/机构名），但中文姓名仍需语境且可能漏报/误报，脱敏后必须人工复核，禁止"一键脱敏即上云"。

## 动作二：审计汇总模板（追加到 工作区/desensitize_audit.md，不存在则创建）
```
【脱敏审计记录】
- 任务时间 / 任务描述
- 原始数据：<本地路径> | 文件数 N | 体量 X
- 敏感字段与级别：<清单摘要>
- 脱敏方法：<遮蔽/假名/令牌/抑制/泛化…>
- 映射表位置：<.desensitize_keys/ 路径，已加密>
- 上云内容：<desensitized/ 路径，仅脱敏副本>
- 上云模型：<模型名>
- 本地复核结论：<是否一致 / 差异说明>
- 精度影响评估：<无损 / 数值保留 / 已泛化需用户注意>
- 外泄风险自评：<低/中/高 + 理由>
- 操作人：<用户/AI> | 异常与待办：<若有>
```
留存：重要/核心数据相关日志 ≥ 1–3 年；建议每季度回看重评估。

## 一键脱敏本地脚本（上云前执行脱敏的可调用工具）
位置：`~/.workbuddy/skills/desensitization-sop/desenstool/desensitize.py`，配套 `desenstool/` 是一个 **uv 工程**（`pyproject.toml` 声明依赖），由 `uv add` 创建虚拟环境（`.venv`）并安装 `cryptography / python-docx / openpyxl / python-pptx / pdfminer.six`，**数据全程不出本机**。

调用（任选其一）：
- 可靠（离线，推荐）：`~/.workbuddy/skills/desensitization-sop/desenstool/.venv/bin/python ~/.workbuddy/skills/desensitization-sop/desenstool/desensitize.py scan|run|restore|audit|decrypt <输入> [--out ./desensitized --keys ./.desensitize_keys --mode hybrid|mask|token|redact --recursive --names 姓名清单.txt --cn-enhance]`
- 或用 uv：`uv run --project ~/.workbuddy/skills/desensitization-sop/desenstool python ~/.workbuddy/skills/desensitization-sop/desenstool/desensitize.py ...`

要点：
- `scan`：仅报告命中（不生成文件），用于上云前自查"有哪些敏感字段"。
- `run`：生成脱敏副本到 `--out`（默认 `./desensitized`，**该目录文件才可上云**）；加密映射表到 `--keys`（默认 `./.desensitize_keys`，含 `*.key` 密钥文件，权限 600，**绝不随副本上传**）。
- `--mode`（默认 `hybrid`）：`mask`（掩码，可逆）/ `token`（令牌化，可逆且跨记录可关联）/ `hybrid`（语义掩码+唯一令牌，可逆、**无歧义恢复且保留字段语义**，SOP 主线默认）/ `redact`（抑制，不可逆）。
- `decrypt`：本地解密映射表以供复核可逆性（`decrypt --keys ./.desensitize_keys [--out 明细.json]`，无需上云）。
- `restore`：本地用映射表把脱敏副本**回填**为含原值的内部文档（`restore --keys ./.desensitize_keys --input ./desensitized --out ./restored [--types name,id_card]`），用于生成工资单/申报表等需实名的交付物；映射表不离本地，回填产物为本地内部文档、勿随副本外传；token 模式请勿用于含同名串的数据。
- `audit`：基于 `run` 生成的 `desensitize_report.json` **自动生成 11 项审计文档**（`audit --report ./desensitize_report.json --out ./desensitize_audit.md`），覆盖数据盘点、分级、脱敏方法、密钥分离、上云内容、复核结论、skip manifest、风险自评，省去手工填模板。
- 内置中文正则：身份证、手机号、银行卡、邮箱、IP、车牌、护照；代码文件（.py/.env 等）自动脱敏 `API_KEY/secret/token/password` 等密钥。
- **`--cn-enhance`（中文识别增强，纯本地离线）**：额外识别**中文姓名 / 中文地址 / 中文机构名**。姓名需带语境（标签词如"姓名/客户/借款人"或称谓如"先生/女士"或冒号/标点），以抑制中文文本极高误报率；机构名/地址按后缀特征匹配。仍建议人工复核。
- 可逆性：mask/token 的原始值仅存于**本地加密映射表**，可用密钥解密还原做本地复核。

## 支持的信息源与上云前注意事项
脚本对以下信息源形态均能抽取文本后脱敏：文本/代码（.txt/.md/.csv/.json/.xml/.html/.log/.rst/.eml/.py/.sql 等）、Office（.docx/.xlsx/.pptx，需装 python-docx/openpyxl/python-pptx）、PDF（pdfminer.six）、SQLite（.db，内置 sqlite3）。

**以下形态脚本不直接处理，会在扫描/脱敏末尾输出 skip manifest（未处理清单）并给出明确可执行提醒，绝不会静默放过：**
- **影像 / 图片（.png/.jpg/.jpeg/.gif/.bmp/.tiff/.webp/.heic 等）**：脚本不做 OCR。须提醒用户在**本地用 OCR 将图片转为文本（.txt/.md）后再纳入**脱敏；原始图片不会被处理。
- **纯图片型 / 扫描件 PDF（无文本层）**：pdfminer 仅能提取文本层，抽到空文本即识别并提醒"先本地 OCR 转文本"，**不再误判为已覆盖**（旧版曾有静默假阴性，已修复）。
- **加密文档（加密 PDF / 加密 Office 等）**：抽取会失败，脚本提醒"先在本地解密后再纳入脱敏（解密后重跑）"，不会崩溃、不会静默放过。
- **其他未知二进制**：提醒"若含敏感文本请先转为文本文件（或 OCR/解密）后再纳入"。

> 红线重申：脱敏副本可上云，原始文件与映射表（重识别钥匙）留本地且分离；自动化识别非 100%，**禁止"一键脱敏即上云"，必须人工复核** skip manifest 中列出的未处理文件。

## 判定与方法的快速索引（详述见同目录 reference.md，按需 Read）
- 输入检测闸门（任务执行前通用前置，按输入形态检测 + 分支决策）：reference.md §0
- 关键概念（去标识化 vs 匿名化、准标识符重识别）：reference.md §1
- 三级风险判定表、准标识符聚合风险处理：reference.md §2
- 六步脱敏流程、映射表安全条款：reference.md §3
- 精度影响（"去标识不扭曲数值"）+ 方法对照表：reference.md §4
- 财务/审计/投研/代码场景专项要求：reference.md §5
- 工具选型（Presidio 本地部署、中文正则、AES 加密）、技术五族、静态/动态脱敏：reference.md §6
- 应急与改进、附录（直接标识符/敏感个人信息速查）：reference.md §7
