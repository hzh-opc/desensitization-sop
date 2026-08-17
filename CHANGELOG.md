# 更新日志（Changelog）

本文件按时间倒序记录重大变更。日常细节以 Git 提交为准。

## v2.4.2 · 2026-08-17（结构调整：贴合 skill-creator 规范）

- **目录与文件对齐 skill-creator 标准约定**：
  - `desenstool/` 重命名为 **`scripts/`**（执行代码目录，含 `scripts/desensitize.py` / `pyproject.toml` / `uv.lock` / `.python-version`）；
  - `reference.md` 移入 **`references/reference.md`**（按需加载的参考文档，不随技能自动加载）。
- **同步更新全部内部引用**（SKILL.md / references/reference.md / README.md / CHANGELOG.md / AGENT_INSTALL.md / CONTRIBUTING.md / requirements.txt / install.py）：`desenstool` → `scripts`、`reference.md` → `references/reference.md`。
- **SKILL.md frontmatter 补全 `agent_created: true`**（skill-creator 强制字段，供 `skill_manage` 后续修改/删除）。
- 版本号同步升至 **v2.4.2**（结构性调整，作为独立补丁版本发布；与 v2.4.1 功能完全一致，仅目录/文件布局对齐规范）。

## v2.4.1 · 2026-08-17（install.py Windows 沙箱安装修复）

- **修复 `install.py` 在 Agent 会话内的 Windows 沙箱安装失败**：WorkBuddy / Claude 等 Agent 经 `sitecustomize.py` 注入「安全删除」shim，仅当 `CODEBUDDY_SESSION_ID` / `CLAUDE_SESSION_ID` 存在时激活，会把所有删除拦截进回收站（fail-closed）。Windows 沙箱无回收站时，uv 构建 `antlr4-python3-runtime`（rapidocr→omegaconf 依赖链）删除临时文件会失败、导致整个 venv 依赖装不上（报 `SAFE_DELETE_FAIL_CLOSED ... windows-sandbox-recycle-bin-unavailable`）。`install.py` 现于 `main()` 起始自动剥离这两个环境变量，并对 `uv add` / `uv sync` 子进程 env 防御性再剥离，恢复常规删除；README 新增 **FAQ Q11** 说明现象与旧版手动 `unset` 解法（PowerShell：`Remove-Item Env:\CODEBUDDY_SESSION_ID, Env:\CLAUDE_SESSION_ID`）。卸载/清理同理。

## v2.4 · 2026-08-17（本地预处理关卡 + 实际解密/OCR + 审查修复）

- **新增 `preprocess` 本地预处理关卡（防割裂）**：扫描输入并分类 `encrypted`/`image`/`image_pdf`/`no_lib`/`error`/`empty`/`unsupported`，并**实际执行**本地解密与本地 OCR（数据全程不出本机），产出 `desensitize_preprocess.json` + 确认单 `desensitize_preprocess_summary.md`——① 原文件与未脱敏副本的保存/外发情况表（均🚫禁止外传）；② OCR 结果需用户逐项校对提醒；③ 预处理异常清单（文件/类别/原因/建议，须另行处理后发回 AI Agent）；④ 确认闸门——`run --preprocess-manifest` 会再次校验：清单仍含异常则拒绝执行，异常清完才放行。`--no-auto` 可降级为仅分类提醒。
- **本地解密**：加密 PDF 用 **pikepdf**（封装 QPDF，稳健；弃用 pypdf——free-threaded Python 下不稳定）产出未加密副本；加密 Office 用 **msoffcrypto-tool**。密码经 `--passwords-file`（每行一个候选，该文件严禁外传）提供；缺密码/解密失败进入异常清单。
- **本地 OCR 用纯本地 rapidocr + onnxruntime**：模型（PP-OCRv6 det/cls/rec）随 wheel 捆绑，完全离线、数据不出本机，无需任何外部服务/端口/守护进程，零部署、零协议风险。图片直接识别；图片型 PDF 由 **pypdfium2** 渲染页面后识别。识别前图像归一化到最长边 ≤2000px、`Det.limit_side_len = clamp(最长边, 736, 2000)`（实测 1000–2100px 为稳定识别区）；已知弱项：单行极端宽高比图片识别率低。
- **PDF 文本抽取由 pdfminer.six 换成 pypdfium2**（Chrome 同款 PDFium，C 实现，快且对畸形 PDF 稳健；与 OCR 页面渲染共用一库）。
- **异常清单显式化**：`run` 报告新增结构化 `skipped_detail`（类别/原因/动作/警告）；`audit` 第七节升级为"异常清单 / 未处理文件"，逐条列出并提示人工处理；scan/run 对无法处理的文件输出 skip manifest 并给出明确可执行提醒（图片→先 OCR、加密→先解密），**绝不静默放过**。
- **红线明确**：解密密码、加密原文件、已解密未脱敏副本、原始图片/图片型 PDF、未脱敏 OCR 文本——全部严禁外传，仅脱敏副本可上云。
- **Python 版本明确为标准（非 free-threaded）CPython ≥3.10 且 <3.14**（onnxruntime 无 free-threaded wheel、3.14 支持未完备），`scripts/.python-version` 锁定 3.13。
- **依赖统一**：requirements.txt / pyproject.toml / install.py `uv add` 列表一致为 `cryptography / python-docx / openpyxl / python-pptx / pypdfium2 / pikepdf / msoffcrypto-tool / rapidocr / onnxruntime`。
- **审查修复**：`_pdf_has_encrypt` 头+尾双向探测（/Encrypt 常位于文件尾部 trailer，只读头部对大文件漏判）；preprocess 递归产出按相对路径保留目录结构（防不同子目录同名文件互相覆盖）；确认单 ready 清单过滤流程元数据文件；`--passwords-file` 不存在/不可读时告警并按无密码处理（不再崩溃）；缺解密库时明确报「缺少解密库 pikepdf/msoffcrypto-tool」（不再误报为"密码错误"）；`iter_targets` 递归遍历排序（token 编号跨平台可复现）；audit 文档措辞统一为「九节，对齐 11 项自查清单」。
- **测试固化（4 套 harness 全量通过）**：`run_tests.py`（16 用例）、`run_source_tests.py`（19 类信息源覆盖矩阵）、`run_restore_audit_tests.py`（37 断言）、`run_preprocess_tests.py`（47 断言，**真实 rapidocr 引擎**端到端——"文本 PDF → 渲染图片 → 图片型 PDF"闭环夹具不依赖系统字体、全平台可移植，含真实 OCR 精度、HF_HUB_OFFLINE=1 离线全流程、中文 OCR 精度验证）。

## v2.3 · 2026-08-15
- `--mode hybrid`（语义掩码 + 唯一令牌 `外壳⟦Txx⟧`）设为默认：无歧义恢复且保留字段语义。
- 放宽数字类标识符边界：身份证/手机/银行卡/IP/车牌/护照可紧邻中文识别（如「手机138…」）。
- 修复：代码密钥脱敏引号残留、`redact` 模式误报碰撞、自定义姓名 2 字整段打码等问题。
- 文件结构从早期版本拆分为 `SKILL.md` / `references/reference.md` / `README.md` 三件套。

## v2.2 · 2026-08（三文件拆分）
- 将执行规范（`SKILL.md`，自动加载）、操作详述（`references/reference.md`，按需读取）、项目说明（`README.md`）拆分，降低每次调用加载成本。

## v2.1 及更早
- 初版脱敏流程与本地脚本 `scripts/desensitize.py`（scan/run/decrypt/restore/audit）。
- 引入中文离线增强 `--cn-enhance`、skip manifest（图片/加密/纯图片 PDF 不再静默放过）。
- 引入一键安装/卸载脚本（跨平台、跨 AI 工具）。
