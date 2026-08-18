# 更新日志（Changelog）

本文件按时间倒序记录重大变更。日常细节以 Git 提交为准。

## v2.5.0 · 2026-08-18（显式声明豁免 + 统一成果中心 + 测试驱动修复）

- **移除"公开主体白名单自动豁免"**：用户反馈白名单维护工作量大、易错漏，且上市公司也有未公开/内幕信息，自动豁免公开主体本身存在错漏风险。故彻底移除该机制（v2.4.2 基座上重新实现）。
- **改为"显式声明豁免"**：**默认全脱敏，仅当用户显式声明时才跳过**——把判断负担交给最懂上下文的用户，工具只忠实执行声明。三种形式：
  1. 提示词声明（AI Agent 在 §0 闸门识别，工具侧 `--assume-public`，整体声明）；
  2. **指定文件 / 文件夹声明（推荐，非专业人员最常用）**：用户指明"文件夹 X 全部 / 其中 a.xlsx 无需脱敏"，Agent 转 `--public-paths <路径>...`（文件夹=其下全部递归、文件=该文件），仅本次任务生效、不落盘为永久设置；
  3. 伴随清单（`.nodesens` / `desensitize_manifest.json`，或 `--public-manifest <文件>`）——重复使用的高级选项。
- **不再做文件名隐式推断**：移除文件名 / 目录名哨兵词（`pub`/`public`/`sample`/`synthetic`/`demo`）与中文子串（`公开`/`无需脱敏`），以及隐藏文件 `.public_root`——这些常见命名/子串会被误判为公开而跳过脱敏（如 `sample.txt`、`公开招标客户名单.xlsx`），违反 fail-safe 原则。豁免仅来自用户明确声明（`--assume-public` / `--public-paths` / 伴随清单）。
- **安全补丁（贯穿所有形式，绝不静默跳过）**：被声明豁免的文件一律进「跳过清单」，在控制台与 `desensitize_report.json` 明确告警"请确认确为公开信息"，并附带 **size / sha256** 供外发前核对，强制留痕 + 二次确认，杜绝误声明导致泄露。**scan 仍检测**：被声明豁免的文件在扫描时仍检测并报告命中，若发现疑似敏感内容追加"⚠ 你声明为公开，但检出疑似敏感，请复核"提醒（fail-safe 不反转）。**会话级一次性**：除高级伴随清单外，声明默认只对本轮对话生效，不变成永久设置。上市公司未公开信息红线不改（默认全脱）。
- **新增参数**：`scan`/`run` 增加 `--assume-public`、`--public-paths`（nargs+）、`--public-manifest`。
- **新增手动安全升级能力（`upgrade.py` / `upgrade.sh` / `upgrade.ps1`）**：参照 `install.py` 范式（自动检测 AI 工具、定位 `skills/` 目录、GitHub 克隆/zip 降级、venv 构建、全环实测），叠加**安全零停机**流程——新版本先下载到与线上技能**同文件系统**的暂存目录（线上技能原封不动、始终可调用），在暂存副本上构建 venv 并跑通 `scan → run → decrypt → restore` 全环校验（**校验不过则拒绝替换**）；校验通过后才把当前线上技能改名备份、以原子 `rename` 把暂存副本落位，再实测线上技能、失败**自动回滚**到备份。新增 `VERSION` 文件作为版本唯一来源（install/upgrade 共用）。**默认不自动运行**（仅手动触发，AI Agent 仅在用户明确要求升级时执行），杜绝"自动升级失败导致技能无法调用"。支持 `--check`（仅查更新）/ `--dry-run`（下载+校验不替换）/ `--force`（强制重装）/ `--source local`（离线/本地源）/ `--clean-backup`（清理历史备份）。
- **实现要点**：`is_public_declared()` 统一判定（全局声明 → `--public-paths` 文件/文件夹 → 伴随清单），新增 `_resolve_public_paths()`；`discover_public_manifests()` 自动发现目录树内清单；`META_SKIP` 纳入 `.nodesens`/`desensitize_manifest.json`（移除 `.public_root`）；新增 `_record_public_declared()`（计算 size/sha256）；`_report_skipped()` 将公开声明豁免单独分组并附 size/sha256 与警示。
- **测试**：`run_tests.py` 新增 T19/T20/T21 锁定"声明者不脱敏、其余仍脱敏、防误命中、全局声明、自定义清单"；T7 还原为 v2.4.2 原断言（北京大学仍可能误识为机构，需人工甄别/声明），删除已失效的 T17/T18（白名单）及其 fixture。全量回归 PASS=16 / KNOWN_LIMIT=3 / FAIL=0。（注：豁免接口从"文件名哨兵"改为"--public-paths"，T19-T21 需随新模型复核。）
- **文档**：SKILL.md（§输入检测闸门加声明分支 + 新增「显式声明豁免」节 + 新增「手动升级（安全零停机）」节 + 版本 v2.5.0）、reference.md（§0.5 + 修正机构名过匹配说明）、README（核心能力表 + 版本表 + 升级小节 + 文件结构列入升级脚本）。
- **install.py 自检免疫**：verify 的 scan/run 调用加 `--public-manifest /dev/null`，使校验彻底与豁免启发式解耦（即使环境存在 `.nodesens` 也不影响；且文件名 `sample` 等不再触发豁免）。
- **新增「统一成果中心（工作区）」+ 上云前自检报告 + status（面向非专业人员，v2.5.0 第二阶段）**：针对各阶段产物分散、命名偏技术化、非专业人员难查找核对的问题——各阶段命令加 `--workspace <目录>` 后，全部产物归拢到一处、用**清晰中文目录**命名（`03_脱敏副本/`✅可上云、`02_未脱敏副本/`🚫、`04_映射表_保密/`🚫、`06_审计与回填/` 等），并自动维护带「可上云/保密」标签的 `成果索引`（json+md）；`run` 额外生成 `05_上云前自检报告.md`，**汇总 OCR 待校对副本 / 脱敏副本 / 公开豁免留痕三处校对提醒 + 确认闸门**，由 AI Agent 展示给用户、待其明确「确认上云」后才上云（期间用户可指出异常补充/修正）；新增 `status` 命令随时回显索引。**修复报告路径脆弱性**：工作区模式下 `desensitize_report.json` 置于工作区根（脱敏副本目录之外，避免被一并上传）；**不带 `--workspace` 时完全保持原默认行为**（向后兼容，install 自检不受影响）。`META_SKIP` 纳入工作区元数据文件，避免被当作业务文本重复处理。
- **电商/互联网小微业务测试驱动修复（v2.5.0 第三阶段，测试套件上强度）**：新增 `test_suite/fixtures/ecommerce_smb/`（星选优选电商公司全链路 26 个业务文件，11 种格式）+ `run_ecommerce_tests.py`（20 用例）暴露并修复 6 项真实缺陷：
  1. **docx 表格抽取**：段落之外新增表格遍历（小微常用 Word 表格做登记表，此前表格内身份证/税号/金额漏检）；
  2. **xlsx 批注抽取**：openpyxl 改非只读模式（`data_only=True`），正文之外读取批注文本（客服常把补充信息写批注，此前批注内手机号漏检）；超大文件注意内存（小微场景可接受）；
  3. **JWT 识别**：新增 `jwt` 类别（`eyJ` 三段式 base64url，特征极强、对所有文本生效），掩码保留 `eyJ` 前缀与末 6 位（`eyJ***`）；
  4. **HTML 内嵌密钥**：html/htm 纳入 `SECRET_PATTERN` 密钥检测（`SECRET_EXTS = CODE_EXTS ∪ {html, htm}`，分类仍属 TEXT），`<script>var adminToken = "..."</script>` 不再漏检；
  5. **GBK/GB2312 编码探测**：文本读取 `UTF-8 → GB18030 → 兜底` 自动回退（电商导出报表多为 GBK，此前中文乱码、可读性受损），数字/金额脱敏不受影响；
  6. **SQL INSERT 位置参数口令**：按「列名含口令关键词 → VALUES 对应位置值」定位脱敏（`INSERT INTO users (…, password, …) VALUES (…, 'secret_pass_123', …)` 前无 `password=` 前缀，SECRET_PATTERN 无法捕获）；scan 与 run 计数一致；无列名 INSERT 仍无法定位（保留局限）。
- **新增「先清洗再脱敏」提醒机制（清洗建议，面向小微业务随意填写）**：新增 `MESSY_PATTERNS` + `_find_cleaning_advice()`，检测疑似未清洗数据形态——带分隔符手机号（`138-0013-8004`/`138 0013 8002`）、10 位手机、15 位旧身份证、订单号/流水号标签后紧跟 16-19 位纯数字（与银行卡区间重叠易误判）——**只提醒、不自动改**（fail-safe：宁可让用户先清洗/复核，也不静默放过或误伤）。scan 控制台逐文件输出 `⚠清洗建议 {类别: 次数}` + 汇总文案；run 报告新增 `cleaning_advice`（分类计数）与 `cleaning_advice_text`（建议文案）。测试：20 用例 PASS 17 / KNOWN_LIMIT 3 / FAIL 0（E9/E10/E11/E12/E19 由 KNOWN_LIMIT → PASS，新增 E20 清洗建议验证）；run_tests（19 用例 16/3/0，T19/T20 同步 v2.5.0 新豁免模型断言）、run_source_tests、install verify 4/4 全部回归通过。

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
