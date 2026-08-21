# 反馈记录：desensitization-sop 常驻闸门写入位置脆弱（WorkBuddy）

- **反馈类型**：改进建议 / 潜在缺陷（Bug）
- **提交人**：天昊
- **目标仓库**：https://github.com/hzh-opc/desensitization-sop
- **涉及版本**：v2.10.0（`install.py` / `AGENT_INSTALL.md`）
- **日期**：2026-08-19

---

## 1. 背景

`install.py` 在 `TOOL_CONFIG` 中为各 AI 工具指定了「技能目录 + 记忆/指令文件」，`install_rule()` 会把「任务执行前通用敏感信息检测闸门」这一**常驻规则**幂等写入该记忆文件，意图让其跨会话常驻生效。

## 2. 问题（WorkBuddy 专属）

WorkBuddy 的配置项（`install.py` 约第 48–69 行 `TOOL_CONFIG` 定义）：

```python
"workbuddy": {
    "label": "WorkBuddy",
    "skills_dir": "~/.workbuddy/skills",
    "memory_file": "~/.workbuddy/MEMORY.md",   # ← 问题点（第 52 行）
},
```

而 `~/.workbuddy/MEMORY.md` 在 WorkBuddy 体系里是**跨项目长期记忆**，由云端缓存管理（缓存于 `~/.workbuddy/memory/`，本地写入会在下次会话被云端回填空）。后果：

- 安装器写入的常驻闸门**可能被云端同步覆盖** → 规则“消失”，失去“常驻”意义；
- 即便未被覆盖，把技能强制规则塞进“用户偏好/长期记忆”文件，语义也不恰当（该文件承担用户偏好，不应承载技能硬规则）。

## 3. 影响评估

- **严重性：中**。不影响技能本体与脱敏能力——`SKILL.md` 自带触发逻辑，技能被显式调用时仍正常生效；但“执行前自动检测闸门”这一**被动常驻**保障，在 `MEMORY.md` 被覆盖后会失效。
- **触发条件**：WorkBuddy 完成一次云端记忆同步 / 会话重载后，本地追加的闸门块被冲掉。

## 4. 已采用的临时方案（用户侧 workaround）

将闸门从 `MEMORY.md` 迁移到 **`~/.workbuddy/SOUL.md`**（新增「常驻安全闸门：任务执行前敏感信息检测」小节，位于「边界」段之后）。理由：`SOUL.md` 的 `read_when: Every session start`，**每次会话必加载、不被云端覆盖**，是权威且稳定的落点。

- 已回写 `MEMORY.md`（移除该块，恢复为仅含用户偏好）。
- **边角情况**：若未来重跑 `install.py` / `upgrade.py`，其幂等逻辑（`if RULE_MARKER in content`）会因 `MEMORY.md` 缺失标记而重新追加一份到 `MEMORY.md`——属无害重复，权威版本仍在 `SOUL.md`。

## 5. 给开发者的修复建议（任选其一或组合）

1. **改默认落点（推荐）**：将 WorkBuddy 的 `memory_file` 由 `~/.workbuddy/MEMORY.md` 改为 `~/.workbuddy/SOUL.md`（或 `IDENTITY.md`），使常驻规则写入每次会话必加载、不被云端回写的人格/边界文件。
2. **可配置化落地**：`install.py` 已支持 `--memory-file` 覆盖；建议在 `AGENT_INSTALL.md` 明确：WorkBuddy 用户若发现 `MEMORY.md` 被云端覆盖，可显式 `python3 install.py --memory-file ~/.workbuddy/SOUL.md` 重装。
3. **文档警示**：在 `AGENT_INSTALL.md` 第 4 步补充：部分工具的“记忆文件”可能被云端/宿主覆盖，若常驻规则失效，请检查该文件并改投 `SOUL.md`。
4. **技能内固化（更彻底）**：若希望“被动常驻”完全不依赖外部记忆文件，可提供一个由宿主在会话启动注入的 `RESIDENT.md` 机制（需宿主支持），作为更稳的常驻载体。

## 6. 关联引用（便于定位）

- `install.py`
  - `TOOL_CONFIG["workbuddy"]["memory_file"]` → 第 52 行
  - `RULE_MARKER` → 第 72 行（`"## 任务执行前通用敏感信息检测闸门"`）
  - `RULE_BLOCK` → 第 73–79 行
  - `install_rule()` → 第 512–526 行
- `AGENT_INSTALL.md`
  - 第 2 步「写入常驻规则」、第 4 步「确认 AI 工具加载技能」
