# 更新日志（Changelog）

本文件按时间倒序记录重大变更。日常细节以 Git 提交为准。

## v2.3 · 2026-08-15
- `--mode hybrid`（语义掩码 + 唯一令牌 `外壳⟦Txx⟧`）设为默认：无歧义恢复且保留字段语义。
- 放宽数字类标识符边界：身份证/手机/银行卡/IP/车牌/护照可紧邻中文识别（如「手机138…」）。
- 修复：代码密钥脱敏引号残留、`redact` 模式误报碰撞、自定义姓名 2 字整段打码等问题。
- 文件结构从早期版本拆分为 `SKILL.md` / `reference.md` / `README.md` 三件套。

## v2.2 · 2026-08（三文件拆分）
- 将执行规范（`SKILL.md`，自动加载）、操作详述（`reference.md`，按需读取）、项目说明（`README.md`）拆分，降低每次调用加载成本。

## v2.1 及更早
- 初版脱敏流程与本地脚本 `desenstool/desensitize.py`（scan/run/decrypt/restore/audit）。
- 引入中文离线增强 `--cn-enhance`、skip manifest（图片/加密/纯图片 PDF 不再静默放过）。
- 引入一键安装/卸载脚本（跨平台、跨 AI 工具）。
