# 贡献指南（Contributing）

感谢关注 **信息脱敏上云 SOP**。本仓库是 hzh.opc 的个人知识资产，欢迎以 Issue / Pull Request 形式提出改进，但合入与否由维护者决定。

## 提交 Issue
- **Bug / 误报 / 漏报**：请附上（脱敏后的）样例与期望行为；中文姓名/地址的误报漏报请说明语境。
- **功能建议**：说明使用场景与收益，最好给出 `reference.md` 对应是否需要补充。

## 提交 Pull Request
1. Fork 本仓库并基于 `main` 分支创建特性分支（`feat/...`、`fix/...`）。
2. 保持三文件职责清晰：`SKILL.md`（自动加载执行规范）、`reference.md`（按需详述）、`README.md`（项目说明），不要互相搬运大段内容。
3. 脚本位于 `desenstool/desensitize.py`，纯标准库 + `cryptography` 等声明在 `pyproject.toml` / `requirements.txt`；**禁止引入需要联网下载模型的重依赖作为默认路径**。
4. 数据不出本机是底线：`desensitize.py` 不得有任何对外网络请求。
5. 若改动脱敏逻辑，请补充/更新验证样例，并确保 `install.py` 的端到端实测（`scan → run → decrypt → restore`）通过。
6. 同步更新 `README.md` 的版本行与 `CHANGELOG.md`。

## 代码风格
- Python ≥ 3.9 语法；注释用中文。
- 保持命令行接口（`scan`/`run`/`decrypt`/`restore`/`audit`）向后兼容，新增参数应带合理默认值。

## 许可
贡献即表示你同意以仓库根目录 [`LICENSE`](LICENSE)（Apache License 2.0）条款授权你的贡献。
