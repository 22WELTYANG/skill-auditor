# CI 与信任基础设施

仓库根目录的 `action.yml` 是同仓 Composite Action。它从
`GITHUB_ACTION_PATH` 安装扫描器，不执行目标仓库代码，先生成并上传 JSON、
SARIF，再应用扫描退出码。

工作流需要：

```yaml
permissions:
  contents: read
  security-events: write
  actions: read
```

PR 中的 `config`、显式 baseline 和 `baseline: auto` 都从 base commit
读取。Action 通过受限的 `git archive` 展开 base 内容，拒绝链接、设备文件、
目录穿越、过多成员和超大展开体积。

Baseline 仅保存 finding fingerprint 次数、内容哈希、规则摘要和工具版本。
完整 findings 仍保留在报告中，但只有新增且未被语义层可靠放行的问题参与门禁。

Lockfile 进一步固定语义策略、verdict 和报告摘要。扫描器不会自动信任目标自带
的 baseline、lockfile 或 cache；它们必须显式指定，或由 Action 从可信 base
commit 获取。
