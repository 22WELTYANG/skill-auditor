[English](ci-ecosystem.md)

# CI 与信任基础设施

## GitHub Action

为保证审计可复现，请固定精确 release 或完整 commit SHA：

```yaml
permissions:
  contents: read
  security-events: write
  actions: read

steps:
  - uses: actions/checkout@<FULL_COMMIT_SHA> # 固定已审阅的 checkout 版本
    with:
      fetch-depth: 0
  - uses: 22WELTYANG/skill-auditor@02cfa26f990a5102f60519b32ee200e13a4d4ae8
    with:
      path: .
      recursive: "true"
      baseline: auto
      artifact-name: skill-auditor-report
      sarif-category: skill-auditor
```

仓库根目录的 `action.yml` 是同仓 Composite Action。它从
`GITHUB_ACTION_PATH` 安装包，在不执行目标内容的前提下扫描，在
`RUNNER_TEMP` 下写入 JSON 和 SARIF，上传两份报告，最后应用扫描退出码。
非法 Action 输入会受控输出 `ERROR` 并返回 `3`，不会泄漏 traceback。制品上传
失败不会中断门禁；没有 GitHub Code Security 的仓库也可保留 SARIF 上传，
因为该步骤失败不影响扫描门禁继续执行。

同一 job 多次扫描时，用 `artifact-name` 避免制品名称冲突；用
`sarif-category` 为每次 Code Scanning 分析设置稳定且不同的类别。

## Pull Request 信任边界

PR 中的 `config` 和显式 `baseline` 路径通过 `git show` 从 base commit
读取。`baseline: auto` 会对 base commit 执行受限的 `git archive` 展开，并
扫描相同输入路径。链接、设备文件、目录穿越、超大归档和过多成员都会被拒绝。
不可信 PR head 中的文件不能自行定义 suppression 或 baseline 策略。

## SARIF 身份

每个 Skill 生成一个具有稳定 automation id 的 SARIF run。物理位置使用
`%SRCROOT%` 下的仓库相对路径；归档 finding 指向真实归档，成员通过逻辑位置
表示。Finding fingerprint 不包含行号，但包含规则 id、Skill 相对路径和
规范化证据，因此代码移动行号不会产生新告警。

## Baseline、Lock 与 Cache 信任

Baseline 保存 fingerprint 次数、内容哈希、扫描器版本和规则摘要。工具版本或
规则摘要不匹配会直接报错；不兼容 baseline 绝不会抑制 finding。完整 findings
始终可见，只有新增 finding 影响兼容的 diff 门禁。

Lockfile 会固定报告 schema、扫描状态、来源身份、覆盖情况、内容与规则哈希、
生效策略、语义设置、verdict 和报告摘要。扫描器不会自动加载目标内容自带的
baseline 或 lockfile；必须显式传入，或由 Action 从可信 base commit 获取。

Cache v2 仅用于优化，以完整内容清单和实际生效策略为键，其中包括解析后的
语义设置。Cache v1 一律 miss。缓存目录必须位于扫描目标之外且不能是链接；
缓存命中不能把覆盖不完整的结果变为通过。

## 仓库检查

干净样例 workflow 只是 smoke test，不代表真实世界 precision。仓库 CI 还会在
排除有意构造的恶意测试语料后审计仓库本身，并分别验证恶意样例、非法 Action
输入、base-commit baseline 行为和同一 job 多次调用 Action。任何公开 precision
结论都必须基于[研究方法](research-methodology.md)所述的冻结、人工标注语料。

## Badge 含义

静态的 “scanned by skill-auditor” badge 只表示仓库已集成该工具。应将它链接到
仓库的 `Skill security` workflow badge，才能说明默认分支当前 commit 是否通过。
