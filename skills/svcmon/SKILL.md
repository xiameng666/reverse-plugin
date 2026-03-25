---
name: svcmon
description: 对 Android APP 进行 syscall 行为监控与检测分析。当用户要求监控 APP、分析闪退、分析环境检测、反调试、反注入、反虚拟机行为时使用。触发词：svcmon, syscall 监控, 检测分析, 闪退监控, 行为分析, 反虚拟机, 反注入
---

# svcMonitor

## 触发

用户说 `/re:svcmon <包名>` 或 "监控APP"、"分析检测" 时使用。

## 你做三件事

### 1. 首次运行检查（用 AskUserQuestion）

先跑：
```bash
which svcMonitor 2>/dev/null && svcMonitor config show 2>&1
```

如果 svcMonitor 没装或 config 为空 → 用 AskUserQuestion 问用户：

```
svcMonitor 首次配置：
1. 报告输出目录？（回车默认 ~/re/svcMonitor）
2. stackplz 本地路径？（回车自动从 GitHub 下载）
```

如果 svcMonitor 已装且有 config → 跳过，直接到第 2 步。

### 2. Spawn subagent

把包名、preset、用户给的配置传给 `re:svcMonitor-analyzer`：

```
包名: <用户给的包名或关键词>
preset: <根据用户意图选的>
output_root: <用户给的路径或默认 ~/re/svcMonitor>
stackplz_local: <用户给的路径或空（表示自动下载）>
```

Preset 选择：
- "分析检测/反调试/反注入" → `re_basic`
- "分析反虚拟机" → `re_full`
- 没说 → `re_basic`

### 3. 输出结果

subagent 返回后，把结果告诉用户。

**不要自己跑采集/分析/HTML 注入，全部交给 subagent。**
**所有跟用户的交互用中文。**
