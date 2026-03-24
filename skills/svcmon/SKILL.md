---
name: svcmon
description: 对 Android APP 进行 syscall 行为监控与检测分析。当用户要求监控 APP、分析闪退、分析环境检测、反调试、反注入、反虚拟机行为时使用。触发词：svcmon, syscall 监控, 检测分析, 闪退监控, 行为分析, 反虚拟机, 反注入
---

# svcmon

## 触发

用户说 `/re:svcmon <包名>` 或 "监控APP"、"分析检测" 时使用。

## 做什么

Spawn `re:svcmon-analyzer` subagent，把包名和 preset 传给它。它会自己完成全部流程：环境检查 → stackplz 采集 → trace 分析 → HTML 注入。

## 你只做两件事

1. **Spawn subagent**：

```
prompt: "包名: <用户给的包名或关键词>, preset: <根据用户意图选的 preset>"
```

Preset 选择：
- "分析检测/反调试/反注入" → `re_basic`
- "分析反虚拟机" → `re_full`
- "看文件" → `file`
- "看网络" → `net`
- 没说 → `re_basic`

2. **输出结果**：subagent 返回后，把结果告诉用户。

不要自己跑 svcmon 命令、不要自己分析 trace、不要自己改 HTML。全部交给 subagent。
