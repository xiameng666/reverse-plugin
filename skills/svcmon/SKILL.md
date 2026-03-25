---
name: svcmon
description: 对 Android APP 进行 syscall 行为监控与检测分析。当用户要求监控 APP、分析闪退、分析环境检测、反调试、反注入、反虚拟机行为时使用。触发词：svcmon, syscall 监控, 检测分析, 闪退监控, 行为分析, 反虚拟机, 反注入
---

# svcMonitor

## 触发

用户说 `/re:svcmon <包名>` 或 "监控APP"、"分析检测" 时使用。

## 环境

session-start hook 已注入当前环境状态（设备、stackplz、session 目录）。
从 hook 注入的上下文里拿 session 目录路径。

## 你做两件事

### 1. Spawn subagent

把包名、preset、session 目录传给 `re:svcMonitor-analyzer`：

```
包名: <用户给的>
preset: <选的>
session_dir: <从 hook 上下文拿到的 session 目录>
```

Preset：
- "分析检测/反调试/反注入" → `re_basic`
- "分析反虚拟机" → `re_full`
- 没说 → `re_basic`

如果 hook 上下文里显示设备未连接或 stackplz 缺失，先提醒用户。

### 2. 输出结果

subagent 返回后告诉用户。

**不要自己跑采集/分析/注入。全部交给 subagent。所有交互用中文。**
