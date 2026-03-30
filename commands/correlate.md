---
description: "交叉关联静态分析与动态 trace，生成 rustFrida hook 脚本和执行计划。"
argument-hint: "<static_report.json> [--trace <trace.log>] [--analysis <analysis.md>] [--output <dir>]"
---

**立刻执行以下操作，不要做任何其他事情：**

用 Agent 工具 spawn 一个 `correlator` subagent（使用 `E:/_github/reverse-plugin/agents/correlator.md` 定义），prompt 如下：

```
STATIC_REPORT: <用户给的第一个参数>
DYNAMIC_TRACE: <如果有 --trace 参数>
SVCMON_ANALYSIS: <如果有 --analysis 参数>
OUTPUT_DIR: <如果有 --output 参数，否则 static_report 同目录>
```

spawn 后等返回，把结果输出给用户。

**禁止：**
- 禁止自己跑 bash/python
- 禁止搜索文件
- 你唯一要做的就是一个 Agent() 调用
