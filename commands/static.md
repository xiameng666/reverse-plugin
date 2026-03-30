---
description: "分析 idat 导出的 SO 静态数据，产出 SVC 模式、字符串解密、保护特征报告。"
argument-hint: "<export_dir> [--output <output_dir>]"
---

**立刻执行以下操作，不要做任何其他事情：**

用 Agent 工具 spawn 一个 `static-analyzer` subagent（使用 `E:/_github/reverse-plugin/agents/static-analyzer.md` 定义），prompt 如下：

```
EXPORT_DIR: <用户给的第一个参数>
OUTPUT_DIR: <如果有 --output 参数则用，否则留空让脚本自动生成>
```

spawn 后等返回，把结果输出给用户。

**禁止：**
- 禁止自己跑 bash/python
- 禁止搜索文件
- 禁止 Explore
- 你唯一要做的就是一个 Agent() 调用
