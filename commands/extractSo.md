---
description: "从设备 pull APK 解压 SO，可选 IDA 全量导出。"
argument-hint: "<package_name> [so_name]"
---

**立刻执行以下操作，不要做任何其他事情：**

用 Agent 工具 spawn 一个 `so-extractor` subagent，prompt 如下：

```
PACKAGE: <用户给的第一个参数>
SO_NAME: <用户给的第二个参数，如果没有则留空>
```

spawn 后等返回，把结果输出给用户。

**禁止：**
- 禁止自己跑 bash/python/adb
- 禁止搜索文件
- 禁止 Explore
- 你唯一要做的就是一个 Agent() 调用
