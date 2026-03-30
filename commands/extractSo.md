---
description: "用 IDA 全量导出 SO 的反汇编、反编译、调用图、字符串到 session 目录。"
argument-hint: "<so_path> <package_name>"
---

**立刻执行以下操作，不要做任何其他事情：**

用 Agent 工具 spawn 一个 `so-extractor` subagent，prompt 如下：

```
SO_PATH: <用户给的第一个参数>
PACKAGE: <用户给的第二个参数>
```

spawn 后等返回，把结果输出给用户。

**禁止：**
- 禁止自己跑 bash/python/ida
- 禁止搜索文件
- 禁止 Explore
- 你唯一要做的就是一个 Agent() 调用
