---
name: kpm
description: 通过 truncate supercall 管理 KernelPatch 模块（KPM）。加载、卸载、列出、查看模块信息。触发词：kpm, 加载模块, load kpm, unload kpm, truncate, xmshadow, wxshadow
---

# KPM 模块管理

通过 `truncate` 触发 KernelPatch supercall，管理内核模块。

## 用法

根据用户意图执行对应命令：

### 列出已加载模块
```bash
adb shell "su -c 'truncate xiameng666 module list'"
```

### 加载模块
```bash
adb shell "su -c 'truncate xiameng666 module load /sdcard/Download/<模块名>.kpm'"
```

### 卸载模块
```bash
adb shell "su -c 'truncate xiameng666 module unload <模块名>'"
```

### 查看模块信息
```bash
adb shell "su -c 'truncate xiameng666 module info <模块名>'"
```

## 注意

- superkey 为 `xiameng666`
- KPM 文件通常先 push 到 `/sdcard/Download/`
- 模块名不一定等于文件名（如 `wxshadow.kpm` 加载后模块名是 `xmshadow`）
- 加载后用 `list` 确认模块名，后续 unload/info/ctl 用模块名操作
