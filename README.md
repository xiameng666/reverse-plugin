# reverse-plugin

Claude Code plugin for Android reverse engineering.

## 安装

```bash
/plugin marketplace add xiameng666/reverse-plugin
/plugin install re
/reload-plugins
```

## 命令

### `/re:svcmon <包名>` — Syscall 行为监控

一键监控 APP 的 syscall 行为，自动生成带 AI 分析的 HTML 报告。

```bash
/re:svcmon silicon              # 模糊匹配包名
/re:svcmon com.example.app      # 完整包名
```

**功能：**
- 基于 [stackplz](https://github.com/SeeFlowerX/stackplz)（eBPF）采集 syscall + 栈回溯
- Zygote maps baseline + mmap 事件重建完整内存映射
- APK 内嵌 SO 偏移解析（split_config.arm64_v8a.apk → libxxx.so）
- addr2line 级别的精确符号化
- AI 语义分析：检测链路、线程分工、关键 SO 定位、绕过建议
- 自包含 HTML 报告（暗色主题、Tab 分类、按线程钻取）

**检测识别：**

| 类别 | 识别内容 |
|------|---------|
| 反调试 | ptrace、prctl PR_SET_DUMPABLE、/proc/self/status |
| 反注入 | maps 扫描、FD 遍历、线程名扫描、暴力 close fd、/proc/self/mem 完整性校验 |
| 反虚拟机 | 系统属性探测、/dev/goldfish_pipe、/proc/cpuinfo、build.prop |
| 挂载检测 | /proc/self/mountinfo（Magisk bind mount） |
| 网络检测 | /proc/net/tcp（frida-server 端口） |
| 文件探测 | faccessat/openat frida/magisk/su/xposed 路径 |

**Preset：**

| Preset | 场景 | Syscall 分类 |
|--------|------|-------------|
| `re_basic` | 检测分析（默认） | 文件操作 + 进程管理 + 信号处理 |
| `re_full` | 完整逆向 | 全部 6 大分类 |
| `file` | 文件行为 | 文件操作 |
| `proc` | 进程行为 | 进程管理 + 信号 |
| `mem` | 内存行为 | 内存管理 |
| `net` | 网络行为 | 网络通信 |
| `security` | 安全审计 | seccomp/bpf/namespace |
| `all` | 全量 | 所有 syscall |

**首次使用自动 setup：**
- 下载 stackplz 最新版
- 推送到设备 `/data/local/tmp/re/`
- 配置报告输出目录

---

### `/re:extractSo <so_path> <package>` — IDA 全量导出

用 IDA headless 将 SO 文件全量导出（反汇编、反编译、调用图、字符串、xrefs）到 session 目录。

```bash
/re:extractSo E:/_github/re/sessions/com.example.app/svc_xxx/split_config.arm64_v8a.apk com.example.app
/re:extractSo /path/to/libnative.so com.example.app
```

**前提：** `/re:init` 时配置了 IDA 路径和 ida-bridge 路径。

**导出产物：**
```
sessions/<package>/static_<so_name>/
├── meta.json           # 二进制元数据
├── functions.json      # 所有函数列表
├── strings.json        # 所有字符串 + xrefs
├── callgraph.json      # 完整调用图
├── xrefs.json          # ���据引用
├── imports.json        # 导入函��
├── exports.json        # 导出函数
├── segments.json       # 内存段
├── disasm/             # 每个函数的反汇编 .asm
└── decompiled/         # 每个函数的伪代码 .c
```

导出后可直接用 Claude 的 Read 工具查看任意函数，或用 `/re:static` 做自动化分析。

---

### `/re:static <export_dir>` — 静态分析报告

分析 idat 导出的 SO 数据，产出 SVC 调用模式、字符串解密点、保护特征报告。

```bash
/re:static E:/_github/ida-bridge/output/export_libbf4b
/re:static E:/_github/ida-bridge/output/export_libxxx --output E:/_github/re/reports/
```

**分析维度：**

| 维度 | 分析内容 |
|------|---------|
| SVC 模式 | wrapper/direct/inline 分类，MBA 混淆检测 |
| Syscall NR | 明文 / MBA 混淆 / 未知 三类统计 |
| 字符串解密 | 高调用量+解密特征(XOR/循环/位运算)的函数 |
| 保护特征 | 反调试/反注入/反root/反VM/反frida/完整性校验 |
| Hook 建议 | HIGH(解密函数) / MEDIUM(SVC wrapper) 优先级排序 |

**输出：**
- `static_report.json` — 机器可读的完整报告
- `analysis.md` — AI 分析的 Markdown 报告

---

### `/re:correlate <static_report.json>` — 静态+动态交叉关联

交叉关联 static 报告与 svcmon 动态 trace，自动生成 rustFrida hook 脚本。

```bash
/re:correlate report.json --trace trace.log --analysis analysis.md
```

**功能：**
- SVC 调用点验证：已确认活跃 / 条件触发 / 动态生成
- 检测链路重建：静态 callgraph + 动态调用栈
- 字符串解密验证：候选函数运行时确认
- 自动生成 rustFrida hook 脚本 + 分阶段执行计划

---

## 计划中

### `/re:hook <包名>` — Frida Hook 编排

自动分析检测点 → 生成 hook 脚本 → 注入绕过 → 验证结果。

### `/re:patch <包名>` — 静态修补

基于 svcmon 分析结果，定位检测 SO → 生成 NOP patch → 重打包验证。

### `/re:trace <包名>` — uprobe 精准追踪

对 svcmon 定位的关键 SO 函数做 uprobe hook，抓取参数和返回值。

### `/re:diff <包名>` — 版本对比

对比两个版本的 APP 检测行为差异，追踪保护方案升级。

### `/re:report` — 综合报告

汇总 svcmon + hook + patch 的结果，生成完整逆向分析报告。

---

## Session 目录结构

按包名分类，动态+静态数据放在一起：

```
<work_dir>/sessions/
├── com.example.app/
│   ├── svc_20260326_171526/          # 动态监控
│   │   ├── trace.log
│   │   ├── analysis.md
│   │   └── report.html
│   ├── static_libnative/             # 静态导出（IDA）
│   │   ├── functions.json
│   │   ├── callgraph.json
│   │   ├── disasm/
│   │   └── decompiled/
│   └── correlate_20260327/           # 交叉关联
│       ├── correlation_report.md
│       └── hooks/
└── com.other.app/
    └── svc_20260328_100000/
```

## 依赖

- Claude Code v2.1+
- Android 设备（root，ARM64，kernel 5.10+）
- ADB
- Python 3.8+ / pip / click
- IDA Pro（可选，仅 `/re:extractSo` 需要，IDAPython 脚本已内置）

## 架构

```
┌─ IDA 导出 ─────────────────────────────────┐
│ /re:extractSo libnative.so com.example.app  │
│      ↓                                      │
│ so-extractor (subagent)                     │
│   ├── extract_so.py → idat headless         │
│   └── → static_<so>/ (disasm/ decompiled/)  │
└─────────────────────────────────────────────┘
          ↓ 导出数据
┌─ 动态分析 ─────────────────────────────────┐
│ /re:svcmon silicon                          │
│      ↓                                      │
│ svcMonitor-analyzer (subagent)              │
│   ├── stackplz 采集 syscall + 栈回溯        │
│   ├── trace 解析 + SO 偏移映射              │
│   ├── AI 语义分析                           │
│   └── → svc_<ts>/ (trace + analysis + html) │
└─────────────────────────────────────────────┘
          ↕ 交叉关联
┌─ 静态分析 ─────────────────────────────────┐
│ /re:static export_dir                       │
│      ↓                                      │
│ static-analyzer (subagent)                  │
│   ├── static_analyze.py (SVC/解密/保护扫描) │
│   ├── AI 深度分析 (反编译验证)              │
│   └── → static_report.json + analysis.md    │
└─────────────────────────────────────────────┘
          ↓
┌─ 交叉关联 + Hook 生成 ────────────────────┐
│ /re:correlate report.json                   │
│      ↓                                      │
│ correlator (subagent)                       │
│   ├── 静态+动态数据交叉验证                 │
│   ├── 检测链路重建                          │
│   ├── rustFrida hook 脚本自动生成           │
│   └── → correlate_<ts>/ (report + hooks/)   │
└─────────────────────────────────────────────┘
          ↓
┌─ 工具链 ───────────────────────────────────┐
│ rustFrida (KPM无痕hook) ← hook 脚本        │
│ edbgcli (uprobe+hwbp调试) ← 断点地址       │
└─────────────────────────────────────────────┘
```

## License

MIT
