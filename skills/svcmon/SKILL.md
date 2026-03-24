---
name: tool-svcmon
description: 对 Android APP 进行 syscall 行为监控与检测分析。当用户要求监控 APP、分析闪退、分析环境检测、反调试、反注入、反虚拟机行为时使用。触发词：svcmon, syscall 监控, 检测分析, 闪退监控, 行为分析, 反虚拟机, 反注入
---

# svcmon — APP Syscall 行为监控与分析

## 触发

用户说 `/svcmon <包名>` 或 "监控APP"、"分析检测"、"分析反调试"、"反虚拟机检测" 时使用。

## 流程

你是主 Agent。三步：采集 → 分析 → 注入。

### Step 1: 采集

```bash
svcmon run <package_or_keyword> --preset re_basic --duration 15s --no-open
```

包名支持模糊匹配：`svcmon run silicon` 会自动 grep 设备上的包列表，匹配到 `silicon.android.app`。多个匹配时交互选择。

输出里拿 trace.log 和 report.html 路径。

**Preset 选择：**

| Preset | 场景 | 包含分类 |
|--------|------|---------|
| re_basic | 检测分析（推荐） | 文件操作 + 进程管理 + 信号处理 |
| re_full | 完整逆向 | 文件 + 进程 + 内存 + 网络 + 信号 + 安全 |
| file | 文件行为 | 文件操作 |
| proc | 进程行为 | 进程管理 + 信号 |
| mem | 内存行为 | 内存管理 |
| net | 网络行为 | 网络通信 |
| security | 安全审计 | seccomp/bpf/namespace |
| all | 全量（慎用，可能 OOM） | 全部 |

根据用户需求选择 preset：
- "分析检测/反调试/反注入" → `re_basic`
- "分析反虚拟机" → `re_full`（需要内存+文件+进程+网络全覆盖）
- "看文件访问" → `file`
- "看网络连接" → `net`

失败排查：
- 0 events → 换 `--preset re_basic` 或确认 `svcmon setup` 已完成
- perf buffer OOM → 减少 syscall 或降 preset

### Step 2: AI 分析（spawn subagent）

spawn `svcmon-analyzer` subagent，prompt 里传 trace.log 路径：

```
读取 <trace.log路径>，这是 stackplz 抓取的 <包名> 的 syscall trace。

分析要点（根据用户需求侧重）：

检测分析场景：
- 检测链路：时间线
- 线程分工：哪个线程做检测/破坏/自杀
- 检测手段：FD遍历/maps扫描/线程名/内存/mountinfo/cmdline/反调试/暴力close/自杀
- 关键 SO + 偏移
- 绕过建议

反虚拟机场景（额外关注）：
- 系统属性读取（__system_property_get: ro.hardware, ro.product.model, ro.build.fingerprint）
- 设备文件探测（/dev/goldfish_pipe, /dev/qemu_pipe, /sys/qemu_trace）
- CPU 信息检查（/proc/cpuinfo）
- 传感器检查（sensor 相关 ioctl/binder）
- 电池/温度异常值检测
- Build 信息（openat 读取 build.prop）
- MAC 地址/IMEI 检测
- 网络特征（10.0.2.* 等模拟器特征 IP）

反注入场景（额外关注）：
- /proc/self/maps 扫描（找异常 SO 映射）
- /proc/self/fd 遍历（找注入的 socket/pipe fd）
- 线程名扫描（找 frida/xposed 线程）
- 暴力 close fd（破坏注入通道）
- /proc/self/mem 读取（内存完整性校验）
- /proc/net/tcp 扫描（找 frida-server 端口）

输出 Markdown，简洁直接。
```

### Step 3: 注入 + 输出

subagent 返回 markdown 后，用 Edit 替换 report.html 中的占位符：

`<div id="ai-analysis"></div>` 替换为：

```html
<div id="ai-analysis" style="background:#16213e;border:1px solid #333;border-radius:4px;padding:12px;margin-bottom:12px">
<h3 style="color:#0f0;margin:0 0 8px">AI Analysis</h3>
<div style="color:#ccc;line-height:1.6">
[markdown 转 HTML]
</div>
</div>
```

最后输出路径 + 简要结论，打开报告。

## 首次使用

需要先运行 `svcmon setup`：
1. 设置报告输出目录（默认 ~/re/svcmon）
2. 自动从 GitHub 下载 stackplz
3. 推送到设备

## 配置

```bash
svcmon config show                      # 查看
svcmon config set output_root ~/re/svcmon  # 设置输出目录
svcmon config set serial XXXX           # 设置默认设备
```
