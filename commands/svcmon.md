---
description: "监控 Android APP syscall 行为并生成 AI 分析报告。"
argument-hint: "<package> [preset: re_basic|re_full|detect|all]"
---

**你（主 agent）负责采集和报告生成。subagent 只负责 AI 分析。按以下步骤执行：**

## Preset 和 Syscall 列表

| preset | syscall 列表 | 说明 |
|--------|-------------|------|
| `re_basic` | `openat,faccessat,unlinkat,readlinkat,getdents64,newfstatat,statx,renameat2,mkdirat,close,clone,clone3,execve,execveat,exit,exit_group,wait4,prctl,ptrace,kill,tgkill,rt_sigaction,seccomp,setns,unshare,bpf` | 文件+进程+信号+安全 |
| `detect` | `openat,faccessat,newfstatat,readlinkat,statfs,getdents64,ptrace,prctl,kill,tgkill,clone,wait4,mprotect,rt_sigaction` | 环境检测专用（含 mprotect） |
| `detect_lite` | `openat,faccessat,newfstatat,readlinkat,statfs,getdents64,ptrace,prctl,clone,wait4,kill,tgkill` | 精简版（零丢失） |
| `re_full` | re_basic + `mmap,mprotect,munmap,brk,mincore,madvise,memfd_create,process_vm_readv,process_vm_writev,socket,bind,listen,connect,accept,accept4,sendto,recvfrom,sendmsg,recvmsg` | 全量 |
| `all` | `all` | 所有 syscall |

默认 preset 为 `detect_lite`。从用户参数解析包名和 preset。

## 步骤 1: 解析包名 + 提前 pull 资源

如果包名不含 `.`，用 `adb shell pm list packages | grep <关键词>` 找完整包名。

提前 pull zygote maps 和 split APK（后面生成报告要用）：

```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'cat /proc/\$(pidof zygote64)/maps'" > /tmp/zygote_maps.txt 2>/dev/null
```

```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'pm path <包名>'" 2>&1
```

从输出找 `split_config.arm64` 的路径并 pull：

```bash
MSYS_NO_PATHCONV=1 adb pull <split_config.arm64_v8a.apk 设备路径> /tmp/split_config.arm64_v8a.apk
```

## 步骤 2: 清数据 + 启动 stackplz

```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'echo 131072 > /proc/sys/kernel/perf_event_mlock_kb; am force-stop <包名>; pm clear <包名>; find /data/app -path \"*<包名>*/oat\" -type d -exec rm -rf {} + 2>/dev/null'"
```

然后**后台启动 stackplz（run_in_background=true）**：

```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'cd /data/local/tmp && rm -f svc_trace.log && ./stackplz -n <包名> -s <syscall列表> --stack --showtime -b 128 -o svc_trace.log --auto > /dev/null 2>&1'"
```

启动后告诉用户：

```
[*] stackplz 已启动，正在监控 <包名> (preset: <preset>)
[*] 请操作 APP，完成后告诉我"停止"
```

然后等待用户回复。

## 步骤 3: 用户说停止后

停止 stackplz：
```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'killall stackplz'" 2>/dev/null
```

创建输出目录并 pull 日志：
```bash
python3 -c "
from pathlib import Path; import json; from datetime import datetime
cfg = json.loads((Path.home()/'.reverse-plugin/config.json').read_text())
ts = datetime.now().strftime('%Y%m%d_%H%M%S')
d = Path(cfg['work_dir'])/'sessions'/f'svc_{ts}'
d.mkdir(parents=True, exist_ok=True)
print(f'OUTPUT_DIR={d}')
"
```

```bash
MSYS_NO_PATHCONV=1 adb pull /data/local/tmp/svc_trace.log "<OUTPUT_DIR>/trace.log"
```

把之前 pull 的 zygote maps 和 APK 也移到 OUTPUT_DIR：
```bash
cp /tmp/zygote_maps.txt "<OUTPUT_DIR>/zygote_maps.txt"
cp /tmp/split_config.arm64_v8a.apk "<OUTPUT_DIR>/split_config.arm64_v8a.apk"
```

## 步骤 4: 生成 HTML 报告（含 SO 偏移 patch）

**你自己执行这一步**，用 `svcMonitor parse` 生成带 SO 偏移 patch 的 HTML 报告：

```bash
svcMonitor parse "<OUTPUT_DIR>/trace.log" -p <包名> --maps "<OUTPUT_DIR>/zygote_maps.txt" --apk "<OUTPUT_DIR>/split_config.arm64_v8a.apk" -o "<OUTPUT_DIR>/report.html" --no-open
```

如果 maps 或 apk 不存在，去掉对应参数。如果命令失败，跳过。

## 步骤 5: spawn subagent 做 AI 分析

spawn `re:svcMonitor-analyzer` subagent，prompt 传：

```
包名: <完整包名>
trace 文件路径: <OUTPUT_DIR>/trace.log
输出目录: <OUTPUT_DIR>
report.html 路径: <OUTPUT_DIR>/report.html（如果存在）
```

等 subagent 返回，把结果输出给用户。
