---
name: svcmon
description: 对 Android APP 进行 syscall 行为监控与检测分析。当用户要求监控 APP、分析闪退、分析环境检测、反调试、反注入、反虚拟机行为时使用。触发词：svcmon, syscall 监控, 检测分析, 闪退监控, 行为分析, 反虚拟机, 反注入
---

# svcMonitor

**你（主 agent）负责采集流程。subagent 只负责分析。**

## Preset 和 Syscall 列表

| preset | syscall 列表 |
|--------|-------------|
| `re_basic` | `openat,faccessat,unlinkat,readlinkat,getdents64,newfstatat,statx,renameat2,mkdirat,close,clone,clone3,execve,execveat,exit,exit_group,wait4,prctl,ptrace,kill,tgkill,rt_sigaction,seccomp,setns,unshare,bpf` |
| `re_full` | re_basic + `mmap,mprotect,munmap,brk,mincore,madvise,memfd_create,process_vm_readv,process_vm_writev,socket,bind,listen,connect,accept,accept4,sendto,recvfrom,sendmsg,recvmsg` |
| `detect` | `openat,faccessat,newfstatat,readlinkat,statfs,read,getdents64,ptrace,prctl,kill,tgkill,clone,wait4,mprotect,rt_sigaction` |
| `all` | `all` |

默认 preset 为 `re_basic`。如果用户参数里有 `--preset xxx` 或第二个参数是 preset 名，使用对应值。

## 步骤 1: 你自己执行——启动 stackplz

**用 Bash（run_in_background=true）后台启动 stackplz：**

如果包名是关键词（如 `kash`），先用 `adb shell pm list packages | grep <关键词>` 找到完整包名。

先清数据和 oat：
```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'am force-stop <包名>; pm clear <包名>; find /data/app -path \"*<包名>*/oat\" -type d -exec rm -rf {} + 2>/dev/null'"
```

再后台启动 stackplz：
```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'cd /data/local/tmp && ./stackplz -n <包名> -s <syscall列表> --stack --showtime -b 64 -o svc_trace.log --auto > /dev/null 2>&1'"
```

启动后立刻告诉用户：

```
[*] stackplz 已启动，正在监控 <包名> (preset: <preset>)
[*] 请操作 APP，完成后告诉我"停止"
```

## 步骤 2: 等待用户说停止

用户说 "停止" / "完成" / "好了" / "闪退了" 等任意表示结束的话后继续。

## 步骤 3: 你自己执行——停止 stackplz 并 pull 日志

```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'killall stackplz'" 2>/dev/null
```

准备输出目录并 pull：

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

## 步骤 4: spawn subagent 做分析

spawn `re:svcMonitor-analyzer` subagent，prompt 传：

```
包名: <完整包名>
trace 文件路径: <OUTPUT_DIR>/trace.log
输出目录: <OUTPUT_DIR>
```

等 subagent 返回，把结果输出给用户。

## 禁止

- 禁止跳过步骤 1-3 直接 spawn subagent
- 禁止让 subagent 执行采集
