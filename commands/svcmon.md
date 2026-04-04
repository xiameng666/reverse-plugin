---
description: "监控 Android APP syscall 行为并生成 AI 分析报告。"
argument-hint: "<package> [preset: re_basic|re_full|detect|all]"
---

**你（主 agent）负责采集。subagent 只负责分析。按以下步骤执行：**

## Preset 和 Syscall 列表

| preset | syscall 列表 |
|--------|-------------|
| `re_basic` | `openat,faccessat,unlinkat,readlinkat,getdents64,newfstatat,statx,renameat2,mkdirat,close,clone,clone3,execve,execveat,exit,exit_group,wait4,prctl,ptrace,kill,tgkill,rt_sigaction,seccomp,setns,unshare,bpf` |
| `re_full` | re_basic + `mmap,mprotect,munmap,brk,mincore,madvise,memfd_create,process_vm_readv,process_vm_writev,socket,bind,listen,connect,accept,accept4,sendto,recvfrom,sendmsg,recvmsg` |
| `detect` | `openat,faccessat,newfstatat,readlinkat,statfs,read,getdents64,ptrace,prctl,kill,tgkill,clone,wait4,mprotect,rt_sigaction` |
| `all` | `all` |

从用户参数解析包名和 preset。第一个参数是包名（可以是关键词），第二个参数或 `--preset xxx` 是 preset，默认 `re_basic`。

## 步骤 1: 解析包名

如果包名不是完整包名（不含 `.`），用 `adb shell pm list packages | grep <关键词>` 找完整包名。

## 步骤 2: 清数据 + 启动 stackplz

```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'am force-stop <包名>; pm clear <包名>; find /data/app -path \"*<包名>*/oat\" -type d -exec rm -rf {} + 2>/dev/null'"
```

然后**后台启动 stackplz（run_in_background=true）**：

```bash
MSYS_NO_PATHCONV=1 adb shell "su -c 'cd /data/local/tmp && ./stackplz -n <包名> -s <syscall列表> --stack --showtime -b 64 -o svc_trace.log --auto > /dev/null 2>&1'"
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

## 步骤 4: spawn subagent 分析

spawn `re:svcMonitor-analyzer` subagent，prompt 传：

```
包名: <完整包名>
trace 文件路径: <OUTPUT_DIR>/trace.log
输出目录: <OUTPUT_DIR>
```

等 subagent 返回，把结果输出给用户。
