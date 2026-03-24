---
name: svcmon
description: 对 Android APP 进行 syscall 行为监控与检测分析。当用户要求监控 APP、分析闪退、分析环境检测、反调试、反注入、反虚拟机行为时使用。触发词：svcmon, syscall 监控, 检测分析, 闪退监控, 行为分析, 反虚拟机, 反注入
---

# svcmon — APP Syscall 行为监控与分析

## 触发

用户说 `/re:svcmon <包名>` 或 "监控APP"、"分析检测" 时使用。

## Step 0: 环境检查（每次都跑）

依次检查，哪个不通就修哪个，全通才继续：

```bash
# 1. svcmon CLI 是否可用
which svcmon 2>/dev/null
# 不可用 → 安装：
pip install -e <plugin_tools_dir>
# plugin_tools_dir 位置：找到本 skill 文件所在目录，往上两级到 plugin root，然后 tools/
# 或者直接：pip install -e ~/.claude/plugins/cache/svcmon-plugin/re/*/tools/

# 2. 设备是否连接
adb devices | grep device

# 3. stackplz 是否在设备上
adb shell "su -c 'ls /data/local/tmp/re/stackplz'" 2>/dev/null
# 不在 → 检查本地有没有：
svcmon config show
# stackplz_local 为空 → 下载：
python -c "
import urllib.request, json, os
api = 'https://api.github.com/repos/SeeFlowerX/stackplz/releases/latest'
req = urllib.request.Request(api, headers={'User-Agent': 'svcmon'})
data = json.loads(urllib.request.urlopen(req, timeout=30).read())
url = [a['browser_download_url'] for a in data['assets'] if a['name']=='stackplz'][0]
dest = os.path.expanduser('~/.svcmon/stackplz')
os.makedirs(os.path.dirname(dest), exist_ok=True)
urllib.request.urlretrieve(url, dest)
print(f'Downloaded to {dest}')
"
# 然后 push：
MSYS_NO_PATHCONV=1 adb push ~/.svcmon/stackplz /data/local/tmp/re/stackplz
adb shell "su -c 'chmod 755 /data/local/tmp/re/stackplz'"

# 4. 输出目录
svcmon config show | grep output_root
# 没设置 → 用默认：~/re/svcmon
svcmon config set output_root ~/re/svcmon
```

**全部检查通过后才进 Step 1。不要跳过。**

## Step 1: 采集

```bash
svcmon run <package_or_keyword> --preset <preset> --duration 15s --no-open
```

包名支持模糊匹配：`svcmon run silicon` 自动匹配 `silicon.android.app`。

**Preset 选择：**
- 用户说"分析检测/反调试/反注入" → `re_basic`
- 用户说"分析反虚拟机" → `re_full`
- 用户说"看文件" → `file`
- 用户说"看网络" → `net`
- 没说具体的 → `re_basic`

输出里拿 trace 和 report 路径。

**失败处理：**
- 0 events → perf buffer OOM，换 `--preset re_basic`
- stackplz panic → 确认 root 和 stackplz 路径

## Step 2: AI 分析（spawn subagent）

spawn `re:svcmon-analyzer` subagent：

```
读取 <trace.log路径>，分析 <包名> 的 syscall trace。

输出 Markdown：
## 检测链路
时间线描述。
## 线程分工
每个线程角色。
## 检测手段
逐项：FD遍历/maps扫描/线程名/内存/mountinfo/cmdline/反调试/暴力close/自杀/反VM/网络端口扫描。
每项给次数、线程、调用栈来源。不存在的不编造。
## 关键调用点
SO + 偏移。
## 绕过建议
每种手段的绕过方向。
```

## Step 3: 注入 + 输出

subagent 返回 markdown 后，用 Edit 替换 report.html 中的 `<div id="ai-analysis"></div>` 为：

```html
<div id="ai-analysis" style="background:#16213e;border:1px solid #333;border-radius:4px;padding:12px;margin-bottom:12px">
<h3 style="color:#0f0;margin:0 0 8px">AI Analysis</h3>
<div style="color:#ccc;line-height:1.6">
[markdown 转 HTML: ## → <h4>, ** → <b>, - → <li>, ``` → <code>, \n → <br>]
</div>
</div>
```

最后输出：
```
Report: <path>/report.html
Trace:  <path>/trace.log
[一句话关键发现]
```

打开报告：Windows 用 `start ""`，Mac 用 `open`。
