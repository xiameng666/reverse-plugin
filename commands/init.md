---
description: "初始化 reverse-plugin 环境。安装后首次运行一次即可。"
argument-hint: ""
---

执行 reverse-plugin 初始化，依次完成：

1. 安装 svcMonitor CLI（pip install）：
```bash
TOOLS_DIR="$(ls -d ~/.claude/plugins/cache/reverse-plugin/re/*/tools/ 2>/dev/null | head -1)"
pip install -e "$TOOLS_DIR" 2>&1 | tail -5
```

2. 用 AskUserQuestion 问用户工作目录：
```
reverse-plugin 初始化：
工作目录？（回车默认 ~/re）
```

3. 保存到全局配置（hook 会读这个文件）。**必须存绝对路径，不存 `~`**：
```bash
mkdir -p ~/.reverse-plugin
python3 -c "
import json,os
cfg_path = os.path.expanduser('~/.reverse-plugin/config.json')
work_dir = os.path.expanduser('<用户给的路径或 ~/re>')  # 展开为绝对路径
work_dir = os.path.abspath(work_dir)  # 确保是绝对路径
cfg = {'work_dir': work_dir}
with open(cfg_path, 'w') as f:
    json.dump(cfg, f, indent=2)
print(f'配置已保存: {cfg_path}')
print(f'工作目录: {work_dir}')
"
```

**重要**：后续所有步骤中的 `<工作目录>` 都用 Python expanduser 后的绝对路径（如 `C:/Users/24151/re`），不要用 `~/re`。特别是 `adb push` 命令必须用绝对路径。

4. 创建目录结构：
```bash
mkdir -p <工作目录>/sessions
mkdir -p <工作目录>/.config
```

5. 下载 stackplz：
```bash
python3 -c "
import urllib.request,json,os
api='https://api.github.com/repos/SeeFlowerX/stackplz/releases/latest'
data=json.loads(urllib.request.urlopen(urllib.request.Request(api,headers={'User-Agent':'s'}),timeout=30).read())
tag=data.get('tag_name','?')
url=[a['browser_download_url'] for a in data['assets'] if a['name']=='stackplz'][0]
dest=os.path.expanduser('<工作目录>/.config/stackplz')
os.makedirs(os.path.dirname(dest),exist_ok=True)
urllib.request.urlretrieve(url,dest)
print(f'stackplz {tag} 下载完成: {dest} ({os.path.getsize(dest)//1024}KB)')
"
```

6. 保存 svcMonitor CLI 配置：
```bash
svcMonitor config set output_root <工作目录>/sessions
```

完成后输出：
```
reverse-plugin 初始化完成！
  工作目录: <路径>
  stackplz: 已下载到 <工作目录>/.config/stackplz
  svcMonitor CLI: 已安装
  工具会在执行时自动推送到设备
  使用 /re:svcmon <包名> 开始监控
```

注意：不要在 init 阶段推送工具到手机。每个命令（如 /re:svcmon）执行时会自己检查并推送需要的工具。
