---
description: "初始化 reverse-plugin 环境。安装后首次运行一次即可。"
argument-hint: ""
---

执行 reverse-plugin 初始化，依次完成：

1. 安装 svcMonitor CLI（pip install）：
```bash
TOOLS_DIR="$(python -c "from pathlib import Path; import glob; dirs=glob.glob(str(Path.home() / '.claude/plugins/cache/reverse-plugin/re/*/tools/')); print(dirs[0] if dirs else 'E:/_github/reverse-plugin/tools')")"
pip install -e "$TOOLS_DIR" 2>&1 | tail -5
```

2. 用 AskUserQuestion 问用户工作目录：
```
reverse-plugin 初始化：
工作目录？（回车默认 ~/re）
```

3. 用 AskUserQuestion 问用户 IDA 目录（可选）：
```
IDA Pro 安装目录？（用于 /re:extractSo 导出 SO）
留空跳过（后续可再配置）
例: F:/IDA Professional 9.1
```

4. 保存到全局配置（hook 会读这个文件）。**必须存绝对路径，不存 `~`**：
```bash
python -c "
from pathlib import Path
import json
cfg_dir = Path.home() / '.reverse-plugin'
cfg_dir.mkdir(parents=True, exist_ok=True)
cfg_path = cfg_dir / 'config.json'
cfg = json.loads(cfg_path.read_text()) if cfg_path.exists() else {}
work_dir = str(Path('<用户给的工作目录或 ~/re>').expanduser().resolve())
cfg['work_dir'] = work_dir
ida_path = '<用户给的 IDA 路径或空>'
if ida_path:
    cfg['ida_path'] = str(Path(ida_path).resolve())
cfg_path.write_text(json.dumps(cfg, indent=2))
print(f'配置已保存: {cfg_path}')
for k, v in cfg.items():
    print(f'  {k}: {v}')
"
```

**重要**：后续所有步骤中的 `<工作目录>` 都用 Python expanduser 后的绝对路径（如 `C:/Users/24151/re`），不要用 `~/re`。特别是 `adb push` 命令必须用绝对路径。

5. 创建目录结构：
```bash
python -c "
from pathlib import Path
work_dir = Path('<工作目录>')
(work_dir / 'sessions').mkdir(parents=True, exist_ok=True)
(work_dir / '.config').mkdir(parents=True, exist_ok=True)
print('目录结构已创建')
"
```

6. 下载 stackplz：
```bash
python -c "
import urllib.request,json
from pathlib import Path
api='https://api.github.com/repos/SeeFlowerX/stackplz/releases/latest'
data=json.loads(urllib.request.urlopen(urllib.request.Request(api,headers={'User-Agent':'s'}),timeout=30).read())
tag=data.get('tag_name','?')
url=[a['browser_download_url'] for a in data['assets'] if a['name']=='stackplz'][0]
dest=Path('<工作目录>') / '.config' / 'stackplz'
dest.parent.mkdir(parents=True, exist_ok=True)
urllib.request.urlretrieve(url, str(dest))
print(f'stackplz {tag} 下载完成: {dest} ({dest.stat().st_size//1024}KB)')
"
```

7. 保存 svcMonitor CLI 配置：
```bash
svcMonitor config set output_root <工作目录>/sessions
```

完成后输出：
```
reverse-plugin 初始化完成！
  工作目录: <路径>
  stackplz: 已下载到 <工作目录>/.config/stackplz
  svcMonitor CLI: 已安装
  IDA: <路径或"未配置（/re:extractSo 不可用）">
  工具会在执行时自动推送到设备
  使用 /re:svcmon <包名> 开始监控
  使用 /re:extractSo <so路径> <包名> 导出 SO
```

注意：不要在 init 阶段推送工具到手机。每个命令（如 /re:svcmon）执行时会自己检查并推送需要的工具。
