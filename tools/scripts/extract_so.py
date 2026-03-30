#!/usr/bin/env python3
"""extract_so.py — 调用 idat 全量导出 SO 到 sessions 目录。

用法: python extract_so.py <so_path> <package_name> [--output <dir>]

需要: ~/.reverse-plugin/config.json 中有 ida_path 和 work_dir
IDA 脚本(ida_full_export.py, ida_run.py)已内置在同目录下。
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPTS_DIR = Path(__file__).parent


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("so_path", help="SO 文件路径")
    parser.add_argument("package", help="包名（用于 session 目录分类）")
    parser.add_argument("--output", help="自定义输出目录（覆盖默认）")
    args = parser.parse_args()

    so_path = Path(args.so_path).resolve()
    if not so_path.is_file():
        print(f"ERROR=SO 文件不存在: {so_path}")
        sys.exit(1)

    # Read config
    cfg_path = Path.home() / ".reverse-plugin" / "config.json"
    if not cfg_path.is_file():
        print("ERROR=未初始化，请先运行 /re:init")
        sys.exit(1)

    cfg = json.loads(cfg_path.read_text())

    # IDA path
    ida_path = cfg.get("ida_path", "")
    if not ida_path:
        print("ERROR=未配置 IDA 路径，请运行 /re:init 配置")
        sys.exit(1)

    ida_dir = Path(ida_path)
    idat_exe = None
    for name in ["idat64.exe", "idat64", "idat.exe", "idat"]:
        candidate = ida_dir / name
        if candidate.exists():
            idat_exe = str(candidate)
            break
    if not idat_exe:
        print(f"ERROR=在 {ida_dir} 中找不到 idat64/idat")
        sys.exit(1)

    # Output dir
    so_stem = so_path.stem  # e.g. libbf4b
    if args.output:
        export_dir = Path(args.output)
    else:
        work_dir = Path(cfg["work_dir"])
        export_dir = work_dir / "sessions" / args.package / f"static_{so_stem}"

    export_dir.mkdir(parents=True, exist_ok=True)

    # Check if already exported
    summary_file = export_dir / "summary.json"
    if summary_file.exists():
        summary = json.loads(summary_file.read_text())
        print(f"WARN=已存在导出数据 ({summary.get('elapsed_seconds', '?')}s)")
        print(f"OUTPUT_DIR={export_dir}")
        print(f"FUNCTIONS={len(list((export_dir / 'disasm').glob('*.asm'))) if (export_dir / 'disasm').exists() else 0}")
        print("STATUS=EXISTS")
        return

    # IDA scripts are bundled in the same directory
    router_src = SCRIPTS_DIR / "ida_run.py"
    export_script = SCRIPTS_DIR / "ida_full_export.py"
    if not router_src.exists() or not export_script.exists():
        print("ERROR=缺少 IDA 脚本 (ida_run.py / ida_full_export.py)")
        sys.exit(1)

    print(f"SO={so_path}")
    print(f"IDA={idat_exe}")
    print(f"OUTPUT_DIR={export_dir}")
    print("PHASE=exporting...")

    # Copy router to temp (IDA's -S has path length issues on Windows)
    tmp_router = Path(tempfile.gettempdir()) / "ida_bridge_run.py"
    shutil.copy2(router_src, tmp_router)

    # Build command
    cmd = f'"{idat_exe}" -A -S"{tmp_router}" "{so_path}"'

    env = os.environ.copy()
    env["IDA_BRIDGE_SCRIPT"] = "full_export"
    env["IDA_BRIDGE_ARGS"] = json.dumps([str(export_dir)])
    env["IDA_BRIDGE_SCRIPT_DIR"] = str(SCRIPTS_DIR)

    start = time.time()
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=600, cwd=str(so_path.parent), env=env
        )
        elapsed = time.time() - start
        print(f"ELAPSED={elapsed:.1f}s")
        print(f"EXIT_CODE={result.returncode}")

        if result.returncode != 0 and not summary_file.exists():
            print(f"ERROR=IDA 导出失败")
            print(f"STDERR={result.stderr[:500]}")
            print("STATUS=FAILED")
            sys.exit(1)

    except subprocess.TimeoutExpired:
        print("ERROR=IDA 导出超时 (>600s)")
        print("STATUS=FAILED")
        sys.exit(1)

    # Verify output
    if not summary_file.exists():
        has_files = (export_dir / "functions.json").exists()
        if not has_files:
            print("ERROR=导出目录为空，IDA 可能未正确运行")
            print("STATUS=FAILED")
            sys.exit(1)

    # Count results
    disasm_count = len(list((export_dir / "disasm").glob("*.asm"))) if (export_dir / "disasm").exists() else 0
    decomp_count = len(list((export_dir / "decompiled").glob("*.c"))) if (export_dir / "decompiled").exists() else 0

    print(f"FUNCTIONS={disasm_count}")
    print(f"DECOMPILED={decomp_count}")
    print(f"OUTPUT_DIR={export_dir}")
    print("STATUS=OK")


if __name__ == "__main__":
    main()
