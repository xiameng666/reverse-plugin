"""
IDA Script Router - reads command from environment variables.

Environment:
    IDA_BRIDGE_SCRIPT     - which script: full_export, analyze_offset, list_functions, search_string
    IDA_BRIDGE_ARGS       - JSON-encoded arguments array
    IDA_BRIDGE_SCRIPT_DIR - path to the scripts directory
"""
import os
import sys
import json

def main():
    script = os.environ.get("IDA_BRIDGE_SCRIPT", "")
    args_json = os.environ.get("IDA_BRIDGE_ARGS", "[]")
    script_dir = os.environ.get("IDA_BRIDGE_SCRIPT_DIR", "")

    try:
        args = json.loads(args_json)
    except:
        args = []

    # Set ARGV for the target script
    import idc
    idc.ARGV = ["ida_run.py"] + args

    script_map = {
        "full_export": "ida_full_export.py",
        "analyze_offset": "ida_analyze_offset.py",
        "list_functions": "ida_list_functions.py",
        "search_string": "ida_search_string.py",
    }

    filename = script_map.get(script, "")
    if not filename:
        print(f"[IDA-Bridge] Unknown script: {script}")
        idc.qexit(1)
        return

    script_path = os.path.join(script_dir, filename)
    if not os.path.exists(script_path):
        print(f"[IDA-Bridge] Script not found: {script_path}")
        idc.qexit(1)
        return

    # Add script_dir to sys.path so imports work
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    with open(script_path, "r", encoding="utf-8") as f:
        code = f.read()

    exec(compile(code, script_path, "exec"), {"__name__": "__main__", "__file__": script_path})

main()
