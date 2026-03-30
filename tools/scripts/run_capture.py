#!/usr/bin/env python3
"""一键采集：push stackplz + svcMonitor run。输出 KEY=VALUE。

用法: python3 run_capture.py <包名或关键词> [--preset re_basic] [--duration 15s]
"""
import argparse, json, os, subprocess, sys
from pathlib import Path


def run(cmd, timeout=120, env_extra=None):
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    if env_extra:
        env.update(env_extra)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("package", help="包名或关键词")
    parser.add_argument("--preset", default="re_basic")
    parser.add_argument("--duration", default="15s")
    args = parser.parse_args()

    # Read config
    cfg_path = Path.home() / ".reverse-plugin" / "config.json"
    if not cfg_path.is_file():
        print("ERROR=未初始化，请先运行 /re:init")
        sys.exit(1)

    cfg = json.loads(cfg_path.read_text())
    work_dir = Path(cfg["work_dir"])
    stackplz_local = str(work_dir / ".config" / "stackplz")
    sessions_dir = str(work_dir / "sessions")
    print(f"WORK_DIR={work_dir}")
    print(f"SESSIONS_DIR={sessions_dir}")

    # Push stackplz if not on device
    rc, out, _ = run(["adb", "shell", "su -c 'ls /data/local/tmp/re/stackplz'"])
    if rc != 0 or "stackplz" not in out:
        print("PUSH_STACKPLZ=pushing...")
        run(["adb", "shell", "su -c 'mkdir -p /data/local/tmp/re'"])
        rc, _, err = run(["adb", "push", stackplz_local, "/data/local/tmp/re/stackplz"])
        if rc != 0:
            print(f"ERROR=push stackplz failed: {err}")
            sys.exit(1)
        run(["adb", "shell", "su -c 'chmod 755 /data/local/tmp/re/stackplz'"])
        print("PUSH_STACKPLZ=done")

    # Run svcMonitor
    cmd = [
        "svcMonitor", "run", args.package,
        "--preset", args.preset,
        "--duration", args.duration,
        "--no-open",
        "-o", sessions_dir,
    ]
    print(f"CMD={' '.join(cmd)}")

    # svcMonitor run 的超时 = 5(eBPF) + duration + 30(buffer)
    dur_sec = int(args.duration.rstrip("sm")) * (60 if args.duration.endswith("m") else 1)
    timeout = 5 + dur_sec + 60

    rc, out, err = run(cmd, timeout=timeout)

    # Parse output for key info
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Events:"):
            print(f"EVENTS={line.split(':')[1].strip()}")
        elif line.startswith("Detections:"):
            print(f"DETECTIONS={line.split(':')[1].strip()}")
        elif line.startswith("Lost:"):
            print(f"LOST={line.split(':')[1].strip()}")
        elif line.startswith("Report:"):
            print(f"REPORT={line.split(':', 1)[1].strip()}")
        elif line.startswith("Trace:"):
            print(f"TRACE={line.split(':', 1)[1].strip()}")

    # Find output dir (last created dir in sessions)
    if rc == 0 or any("Events:" in l for l in out.splitlines()):
        # Find the output dir from Report path
        for line in out.splitlines():
            if "Report:" in line:
                report_path = line.split(":", 1)[1].strip()
                output_dir = str(Path(report_path).parent)
                print(f"OUTPUT_DIR={output_dir}")
                break
        print("STATUS=OK")
    else:
        print(f"ERROR=svcMonitor run failed")
        print(f"STDOUT={out[:500]}")
        print(f"STDERR={err[:500]}")
        print("STATUS=FAILED")
        sys.exit(1)


if __name__ == "__main__":
    main()
