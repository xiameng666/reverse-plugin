#!/usr/bin/env python3
"""svcmon CLI — stackplz-based syscall monitoring + HTML report generation.

Usage:
  svcmon setup                         Interactive setup (download stackplz, set output dir)
  svcmon run <package> [options]        Monitor app + generate report
  svcmon parse <trace> [options]        Parse existing trace to HTML
  svcmon config show                    Show config
  svcmon config set <key> <value>       Set config value
"""

import json
import os
import platform
import subprocess
import sys
import webbrowser
from datetime import datetime
from pathlib import Path
from typing import Optional

# ─── Inline config (no external deps except click) ───

CONFIG_DIR = os.path.join(os.path.expanduser("~"), ".svcmon")
CONFIG_FILE = os.path.join(CONFIG_DIR, "svcmon_config.json")
STACKPLZ_REPO = "SeeFlowerX/stackplz"
STACKPLZ_API = f"https://api.github.com/repos/{STACKPLZ_REPO}/releases/latest"
DEVICE_STACKPLZ_DIR = "/data/local/tmp/re"
DEVICE_STACKPLZ_BIN = f"{DEVICE_STACKPLZ_DIR}/stackplz"

try:
    import click
except ImportError:
    print("Error: click not installed. Run: pip install click")
    sys.exit(1)


def _load_config():
    if os.path.isfile(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            return json.load(f)
    return {}


def _save_config(cfg):
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        json.dump(cfg, f, indent=2)


def _output_root(cfg=None):
    if cfg is None:
        cfg = _load_config()
    r = cfg.get("output_root", "~/re/svcmon")
    return os.path.expanduser(r)


def _is_windows():
    return platform.system() == "Windows"


def _adb_env():
    env = os.environ.copy()
    if _is_windows():
        env["MSYS_NO_PATHCONV"] = "1"
    return env


def _adb_base(serial=None):
    cmd = ["adb"]
    if serial:
        cmd += ["-s", serial]
    return cmd


def _adb_shell(cmd, serial=None, timeout=30):
    full = _adb_base(serial) + ["shell", cmd]
    r = subprocess.run(full, capture_output=True, text=True,
                       timeout=timeout, env=_adb_env())
    if r.returncode != 0 and not r.stdout.strip():
        raise RuntimeError(r.stderr.strip())
    return r.stdout


def _adb_shell_su(cmd, serial=None, timeout=30):
    return _adb_shell(f"su -c '{cmd}'", serial=serial, timeout=timeout)


def _adb_pull(remote, local, serial=None):
    full = _adb_base(serial) + ["push" if False else "pull", remote, local]
    r = subprocess.run(full, capture_output=True, text=True, env=_adb_env(), timeout=60)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())


def _resolve_package(keyword, serial=None):
    """Resolve a keyword to full package name. Supports partial match.

    Returns (full_package_name, uid) or (None, None).
    """
    # First try exact match: check if this is a real installed package
    try:
        out = _adb_shell(f"pm list packages {keyword}", serial=serial, timeout=10)
        exact = [l.strip()[8:] for l in out.splitlines()
                 if l.strip() == f"package:{keyword}"]
        if exact:
            uid = _get_uid(keyword, serial)
            if uid:
                return keyword, uid
    except RuntimeError:
        pass

    # Partial match: grep installed packages
    try:
        out = _adb_shell("pm list packages", serial=serial, timeout=15)
        matches = []
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("package:"):
                pkg = line[8:]
                if keyword.lower() in pkg.lower():
                    matches.append(pkg)

        if len(matches) == 0:
            return None, None
        if len(matches) == 1:
            pkg = matches[0]
            uid = _get_uid(pkg, serial)
            return pkg, uid
        # Multiple matches — show and let user pick
        click.echo(f"  Found {len(matches)} packages matching '{keyword}':")
        for i, m in enumerate(matches):
            click.echo(f"    [{i}] {m}")
        choice = click.prompt("  Select", type=int, default=0)
        if 0 <= choice < len(matches):
            pkg = matches[choice]
            uid = _get_uid(pkg, serial)
            return pkg, uid
        return None, None
    except RuntimeError:
        return None, None


def _get_uid(package, serial=None):
    try:
        out = _adb_shell(f"dumpsys package {package}", serial=serial, timeout=15)
        for line in out.splitlines():
            if "userId=" in line:
                for part in line.split():
                    if part.startswith("userId="):
                        try:
                            return int(part.split("=")[1])
                        except ValueError:
                            pass
    except RuntimeError:
        pass
    return None


# ─── Syscall categories (from SVCMonitors project) ───

CATEGORIES = {
    '文件操作': ['openat', 'close', 'faccessat', 'unlinkat', 'readlinkat',
                'getdents64', 'read', 'write', 'newfstatat', 'statx', 'renameat2', 'mkdirat'],
    '进程管理': ['clone', 'clone3', 'execve', 'execveat', 'exit', 'exit_group',
                'wait4', 'prctl', 'ptrace'],
    '内存管理': ['mmap', 'mprotect', 'munmap', 'brk', 'mincore', 'madvise',
                'memfd_create', 'process_vm_readv', 'process_vm_writev'],
    '网络通信': ['socket', 'bind', 'listen', 'connect', 'accept', 'accept4',
                'sendto', 'recvfrom'],
    '信号处理': ['kill', 'tgkill', 'rt_sigaction'],
    '安全相关': ['seccomp', 'setns', 'unshare', 'bpf'],
    'Tier2': ['ioctl', 'lseek', 'readv', 'writev', 'fcntl', 'sendfile',
              'sendmsg', 'recvmsg', 'setsockopt', 'getsockopt', 'mount',
              'umount2', 'prlimit64', 'capget', 'capset', 'setuid', 'setgid',
              'finit_module', 'init_module', 'delete_module'],
}

BASE_SC = 'openat,close,mmap,mprotect,munmap'


def _cat_sc(*names):
    scs = []
    for n in names:
        scs.extend(CATEGORIES.get(n, []))
    return ','.join(scs)


PRESETS = {
    're_basic': _cat_sc('文件操作', '进程管理', '信号处理'),
    're_full': _cat_sc('文件操作', '进程管理', '内存管理', '网络通信', '信号处理', '安全相关'),
    'file': _cat_sc('文件操作'),
    'proc': _cat_sc('进程管理', '信号处理'),
    'mem': _cat_sc('内存管理'),
    'net': _cat_sc('网络通信'),
    'security': _cat_sc('安全相关'),
    'all': 'all',
}


def _dedup(s):
    seen = []
    for x in s.split(','):
        x = x.strip()
        if x and x not in seen:
            seen.append(x)
    return ','.join(seen)


def _ensure_stackplz(serial=None):
    """Check if stackplz exists on device, push if not."""
    cfg = _load_config()
    try:
        out = _adb_shell_su(f"ls {DEVICE_STACKPLZ_BIN}", serial=serial, timeout=5)
        if DEVICE_STACKPLZ_BIN in out:
            return True
    except RuntimeError:
        pass

    # Try to push from local
    local = cfg.get("stackplz_local")
    if local and os.path.isfile(local):
        click.echo("  Pushing stackplz to device...")
        _adb_shell_su(f"mkdir -p {DEVICE_STACKPLZ_DIR}", serial=serial, timeout=5)
        full = _adb_base(serial) + ["push", local, DEVICE_STACKPLZ_BIN]
        subprocess.run(full, capture_output=True, env=_adb_env(), timeout=30)
        _adb_shell_su(f"chmod 755 {DEVICE_STACKPLZ_BIN}", serial=serial, timeout=5)
        return True

    click.echo("  stackplz not found. Run: svcmon setup")
    return False


# ─── CLI ───

@click.group()
def cli():
    """svcmon — Stackplz syscall monitoring + analysis"""
    pass


# ─── setup ───

@cli.command()
def setup():
    """Download stackplz + configure output directory."""
    import urllib.request

    cfg = _load_config()
    click.echo("=" * 50)
    click.echo("  svcmon Setup")
    click.echo("=" * 50)

    # Output dir
    current = cfg.get("output_root", "~/re/svcmon")
    click.echo(f"\n[1/3] Output directory: {current}")
    new = click.prompt("  Path", default=current)
    cfg["output_root"] = new
    actual = os.path.expanduser(new)
    os.makedirs(actual, exist_ok=True)
    click.echo(f"  → {actual}")

    # Download stackplz
    click.echo("\n[2/3] Downloading stackplz...")
    try:
        req = urllib.request.Request(STACKPLZ_API, headers={"User-Agent": "svcmon"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read())
        tag = data.get("tag_name", "?")
        url = None
        for a in data.get("assets", []):
            if a["name"] == "stackplz":
                url = a["browser_download_url"]
                break
        if url:
            local = os.path.join(CONFIG_DIR, "stackplz")
            os.makedirs(CONFIG_DIR, exist_ok=True)
            click.echo(f"  {tag}: {url}")
            urllib.request.urlretrieve(url, local)
            cfg["stackplz_version"] = tag
            cfg["stackplz_local"] = local
            click.echo(f"  Saved: {local} ({os.path.getsize(local) // 1024}KB)")
        else:
            click.echo("  No binary found in release")
    except Exception as e:
        click.echo(f"  Download failed: {e}")

    # Push to device
    click.echo("\n[3/3] Push to device")
    try:
        r = subprocess.run(["adb", "devices"], capture_output=True, text=True)
        devs = [l for l in r.stdout.splitlines() if "\tdevice" in l]
        if devs:
            click.echo(f"  Device: {devs[0].split()[0]}")
            _save_config(cfg)
            _ensure_stackplz()
        else:
            click.echo("  No device. Skipping.")
    except FileNotFoundError:
        click.echo("  adb not found.")

    _save_config(cfg)
    click.echo(f"\nConfig: {CONFIG_FILE}")
    click.echo("Done!")


# ─── run ───

@cli.command()
@click.argument("package")
@click.option("--preset", default="re_basic",
              type=click.Choice(list(PRESETS.keys())), help="Syscall preset")
@click.option("--duration", default="15s", help="Wait after launch")
@click.option("-o", "--output", default=None, help="Output directory (overrides config)")
@click.option("-s", "--serial", default=None, help="ADB device serial")
@click.option("--open/--no-open", "open_browser", default=False)
@click.option("--json", "json_mode", is_flag=True)
def run(package, preset, duration, output, serial, open_browser, json_mode):
    """Monitor APP syscalls and generate HTML report."""
    cfg = _load_config()
    if not serial:
        serial = cfg.get("serial")

    dur_sec = _parse_dur(duration)
    if dur_sec <= 0:
        click.echo(f"Invalid duration: {duration}")
        return

    # Output dir
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    if output:
        out_dir = Path(output)
    else:
        root = _output_root(cfg)
        out_dir = Path(root) / f"{package}_{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    trace_dev = "/data/local/tmp/agent_trace.log"
    zygote_dev = "/data/local/tmp/zygote_maps.txt"
    trace_local = str(out_dir / "trace.log")
    zygote_local = str(out_dir / "zygote_maps.txt")
    html_path = str(out_dir / "report.html")

    # 1. Resolve package
    click.echo(f"[1/7] Resolving {package}...")
    package, uid = _resolve_package(package, serial)
    if not package or not uid:
        click.echo("  No matching package found")
        return
    click.echo(f"  {package} (UID: {uid})")

    # 2. Syscalls
    click.echo(f"[2/7] Preset: {preset}")
    psc = PRESETS[preset]
    all_sc = "all" if psc == "all" else _dedup(BASE_SC + "," + psc)

    # 3. Ensure stackplz
    click.echo("[3/7] Checking stackplz...")
    if not _ensure_stackplz(serial):
        return

    # 4. Zygote maps
    click.echo("[4/7] Zygote maps...")
    try:
        _adb_shell_su(f"cat /proc/$(pidof zygote64)/maps > {zygote_dev}",
                      serial=serial, timeout=10)
        _adb_pull(zygote_dev, zygote_local, serial=serial)
        click.echo("  OK")
    except RuntimeError:
        click.echo("  Warning: failed")
        zygote_local = None

    # 5. stackplz + pm clear + launch
    click.echo(f"[5/7] stackplz → clear → wait 5s → launch → wait {dur_sec}s...")
    cmd = (
        f"cd {DEVICE_STACKPLZ_DIR} && "
        f"am force-stop {package} 2>/dev/null; "
        f"./stackplz -n {package} -s {all_sc} --stack --showtime -b 32 "
        f"> {trace_dev} 2>&1 & "
        f"SPID=$! && "
        f"pm clear {package} && "
        f"sleep 5 && "
        f"monkey -p {package} -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1 && "
        f"sleep {dur_sec} && "
        f"kill $SPID 2>/dev/null; wait $SPID 2>/dev/null"
    )
    try:
        _adb_shell_su(cmd, serial=serial, timeout=5 + dur_sec + 30)
    except RuntimeError:
        pass
    click.echo("  Done")

    # 6. Pull trace + APK
    click.echo("[6/7] Pulling trace + APK...")
    try:
        _adb_pull(trace_dev, trace_local, serial=serial)
        sz = os.path.getsize(trace_local)
        click.echo(f"  trace: {sz // 1024}KB")
    except RuntimeError as e:
        click.echo(f"  Failed: {e}")
        return

    apk_local = None
    apk_device = None
    try:
        info = _adb_shell_su(f"pm path {package}", serial=serial, timeout=10)
        paths = [l.strip()[8:] for l in info.splitlines() if l.strip().startswith("package:")]
        for p in paths:
            if "split_config.arm64" in p:
                apk_device = p
                break
        if not apk_device:
            for p in paths:
                if "base.apk" in p:
                    apk_device = p
                    break
        if not apk_device and paths:
            apk_device = paths[0]
        if apk_device:
            apk_local = str(out_dir / apk_device.rsplit("/", 1)[-1])
            _adb_pull(apk_device, apk_local, serial=serial)
            click.echo(f"  apk: {apk_device.rsplit('/', 1)[-1]}")
    except RuntimeError:
        pass

    # 7. Parse + HTML
    click.echo("[7/7] Generating report...")
    from .core.trace_parser import parse_trace, merge_entry_return, categorize_event
    from .core.maps_reconstructor import MapsReconstructor
    from .core.html_report import generate_html_report

    with open(trace_local, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    events, lost = parse_trace(raw)
    merged = merge_entry_return(events)

    recon = MapsReconstructor()
    if zygote_local and os.path.isfile(zygote_local):
        n = recon.load_baseline_file(zygote_local)
        click.echo(f"  baseline: {n} regions")
    if apk_local and os.path.isfile(apk_local) and apk_device:
        recon.register_local_apk(apk_device, apk_local)
    recon.process_events(merged)

    for ev in merged:
        ev["category"] = categorize_event(ev)

    det_cats = {"anti_debug", "fd_scan", "maps_scan", "thread_scan",
                "mem_probe", "mount_check", "self_kill", "cmdline_check"}
    det_n = sum(1 for ev in merged if ev.get("category") in det_cats)

    html = generate_html_report(
        events=merged, reconstructor=recon, package=package,
        uid=uid, duration_sec=dur_sec, total_lost=lost,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    Path(html_path).write_text(html, encoding="utf-8")

    # Output
    result = {
        "events": len(merged), "detections": det_n, "lost": lost,
        "regions": len(recon.get_region_summary()),
        "trace": trace_local, "report": html_path, "output_dir": str(out_dir),
        "package": package, "uid": uid,
    }

    if json_mode:
        click.echo(json.dumps({"ok": True, **result}, indent=2))
    else:
        click.echo(f"\n  Events:     {result['events']}")
        click.echo(f"  Detections: {result['detections']}")
        click.echo(f"  Lost:       {result['lost']}")
        click.echo(f"  Report:     {html_path}")
        click.echo(f"  Trace:      {trace_local}")

    if open_browser:
        webbrowser.open(f"file://{os.path.abspath(html_path)}")


# ─── parse ───

@cli.command()
@click.argument("trace_file", type=click.Path(exists=True))
@click.option("-p", "--package", default="unknown")
@click.option("--maps", "maps_file", default=None, type=click.Path(exists=True))
@click.option("--apk", "apk_file", default=None, type=click.Path(exists=True))
@click.option("-o", "--output", default=None)
@click.option("--open/--no-open", "open_browser", default=True)
def parse(trace_file, package, maps_file, apk_file, output, open_browser):
    """Parse existing stackplz trace to HTML report."""
    from .core.trace_parser import parse_trace, merge_entry_return, categorize_event
    from .core.maps_reconstructor import MapsReconstructor
    from .core.html_report import generate_html_report

    if output:
        html_path = output
    else:
        base = os.path.splitext(os.path.basename(trace_file))[0]
        html_path = f"{base}_report.html"

    click.echo(f"Parsing {trace_file}...")
    with open(trace_file, "r", encoding="utf-8", errors="replace") as f:
        raw = f.read()

    events, lost = parse_trace(raw)
    merged = merge_entry_return(events)

    recon = MapsReconstructor()
    if maps_file:
        n = recon.load_baseline_file(maps_file)
        click.echo(f"  baseline: {n} regions")
    if apk_file:
        recon.register_local_apk(os.path.basename(apk_file), apk_file)
    recon.process_events(merged)

    for ev in merged:
        ev["category"] = categorize_event(ev)

    det_cats = {"anti_debug", "fd_scan", "maps_scan", "thread_scan",
                "mem_probe", "mount_check", "self_kill", "cmdline_check"}
    det_n = sum(1 for ev in merged if ev.get("category") in det_cats)

    html = generate_html_report(
        events=merged, reconstructor=recon, package=package,
        uid=None, duration_sec=0, total_lost=lost,
        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    Path(html_path).write_text(html, encoding="utf-8")

    click.echo(f"  Events:     {len(merged)}")
    click.echo(f"  Detections: {det_n}")
    click.echo(f"  Report:     {html_path}")

    if open_browser:
        webbrowser.open(f"file://{os.path.abspath(html_path)}")


# ─── config ───

@cli.group("config")
def config_group():
    """Configuration."""
    pass


@config_group.command("show")
def config_show():
    """Show config."""
    cfg = _load_config()
    click.echo(f"Config: {CONFIG_FILE}")
    click.echo(f"Output: {_output_root(cfg)}")
    for k, v in sorted(cfg.items()):
        click.echo(f"  {k}: {v}")


@config_group.command("set")
@click.argument("key")
@click.argument("value")
def config_set(key, value):
    """Set config value (output_root, serial, etc)."""
    cfg = _load_config()
    cfg[key] = value
    _save_config(cfg)
    if key == "output_root":
        actual = os.path.expanduser(value)
        os.makedirs(actual, exist_ok=True)
        click.echo(f"Set {key} = {value} → {actual}")
    else:
        click.echo(f"Set {key} = {value}")


def _parse_dur(s):
    s = s.strip().lower()
    if s.endswith("m"):
        return int(s[:-1]) * 60
    if s.endswith("s"):
        return int(s[:-1])
    return int(s)
