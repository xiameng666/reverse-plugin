"""Parse stackplz text trace output into structured Python dicts.

Handles two backtrace formats:
  Format A (full):   #00 pc 00000000000ac878  /path/to/lib.so (symbol+offset)
  Format B (short):  \\t0x7df1e60878 <lib.so + 0xac878>

Entry events carry arguments (and possibly a path in parentheses).
Return events carry a ret= field.
Events are correlated by (tid, syscall) sequential ordering.
"""

import re
from typing import Any, Dict, List, Optional, Tuple

# Main event line:
# [timestamp|PID|TID|thread] syscall(args...) LR:0x... PC:0x... SP:0x..., Backtrace:
# OR return event (no LR/PC/SP, has ret=):
# [timestamp|PID|TID|thread] syscall(args..., ret=N)
_RE_EVENT = re.compile(
    r'^\[(\d+)\|(\d+)\|(\d+)\|([^\]]+)\]\s+'
    r'(\w+)\((.+)\)'
    r'(?:\s+LR:(0x[\da-fA-F]+)\s+PC:(0x[\da-fA-F]+)\s+SP:(0x[\da-fA-F]+))?'
)

# Backtrace format A (full):
#   #00 pc 00000000000ac878  /path/to/lib.so (symbol+offset)
_RE_BT_FULL = re.compile(
    r'^\s+#(\d+)\s+pc\s+([\da-fA-F]+)\s+'
    r'(\S+)'
    r'(?:\s+\((.+?)\))?'
)

# Backtrace format B (short, tab-prefixed):
#   0x7df1e60878 <lib.so + 0xac878>
_RE_BT_SHORT = re.compile(
    r'^\t(0x[\da-fA-F]+)\s+<(.+?)\s*\+\s*(0x[\da-fA-F]+)>'
)

# Also handle <unknown> in short format:
#   0x13022ab813022aa0 <unknown>
_RE_BT_SHORT_UNKNOWN = re.compile(
    r'^\t(0x[\da-fA-F]+)\s+<unknown>'
)

# Extract path from *pathname=0x...(/actual/path)
_RE_PATHNAME = re.compile(r'\*pathname=0x[\da-fA-F]+\(([^)]+)\)')

# Extract ret= value from args string
_RE_RET = re.compile(r'ret=(-?\d+|0x[\da-fA-F]+)')

# TotalLost line
_RE_TOTAL_LOST = re.compile(r'^TotalLost\s*=>\s*(\d+)')


def _parse_hex(s: str) -> int:
    """Parse hex or decimal string to int."""
    if s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    return int(s)


def _parse_ret(val_str: str) -> int:
    """Parse a ret value which may be hex or decimal (possibly negative)."""
    val_str = val_str.strip()
    if val_str.startswith('0x') or val_str.startswith('0X'):
        return int(val_str, 16)
    return int(val_str)


def _is_return_event(args_str: str) -> bool:
    """Check if this is a return event (has ret= in args)."""
    return 'ret=' in args_str


def _extract_pathname(args_str: str) -> Optional[str]:
    """Extract pathname from openat/readlinkat entry args."""
    m = _RE_PATHNAME.search(args_str)
    if m:
        return m.group(1)
    return None


def _extract_ret(args_str: str) -> Optional[int]:
    """Extract ret value from return event args."""
    m = _RE_RET.search(args_str)
    if m:
        return _parse_ret(m.group(1))
    return None


def _extract_buf_path(args_str: str) -> Optional[str]:
    """Extract resolved path from readlinkat return: buf=0x...(/actual/path)."""
    m = re.search(r'buf=0x[\da-fA-F]+\(([^)]+)\)', args_str)
    if m:
        return m.group(1)
    return None


def _parse_args_dict(args_str: str) -> Dict[str, str]:
    """Best-effort parse of key=value args from syscall args string.

    This handles nested parens like prot=0x5(PROT_READ|PROT_EXEC).
    """
    result = {}
    depth = 0
    current_key = ''
    current_val = ''
    in_value = False
    i = 0
    while i < len(args_str):
        c = args_str[i]
        if c == '(' and in_value:
            depth += 1
            current_val += c
        elif c == ')' and in_value and depth > 0:
            depth -= 1
            current_val += c
        elif c == ',' and depth == 0:
            if current_key:
                result[current_key.strip()] = current_val.strip()
            current_key = ''
            current_val = ''
            in_value = False
        elif c == '=' and not in_value:
            in_value = True
        elif in_value:
            current_val += c
        else:
            current_key += c
        i += 1

    if current_key:
        result[current_key.strip()] = current_val.strip()

    return result


def parse_trace(text: str) -> Tuple[List[Dict[str, Any]], int]:
    """Parse a stackplz trace log into structured events.

    Returns:
        (events, total_lost) where events is a list of dicts and
        total_lost is the maximum TotalLost value seen.
    """
    lines = text.splitlines()
    events: List[Dict[str, Any]] = []
    total_lost = 0
    current_event: Optional[Dict[str, Any]] = None
    current_bt: List[Dict[str, Any]] = []
    bt_index = 0

    def _flush():
        nonlocal current_event, current_bt, bt_index
        if current_event is not None:
            if current_bt:
                current_event['backtrace'] = current_bt
            events.append(current_event)
        current_event = None
        current_bt = []
        bt_index = 0

    for line in lines:
        # Check TotalLost
        m_lost = _RE_TOTAL_LOST.match(line)
        if m_lost:
            val = int(m_lost.group(1))
            if val > total_lost:
                total_lost = val
            continue

        # Skip noise lines
        if line.startswith('read next_fp') or line.startswith('warn,') or \
           line.startswith('hook syscall') or line.startswith('ConfigMap') or \
           line.startswith('uid =>') or line.startswith('pid =>') or \
           line.startswith('tid =>') or line.startswith('start ') or \
           line.startswith('PerfMod') or line.startswith('mod Close'):
            continue

        # Try event line
        m_event = _RE_EVENT.match(line)
        if m_event:
            _flush()
            timestamp = int(m_event.group(1))
            pid = int(m_event.group(2))
            tid = int(m_event.group(3))
            thread = m_event.group(4)
            syscall = m_event.group(5)
            args_raw = m_event.group(6)
            lr = _parse_hex(m_event.group(7)) if m_event.group(7) else None
            pc = _parse_hex(m_event.group(8)) if m_event.group(8) else None
            sp = _parse_hex(m_event.group(9)) if m_event.group(9) else None

            is_ret = _is_return_event(args_raw)
            pathname = _extract_pathname(args_raw)
            ret_val = _extract_ret(args_raw) if is_ret else None
            buf_path = _extract_buf_path(args_raw) if is_ret else None

            current_event = {
                'timestamp': timestamp,
                'pid': pid,
                'tid': tid,
                'thread': thread,
                'syscall': syscall,
                'args_raw': args_raw,
                'is_return': is_ret,
                'lr': lr,
                'pc': pc,
                'sp': sp,
            }

            if pathname:
                current_event['pathname'] = pathname
            if ret_val is not None:
                current_event['ret'] = ret_val
            if buf_path:
                current_event['buf_path'] = buf_path

            # Parse structured args
            args_dict = _parse_args_dict(args_raw)
            current_event['args'] = args_dict

            continue

        # Try backtrace format A (full)
        m_bt_full = _RE_BT_FULL.match(line)
        if m_bt_full and current_event is not None:
            frame = {
                'index': int(m_bt_full.group(1)),
                'pc_offset': int(m_bt_full.group(2), 16),
                'module': m_bt_full.group(3),
                'symbol': m_bt_full.group(4),
            }
            current_bt.append(frame)
            continue

        # Try backtrace format B (short)
        m_bt_short = _RE_BT_SHORT.match(line)
        if m_bt_short and current_event is not None:
            frame = {
                'index': bt_index,
                'abs_addr': int(m_bt_short.group(1), 16),
                'module': m_bt_short.group(2).strip(),
                'pc_offset': int(m_bt_short.group(3), 16),
                'symbol': None,
            }
            current_bt.append(frame)
            bt_index += 1
            continue

        # Try backtrace format B (unknown)
        m_bt_unk = _RE_BT_SHORT_UNKNOWN.match(line)
        if m_bt_unk and current_event is not None:
            frame = {
                'index': bt_index,
                'abs_addr': int(m_bt_unk.group(1), 16),
                'module': '<unknown>',
                'pc_offset': None,
                'symbol': None,
            }
            current_bt.append(frame)
            bt_index += 1
            continue

    _flush()
    return events, total_lost


def merge_entry_return(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge entry and return events by (tid, syscall) sequential ordering.

    For each entry event, find the next return event with same tid+syscall
    and merge ret value into the entry event.  Return events that don't
    match an entry are kept standalone.

    The merged list is sorted by timestamp.
    """
    # Group by (tid, syscall)
    from collections import defaultdict
    pending: Dict[Tuple[int, str], List[Dict[str, Any]]] = defaultdict(list)
    merged = []
    returns_used = set()

    # First pass: index entry events by (tid, syscall)
    entries_by_key: Dict[Tuple[int, str], List[int]] = defaultdict(list)
    for i, ev in enumerate(events):
        if not ev.get('is_return'):
            entries_by_key[(ev['tid'], ev['syscall'])].append(i)

    # Second pass: match return events to entries
    entry_cursors: Dict[Tuple[int, str], int] = defaultdict(int)
    for i, ev in enumerate(events):
        if ev.get('is_return'):
            key = (ev['tid'], ev['syscall'])
            cursor = entry_cursors[key]
            entry_indices = entries_by_key.get(key, [])
            # Find the entry that comes before this return
            matched_idx = None
            while cursor < len(entry_indices):
                eidx = entry_indices[cursor]
                if events[eidx]['timestamp'] <= ev['timestamp']:
                    matched_idx = eidx
                    cursor += 1
                else:
                    break
            entry_cursors[key] = cursor

            if matched_idx is not None and matched_idx not in returns_used:
                # Merge ret into entry
                entry = events[matched_idx]
                if ev.get('ret') is not None:
                    entry['ret'] = ev['ret']
                if ev.get('buf_path'):
                    entry['buf_path'] = ev['buf_path']
                entry['has_return'] = True
                returns_used.add(i)
            # else: unmatched return, skip it

    # Collect all entry events (now with merged ret) and unmatched returns
    result = []
    for i, ev in enumerate(events):
        if i in returns_used:
            continue
        if ev.get('is_return') and i not in returns_used:
            # Standalone return with no matching entry - keep if it has useful info
            continue
        result.append(ev)

    result.sort(key=lambda e: e['timestamp'])
    return result


def categorize_event(ev: Dict[str, Any]) -> str:
    """Classify a parsed event into a detection category.

    Returns one of: 'anti_debug', 'fd_scan', 'maps_scan', 'thread_scan',
    'mem_probe', 'mount_check', 'self_kill', 'cmdline_check', 'fd_bruteclose',
    'file', 'process', 'memory', 'network', 'normal'.
    """
    sc = ev.get('syscall', '')
    pathname = ev.get('pathname', '')
    args_raw = ev.get('args_raw', '')

    # ── Anti-debug: ptrace ──
    if sc == 'ptrace':
        return 'anti_debug'

    # ── Anti-debug: suspicious prctl ──
    if sc == 'prctl':
        if any(p in args_raw for p in ('PR_SET_DUMPABLE', 'PR_SET_PTRACER',
                                        'PR_GET_DUMPABLE', 'PR_SET_SECCOMP')):
            return 'anti_debug'

    # ── Self-kill ──
    if sc in ('kill', 'tgkill'):
        return 'self_kill'

    # ── /proc/self probing (openat, faccessat, readlinkat) ──
    if pathname:
        # FD scanning: readlinkat /proc/self/fd/*
        if sc == 'readlinkat' and '/proc/self/fd/' in pathname:
            return 'fd_scan'
        # readlinkat /proc/self/exe — check process binary
        if sc == 'readlinkat' and '/proc/self/exe' in pathname:
            return 'anti_debug'

        # openat / faccessat on /proc/self/*
        if sc in ('openat', 'faccessat', 'readlinkat'):
            if '/proc/self/maps' in pathname:
                return 'maps_scan'
            if '/proc/self/smaps' in pathname:
                return 'mem_probe'
            if '/proc/self/mem' == pathname or pathname.endswith('/proc/self/mem'):
                return 'mem_probe'
            if re.search(r'/proc/self/task/\d+/comm', pathname):
                return 'thread_scan'
            if '/proc/self/task' == pathname or pathname.endswith('/proc/self/task'):
                return 'thread_scan'
            if '/proc/self/fd' == pathname or pathname.endswith('/proc/self/fd'):
                return 'fd_scan'
            if '/proc/self/mountinfo' in pathname or '/proc/self/mounts' in pathname:
                return 'mount_check'
            if '/proc/self/cmdline' in pathname:
                return 'cmdline_check'
            if '/proc/self/status' in pathname:
                return 'anti_debug'
            if '/proc/self/wchan' in pathname:
                return 'anti_debug'
            if '/proc/self/attr' in pathname:
                return 'anti_debug'
            # /proc/net/tcp — check open sockets (frida detection)
            if '/proc/net/tcp' in pathname or '/proc/net/unix' in pathname:
                return 'anti_debug'
            # Generic /proc/self/ access that doesn't match above
            if '/proc/self/' in pathname:
                return 'mem_probe'

    # ── Suspicious file paths ──
    if sc in ('openat', 'faccessat') and pathname:
        lower = pathname.lower()
        sus_keywords = ('frida', 'xposed', 'magisk', 'libgadget', 'substrate',
                        'riru', 'edxp', 'zygisk', 'busybox', 'supersu',
                        '/sbin/su', '/system/xbin/su', '/system/bin/su')
        if any(s in lower for s in sus_keywords):
            return 'anti_debug'
        # /data/local/tmp — often used by tools
        if '/data/local/tmp' in pathname:
            return 'anti_debug'

    # ── seccomp / bpf — sandbox escape or monitoring detection ──
    if sc == 'seccomp':
        return 'anti_debug'
    if sc == 'bpf':
        return 'anti_debug'

    # ── Memory operations ──
    if sc in ('mmap', 'mprotect', 'munmap', 'madvise'):
        return 'memory'

    # ── Process ──
    if sc in ('clone', 'clone3', 'execve', 'exit_group', 'prctl',
              'exit', 'wait4'):
        return 'process'

    # ── Network ──
    if sc in ('socket', 'connect', 'bind', 'sendto', 'recvfrom', 'accept',
              'accept4'):
        return 'network'

    # ── File ──
    if sc in ('openat', 'close', 'read', 'write', 'readlinkat', 'faccessat',
              'newfstatat', 'unlinkat', 'getdents64', 'lseek', 'statx',
              'fstat', 'pread64', 'writev'):
        return 'file'

    return 'normal'


def detect_fd_bruteclose(events: List[Dict[str, Any]],
                         threshold: int = 50) -> List[Dict[str, Any]]:
    """Detect fd brute-close patterns: a thread doing massive sequential close().

    Returns list of summary dicts for threads that did brute-close.
    Silicon does this with Thread-4: close fd 0~15000.
    """
    from collections import defaultdict, Counter
    tid_close_count = Counter()
    tid_info = {}

    for ev in events:
        if ev['syscall'] == 'close':
            tid = ev.get('tid', 0)
            tid_close_count[tid] += 1
            if tid not in tid_info:
                tid_info[tid] = {
                    'thread': ev.get('thread', '?'),
                    'first_ts': ev.get('timestamp', 0),
                }
            tid_info[tid]['last_ts'] = ev.get('timestamp', 0)

    results = []
    for tid, count in tid_close_count.items():
        if count >= threshold:
            info = tid_info[tid]
            results.append({
                'tid': tid,
                'thread': info['thread'],
                'close_count': count,
                'first_ts': info['first_ts'],
                'last_ts': info['last_ts'],
            })
    return results
