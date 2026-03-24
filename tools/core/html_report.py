"""Generate a self-contained HTML report for stackplz trace analysis.

Tab-based layout, high information density, no fluff.
Tabs: Overview | Detection | Threads | File Access | Strings | Full Log
"""

import html
import json
import re
from collections import Counter, defaultdict
from typing import Any, Dict, List, Optional

from .trace_parser import categorize_event
from .maps_reconstructor import (
    MapsReconstructor, symbolize_backtrace, format_backtrace_line,
)

# Import categories from CLI (avoid circular by lazy import)
def _get_categories():
    try:
        from ..svcmon_cli import SYSCALL_CATEGORIES, _SC_TO_CAT
        return SYSCALL_CATEGORIES, _SC_TO_CAT
    except ImportError:
        return {}, {}


def _esc(s: str) -> str:
    return html.escape(str(s), quote=True)


def generate_html_report(
    events: List[Dict[str, Any]],
    reconstructor: MapsReconstructor,
    package: str = "unknown",
    uid: Optional[int] = None,
    duration_sec: int = 0,
    total_lost: int = 0,
    timestamp: str = "",
) -> str:
    """Generate self-contained HTML report."""

    # Categorize
    for ev in events:
        if 'category' not in ev:
            ev['category'] = categorize_event(ev)

    # Symbolize backtraces
    for ev in events:
        if ev.get('backtrace'):
            ev['sym_bt'] = symbolize_backtrace(ev['backtrace'], reconstructor)

    # Gather stats
    total = len(events)
    sc_counts = Counter(ev['syscall'] for ev in events)
    cat_counts = Counter(ev.get('category', 'normal') for ev in events)
    pids = set(ev.get('pid', 0) for ev in events)
    tids = set(ev.get('tid', 0) for ev in events)

    # Thread info
    thread_info = _build_thread_info(events)

    # Detection events
    det_cats = {'anti_debug', 'fd_scan', 'maps_scan', 'thread_scan',
                'mem_probe', 'mount_check', 'self_kill', 'cmdline_check'}
    det_events = [ev for ev in events if ev.get('category') in det_cats]

    # File access
    file_events = [ev for ev in events
                   if ev['syscall'] in ('openat', 'faccessat', 'readlinkat')
                   and ev.get('pathname')]

    # Strings
    strings = _extract_strings(events)

    # Regions
    regions = reconstructor.get_region_summary()

    parts = []
    parts.append(_html_head(package, timestamp))
    parts.append(_tab_bar())
    parts.append(_tab_overview(package, uid, timestamp, duration_sec, total,
                               total_lost, sc_counts, cat_counts, pids, tids, regions))
    parts.append(_tab_detection(det_events, reconstructor))
    parts.append(_tab_threads(thread_info, reconstructor))
    parts.append(_tab_by_thread(thread_info, reconstructor))
    parts.append(_tab_files(file_events))
    parts.append(_tab_strings(strings))
    parts.append(_tab_fulllog(events, reconstructor))
    parts.append(_html_foot())
    return '\n'.join(parts)


def _build_thread_info(events):
    """Group events by tid, extract clone/lifecycle info."""
    by_tid = defaultdict(list)
    for ev in events:
        by_tid[ev.get('tid', 0)].append(ev)

    threads = []
    for tid, evts in sorted(by_tid.items()):
        sc_counts = Counter(e['syscall'] for e in evts)
        names = set(e.get('thread', '') for e in evts if e.get('thread'))
        cats = Counter(e.get('category', 'normal') for e in evts)

        # Find clone event that created this thread
        clone_bt = None
        for e in evts:
            if e['syscall'] in ('clone', 'clone3') and e.get('sym_bt'):
                clone_bt = e['sym_bt']
                break

        threads.append({
            'tid': tid,
            'names': sorted(names),
            'count': len(evts),
            'syscalls': sc_counts,
            'categories': cats,
            'clone_bt': clone_bt,
            'first_ts': evts[0].get('timestamp', 0),
            'last_ts': evts[-1].get('timestamp', 0),
            'events': evts,
        })
    return threads


def _extract_strings(events):
    """Extract interesting strings from event args."""
    strings = defaultdict(int)
    for ev in events:
        path = ev.get('pathname')
        if path:
            strings[path] += 1
        # Also check desc-like fields
        args_raw = ev.get('args_raw', '')
        for m in re.finditer(r'/[\w/.\-@:]+', args_raw):
            p = m.group(0)
            if len(p) > 3:
                strings[p] += 1
    return sorted(strings.items(), key=lambda x: -x[1])


# ─── HTML Head ───

def _html_head(package, timestamp):
    return f'''<!DOCTYPE html>
<html><head>
<meta charset="UTF-8">
<title>{_esc(package)} - SvcMon Report</title>
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{ font-family: 'SF Mono','Consolas','Monaco',monospace; font-size:13px;
       background:#1a1a2e; color:#e0e0e0; }}
.header {{ padding:10px 16px; background:#16213e; border-bottom:1px solid #333;
           display:flex; gap:20px; align-items:center; flex-wrap:wrap; }}
.header h1 {{ font-size:16px; color:#0f0; }}
.header .meta {{ font-size:12px; color:#888; }}
.header .stat {{ background:#0d1b2a; padding:4px 10px; border-radius:4px; }}
.header .stat b {{ color:#4fc3f7; }}
.header .stat.warn b {{ color:#ff5252; }}

/* Tabs */
.tabs {{ display:flex; background:#0d1b2a; border-bottom:2px solid #333; padding:0 8px; }}
.tabs button {{ background:none; border:none; color:#888; padding:8px 16px; cursor:pointer;
               font-family:inherit; font-size:13px; border-bottom:2px solid transparent;
               margin-bottom:-2px; }}
.tabs button:hover {{ color:#ccc; }}
.tabs button.active {{ color:#4fc3f7; border-bottom-color:#4fc3f7; }}
.tab-content {{ display:none; padding:12px 16px; }}
.tab-content.active {{ display:block; }}

/* Tables */
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th {{ text-align:left; padding:6px 8px; background:#16213e; color:#4fc3f7;
     border-bottom:1px solid #333; position:sticky; top:0; }}
td {{ padding:4px 8px; border-bottom:1px solid #222; vertical-align:top; }}
tr:hover {{ background:#1a2744; }}
.mono {{ font-family:inherit; }}

/* Categories */
.cat {{ display:inline-block; padding:1px 6px; border-radius:3px; font-size:11px; }}
.cat-red {{ background:#5c1a1a; color:#ff5252; }}
.cat-orange {{ background:#5c3a1a; color:#ffa726; }}
.cat-blue {{ background:#1a3a5c; color:#4fc3f7; }}
.cat-green {{ background:#1a5c3a; color:#66bb6a; }}
.cat-grey {{ background:#333; color:#999; }}

/* Backtrace */
.bt {{ font-size:11px; color:#888; margin:4px 0 4px 16px; white-space:pre; }}
.bt .resolved {{ color:#4fc3f7; }}
.bt .unknown {{ color:#666; }}
.bt .invalid {{ color:#5c1a1a; }}
details {{ cursor:pointer; }}
details summary {{ color:#4fc3f7; }}
details summary:hover {{ color:#fff; }}

/* Search */
.search {{ width:100%; padding:6px 10px; background:#0d1b2a; border:1px solid #333;
          color:#e0e0e0; font-family:inherit; font-size:12px; margin-bottom:8px; }}
.search:focus {{ outline:none; border-color:#4fc3f7; }}

/* File list */
.path-suspicious {{ color:#ff5252; }}
.path-proc {{ color:#ffa726; }}
.path-normal {{ color:#aaa; }}
.count {{ color:#666; min-width:40px; display:inline-block; text-align:right; margin-right:8px; }}

/* Thread card */
.thread-card {{ background:#16213e; border:1px solid #333; border-radius:4px;
               padding:10px; margin-bottom:8px; }}
.thread-card h3 {{ font-size:13px; color:#4fc3f7; margin-bottom:6px; }}
.thread-card .sc-bar {{ display:flex; gap:2px; margin:4px 0; height:16px; }}
.thread-card .sc-bar span {{ display:inline-block; height:100%; min-width:2px; }}
.sc-file {{ background:#4fc3f7; }}  .sc-proc {{ background:#66bb6a; }}
.sc-mem {{ background:#ab47bc; }}   .sc-det {{ background:#ff5252; }}
.sc-other {{ background:#555; }}

/* Strings */
.str-row {{ padding:2px 0; }}
.str-val {{ word-break:break-all; }}

/* Scrollable */
.scroll-box {{ max-height:calc(100vh - 140px); overflow-y:auto; }}
</style>
</head><body>
'''


def _tab_bar():
    tabs = ['Overview', 'Detection', 'Threads', 'By Thread', 'Files', 'Strings', 'Full Log']
    btns = ''.join(
        f'<button onclick="switchTab(\'{t.lower().replace(" ","")}\', this)" '
        f'{"class=\\'active\\'" if i==0 else ""}>{t}</button>'
        for i, t in enumerate(tabs)
    )
    return f'<div class="tabs">{btns}</div>'


# ─── Tab: Overview ───

def _tab_overview(package, uid, timestamp, duration, total, lost,
                  sc_counts, cat_counts, pids, tids, regions):
    det_cats = {'anti_debug', 'fd_scan', 'maps_scan', 'thread_scan',
                'mem_probe', 'mount_check', 'self_kill'}
    det_total = sum(v for k, v in cat_counts.items() if k in det_cats)

    # Header
    uid_str = str(uid) if uid else '?'
    h = f'''<div class="header">
<h1>{_esc(package)}</h1>
<span class="meta">UID:{uid_str} | {_esc(timestamp)} | {duration}s</span>
<span class="stat"><b>{total}</b> events</span>
<span class="stat {'warn' if lost else ''}"><b>{lost}</b> lost</span>
<span class="stat"><b>{len(pids)}</b> PIDs</span>
<span class="stat"><b>{len(tids)}</b> TIDs</span>
<span class="stat {'warn' if det_total else ''}"><b>{det_total}</b> detections</span>
<span class="stat"><b>{len(regions)}</b> regions</span>
</div>'''

    # Syscall distribution grouped by SVC category
    categories, sc_to_cat = _get_categories()
    cat_groups = defaultdict(lambda: Counter())
    uncategorized = Counter()
    for sc, cnt in sc_counts.items():
        cat_name = sc_to_cat.get(sc)
        if cat_name:
            cat_groups[cat_name][sc] = cnt
        else:
            uncategorized[sc] = cnt

    sc_sections = []
    for cat_name, cat_info in categories.items():
        if cat_name not in cat_groups:
            continue
        icon = cat_info.get('icon', '')
        group_counts = cat_groups[cat_name]
        group_total = sum(group_counts.values())
        rows = ''.join(
            f'<tr><td style="padding-left:20px">{_esc(sc)}</td>'
            f'<td style="text-align:right">{cnt}</td></tr>'
            for sc, cnt in group_counts.most_common()
        )
        sc_sections.append(
            f'<tr style="background:#1a2744"><td><b>{icon} {_esc(cat_name)}</b></td>'
            f'<td style="text-align:right"><b>{group_total}</b></td></tr>{rows}'
        )

    if uncategorized:
        rows = ''.join(
            f'<tr><td style="padding-left:20px">{_esc(sc)}</td>'
            f'<td style="text-align:right">{cnt}</td></tr>'
            for sc, cnt in uncategorized.most_common()
        )
        unc_total = sum(uncategorized.values())
        sc_sections.append(
            f'<tr style="background:#1a2744"><td><b>其他</b></td>'
            f'<td style="text-align:right"><b>{unc_total}</b></td></tr>{rows}'
        )

    sc_table = f'<table>{"".join(sc_sections)}</table>'

    # Detection category summary
    det_labels = {
        'anti_debug': ('Anti-Debug', 'cat-red'),
        'fd_scan': ('FD Scan', 'cat-orange'),
        'maps_scan': ('Maps Scan', 'cat-orange'),
        'thread_scan': ('Thread Scan', 'cat-orange'),
        'mem_probe': ('Mem Probe', 'cat-orange'),
        'mount_check': ('Mount Check', 'cat-orange'),
        'self_kill': ('Self-Kill', 'cat-red'),
        'cmdline_check': ('Cmdline', 'cat-orange'),
    }
    det_tags = []
    for cat, count in cat_counts.most_common():
        if cat in det_labels:
            label, cls = det_labels[cat]
            det_tags.append(f'<span class="cat {cls}">{label}: {count}</span> ')

    det_section = ''
    if det_tags:
        det_section = f'<h3 style="margin:12px 0 6px;color:#ff5252">Detection Summary</h3><div>{"".join(det_tags)}</div>'

    return f'''{h}
<div id="tab-overview" class="tab-content active"><div class="scroll-box">
<div id="ai-analysis"></div>
{det_section}
<h3 style="margin:12px 0 6px;color:#4fc3f7">Syscall Distribution</h3>
{sc_table}
</div></div>'''


# ─── Tab: Detection ───

def _tab_detection(det_events, recon):
    parts = []

    if not det_events:
        return '<div id="tab-detection" class="tab-content"><p style="color:#888">No detection events found.</p></div>'

    rows = []
    for i, ev in enumerate(det_events):
        cat = ev.get('category', 'normal')
        label, cls = {
            'anti_debug': ('ANTI-DBG', 'cat-red'),
            'fd_scan': ('FD-SCAN', 'cat-orange'),
            'maps_scan': ('MAPS', 'cat-orange'),
            'thread_scan': ('THREAD', 'cat-orange'),
            'mem_probe': ('MEM-PROBE', 'cat-orange'),
            'mount_check': ('MOUNT', 'cat-orange'),
            'self_kill': ('KILL', 'cat-red'),
            'cmdline_check': ('CMDLINE', 'cat-orange'),
        }.get(cat, (cat, 'cat-grey'))

        thread = _esc(ev.get('thread', '?'))
        syscall = _esc(ev['syscall'])
        args_short = _esc(_short_args(ev))

        bt_html = _render_bt(ev, recon)
        bt_block = f'<div class="bt">{bt_html}</div>' if bt_html else ''

        rows.append(
            f'<tr><td><span class="cat {cls}">{label}</span></td>'
            f'<td>{thread}</td><td>{syscall}</td>'
            f'<td>{args_short}{bt_block}</td></tr>'
        )

    parts.append(f'''<table><tr><th>Type</th><th>Thread</th><th>Syscall</th><th>Detail</th></tr>
{"".join(rows)}
</table>''')

    return f'<div id="tab-detection" class="tab-content"><div class="scroll-box">{"".join(parts)}</div></div>'


# ─── Tab: Threads ───

def _tab_threads(thread_info, recon):
    cards = []
    for t in sorted(thread_info, key=lambda x: -x['count']):
        tid = t['tid']
        names = ', '.join(t['names']) or '?'
        count = t['count']

        # Syscall breakdown mini-bar
        sc = t['syscalls']
        file_sc = {'openat', 'close', 'read', 'write', 'readlinkat', 'faccessat',
                   'newfstatat', 'lseek', 'getdents64', 'statx', 'unlinkat'}
        proc_sc = {'clone', 'clone3', 'execve', 'exit', 'exit_group', 'prctl'}
        mem_sc = {'mmap', 'mprotect', 'munmap', 'madvise', 'brk'}
        det_sc = {'ptrace', 'kill', 'tgkill'}

        file_n = sum(v for k, v in sc.items() if k in file_sc)
        proc_n = sum(v for k, v in sc.items() if k in proc_sc)
        mem_n = sum(v for k, v in sc.items() if k in mem_sc)
        det_n = sum(v for k, v in sc.items() if k in det_sc)
        other_n = count - file_n - proc_n - mem_n - det_n

        def bar_span(n, cls):
            if n <= 0:
                return ''
            pct = max(n / count * 100, 1)
            return f'<span class="{cls}" style="width:{pct}%" title="{cls.replace("sc-","")}: {n}"></span>'

        bar = (bar_span(file_n, 'sc-file') + bar_span(proc_n, 'sc-proc') +
               bar_span(mem_n, 'sc-mem') + bar_span(det_n, 'sc-det') +
               bar_span(other_n, 'sc-other'))

        # Top syscalls
        top_sc = ', '.join(f'{k}({v})' for k, v in sc.most_common(5))

        # Clone backtrace
        clone_html = ''
        if t['clone_bt']:
            bt_lines = []
            for f in t['clone_bt']:
                bt_lines.append(_format_frame(f))
            clone_html = f'<div class="bt" style="margin-top:4px">{"".join(bt_lines)}</div>'

        # Detection summary for this thread
        det_cats = {'anti_debug', 'fd_scan', 'maps_scan', 'thread_scan',
                    'mem_probe', 'mount_check', 'self_kill'}
        det_in_thread = sum(1 for e in t['events'] if e.get('category') in det_cats)
        det_badge = f' <span class="cat cat-red">{det_in_thread} detections</span>' if det_in_thread else ''

        cards.append(f'''<div class="thread-card">
<h3>TID {tid} — {_esc(names)} ({count} events){det_badge}</h3>
<div class="sc-bar">{bar}</div>
<div style="font-size:11px;color:#888">{top_sc}</div>
{clone_html}
</div>''')

    return f'<div id="tab-threads" class="tab-content"><div class="scroll-box">{"".join(cards)}</div></div>'


# ─── Tab: By Thread ───

def _tab_by_thread(thread_info, recon):
    """Per-thread drill-down: select a thread, see its full event log + categorized syscalls."""
    categories, sc_to_cat = _get_categories()

    # Sort threads: detection count desc, then event count desc
    det_cats = {'anti_debug', 'fd_scan', 'maps_scan', 'thread_scan',
                'mem_probe', 'mount_check', 'self_kill', 'cmdline_check'}

    def threat_score(t):
        det_n = sum(1 for e in t['events'] if e.get('category') in det_cats)
        return (-det_n, -t['count'])

    sorted_threads = sorted(thread_info, key=threat_score)

    # Thread selector buttons
    btns = []
    for t in sorted_threads:
        tid = t['tid']
        name = t['names'][0] if t['names'] else '?'
        det_n = sum(1 for e in t['events'] if e.get('category') in det_cats)
        badge = f' <span class="cat cat-red">{det_n}</span>' if det_n else ''
        btns.append(
            f'<button onclick="showThread({tid}, this)" '
            f'class="thread-btn" data-tid="{tid}">'
            f'TID {tid} {_esc(name)} ({t["count"]}){badge}</button>'
        )

    # Per-thread content panels
    panels = []
    for t in sorted_threads:
        tid = t['tid']
        evts = t['events']
        name = t['names'][0] if t['names'] else '?'

        # Categorized syscall breakdown
        cat_sc = defaultdict(Counter)
        uncategorized = Counter()
        for e in evts:
            sc = e['syscall']
            cn = sc_to_cat.get(sc)
            if cn:
                cat_sc[cn][sc] += 1
            else:
                uncategorized[sc] += 1

        cat_html = []
        for cn, ci in categories.items():
            if cn not in cat_sc:
                continue
            icon = ci.get('icon', '')
            grp = cat_sc[cn]
            total = sum(grp.values())
            items = ' '.join(f'{sc}({c})' for sc, c in grp.most_common(8))
            cat_html.append(
                f'<div style="margin:2px 0">'
                f'<b>{icon} {_esc(cn)}: {total}</b> — '
                f'<span style="color:#888">{items}</span></div>'
            )
        if uncategorized:
            items = ' '.join(f'{sc}({c})' for sc, c in uncategorized.most_common(8))
            cat_html.append(
                f'<div style="margin:2px 0"><b>其他: {sum(uncategorized.values())}</b> — '
                f'<span style="color:#888">{items}</span></div>'
            )

        # Detection events for this thread
        det_evts = [e for e in evts if e.get('category') in det_cats]
        det_html = ''
        if det_evts:
            det_rows = []
            for e in det_evts:
                cat = e.get('category', '')
                label_map = {
                    'anti_debug': 'ANTI-DBG', 'fd_scan': 'FD-SCAN',
                    'maps_scan': 'MAPS', 'thread_scan': 'THREAD',
                    'mem_probe': 'MEM', 'mount_check': 'MOUNT',
                    'self_kill': 'KILL', 'cmdline_check': 'CMDLINE',
                }
                label = label_map.get(cat, cat)
                cls = 'cat-red' if cat in ('anti_debug', 'self_kill') else 'cat-orange'
                args = _esc(_short_args(e))
                bt = _render_bt(e, recon)
                bt_block = f'<div class="bt">{bt}</div>' if bt else ''
                det_rows.append(
                    f'<tr><td><span class="cat {cls}">{label}</span></td>'
                    f'<td>{_esc(e["syscall"])}</td><td>{args}{bt_block}</td></tr>'
                )
            det_html = (
                f'<h4 style="color:#ff5252;margin:8px 0 4px">Detection Events ({len(det_evts)})</h4>'
                f'<table><tr><th>Type</th><th>Syscall</th><th>Detail</th></tr>'
                f'{"".join(det_rows)}</table>'
            )

        # File paths accessed by this thread
        paths = Counter()
        for e in evts:
            p = e.get('pathname')
            if p:
                paths[p] += 1
        paths_html = ''
        if paths:
            suspicious_kw = {'frida', 'magisk', 'su', 'xposed', 'proc/self',
                             'proc/net', 'mountinfo', 'smaps', 'cmdline'}
            path_rows = []
            for p, c in paths.most_common(50):
                pl = p.lower()
                cls = 'path-suspicious' if any(k in pl for k in suspicious_kw) else 'path-normal'
                path_rows.append(
                    f'<tr><td><span class="count">{c}</span></td>'
                    f'<td class="{cls}">{_esc(p)}</td></tr>'
                )
            paths_html = (
                f'<h4 style="color:#4fc3f7;margin:8px 0 4px">File Access ({len(paths)})</h4>'
                f'<table>{"".join(path_rows)}</table>'
            )

        # Event log for this thread (compact)
        log_rows = []
        for i, e in enumerate(evts):
            cat = e.get('category', 'normal')
            style = 'color:#ff5252' if cat in ('anti_debug', 'self_kill') else (
                'color:#ffa726' if cat in det_cats else '')
            args = _esc(_short_args(e))
            bt = _render_bt(e, recon)
            bt_block = f'<div class="bt">{bt}</div>' if bt else ''
            log_rows.append(
                f'<tr style="{style}"><td>{i}</td><td>{_esc(e["syscall"])}</td>'
                f'<td>{args}{bt_block}</td></tr>'
            )

        panels.append(
            f'<div id="thread-{tid}" class="thread-panel" style="display:none">'
            f'<h3 style="color:#4fc3f7">TID {tid} — {_esc(name)} ({len(evts)} events)</h3>'
            f'<div style="margin:8px 0">{"".join(cat_html)}</div>'
            f'{det_html}'
            f'{paths_html}'
            f'<h4 style="color:#4fc3f7;margin:8px 0 4px">All Events</h4>'
            f'<input class="search" placeholder="Filter..." '
            f'oninput="filterTable(this,\'tlog-{tid}\')">'
            f'<div style="max-height:400px;overflow-y:auto">'
            f'<table id="tlog-{tid}"><tr><th>#</th><th>Syscall</th><th>Args</th></tr>'
            f'{"".join(log_rows)}</table></div>'
            f'</div>'
        )

    # Show first thread by default
    first_tid = sorted_threads[0]['tid'] if sorted_threads else 0

    return f'''<div id="tab-bythread" class="tab-content"><div class="scroll-box">
<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:8px">{"".join(btns)}</div>
{"".join(panels)}
</div></div>
<style>
.thread-btn {{ background:#16213e; border:1px solid #333; color:#aaa; padding:4px 10px;
              border-radius:4px; cursor:pointer; font-family:inherit; font-size:12px; }}
.thread-btn:hover {{ border-color:#4fc3f7; color:#fff; }}
.thread-btn.active {{ background:#1a3a5c; border-color:#4fc3f7; color:#4fc3f7; }}
</style>
<script>
function showThread(tid, btn) {{
  document.querySelectorAll('.thread-panel').forEach(p => p.style.display = 'none');
  document.querySelectorAll('.thread-btn').forEach(b => b.classList.remove('active'));
  var panel = document.getElementById('thread-' + tid);
  if (panel) panel.style.display = 'block';
  if (btn) btn.classList.add('active');
}}
// Auto-show first thread
document.addEventListener('DOMContentLoaded', function() {{
  var firstBtn = document.querySelector('.thread-btn');
  if (firstBtn) showThread(firstBtn.dataset.tid, firstBtn);
}});
</script>'''


# ─── Tab: Files ───

def _tab_files(file_events):
    # Deduplicate paths with counts
    path_counts = defaultdict(lambda: {'count': 0, 'syscalls': set()})
    for ev in file_events:
        p = ev.get('pathname', '')
        if p:
            path_counts[p]['count'] += 1
            path_counts[p]['syscalls'].add(ev['syscall'])

    rows = []
    suspicious_kw = {'frida', 'magisk', 'su', 'xposed', 'edxp', 'riru', 'zygisk',
                     'substrate', 'gadget'}
    proc_kw = {'/proc/', '/sys/'}

    for path, info in sorted(path_counts.items(), key=lambda x: -x[1]['count']):
        count = info['count']
        scs = ','.join(sorted(info['syscalls']))
        path_lower = path.lower()

        if any(k in path_lower for k in suspicious_kw):
            cls = 'path-suspicious'
        elif any(k in path for k in proc_kw):
            cls = 'path-proc'
        else:
            cls = 'path-normal'

        rows.append(f'<tr><td><span class="count">{count}</span></td>'
                    f'<td style="font-size:11px;color:#888">{scs}</td>'
                    f'<td class="{cls}">{_esc(path)}</td></tr>')

    return f'''<div id="tab-files" class="tab-content"><div class="scroll-box">
<input class="search" placeholder="Filter paths..." oninput="filterTable(this,'files-table')">
<table id="files-table"><tr><th>#</th><th>Syscall</th><th>Path</th></tr>
{"".join(rows)}
</table></div></div>'''


# ─── Tab: Strings ───

def _tab_strings(strings):
    suspicious_kw = {'frida', 'magisk', 'su', 'xposed', 'root', 'busybox',
                     'substrate', 'gadget', '/proc/self', '/proc/net',
                     'maps', 'status', 'cmdline', 'mountinfo', 'smaps'}
    rows = []
    for s, count in strings[:500]:
        s_lower = s.lower()
        if any(k in s_lower for k in suspicious_kw):
            cls = 'path-suspicious'
        elif '/proc/' in s:
            cls = 'path-proc'
        else:
            cls = 'path-normal'
        rows.append(f'<tr><td><span class="count">{count}</span></td>'
                    f'<td class="{cls} str-val">{_esc(s)}</td></tr>')

    return f'''<div id="tab-strings" class="tab-content"><div class="scroll-box">
<input class="search" placeholder="Filter strings..." oninput="filterTable(this,'strings-table')">
<table id="strings-table"><tr><th>#</th><th>String</th></tr>
{"".join(rows)}
</table></div></div>'''


# ─── Tab: Full Log ───

def _tab_fulllog(events, recon):
    rows = []
    for i, ev in enumerate(events):
        cat = ev.get('category', 'normal')
        cls = {
            'anti_debug': 'cat-red', 'fd_scan': 'cat-orange',
            'maps_scan': 'cat-orange', 'thread_scan': 'cat-orange',
            'mem_probe': 'cat-orange', 'mount_check': 'cat-orange',
            'self_kill': 'cat-red',
        }.get(cat, '')

        tid = ev.get('tid', 0)
        thread = _esc(ev.get('thread', '?'))
        syscall = _esc(ev['syscall'])
        args_short = _esc(_short_args(ev))

        style = f'color:#ff5252' if cls == 'cat-red' else (
            f'color:#ffa726' if cls == 'cat-orange' else '')

        bt_html = _render_bt(ev, recon)
        bt_block = f'<div class="bt">{bt_html}</div>' if bt_html else ''

        rows.append(
            f'<tr style="{style}">'
            f'<td>{i}</td><td>{tid}</td><td>{thread}</td>'
            f'<td>{syscall}</td><td>{args_short}{bt_block}</td></tr>'
        )

    return f'''<div id="tab-fulllog" class="tab-content"><div class="scroll-box">
<input class="search" placeholder="Filter..." oninput="filterTable(this,'log-table')">
<table id="log-table"><tr><th>#</th><th>TID</th><th>Thread</th><th>Syscall</th><th>Args</th></tr>
{"".join(rows)}
</table></div></div>'''


# ─── Helpers ───

def _short_args(ev):
    """Extract the most useful part of args for display."""
    path = ev.get('pathname', '')
    ret = ev.get('ret')
    sc = ev['syscall']
    args_raw = ev.get('args_raw', '')

    if path:
        s = path
        if ret is not None:
            s += f' → {ret}'
        return s

    if sc in ('kill', 'tgkill'):
        # Extract pid and sig
        m = re.search(r'pid=(\d+).*?sig=(\d+|SIG\w+)', args_raw)
        if m:
            return f'pid={m.group(1)} sig={m.group(2)}'

    if sc == 'clone':
        m = re.search(r'flags=([^,\)]+)', args_raw)
        if m:
            return f'flags={m.group(1)}'

    if sc in ('mmap', 'mprotect'):
        m = re.search(r'addr=(0x[\da-fA-F]+).*?length=(\d+).*?prot=([^,\)]+)', args_raw)
        if m:
            s = f'addr={m.group(1)} len={m.group(2)} prot={m.group(3)}'
            if ret is not None:
                s += f' → 0x{ret:x}' if isinstance(ret, int) else f' → {ret}'
            return s

    if sc == 'prctl':
        m = re.search(r'option=([^,\)]+)', args_raw)
        if m:
            return f'option={m.group(1)}'

    # Fallback: first 120 chars
    return args_raw[:120]


def _render_bt(ev, recon):
    """Render backtrace frames."""
    bt = ev.get('sym_bt') or ev.get('backtrace')
    if not bt:
        return ''
    lines = []
    for f in bt:
        lines.append(_format_frame(f))
    return ''.join(lines)


def _format_frame(f):
    """Format a single backtrace frame as HTML line."""
    idx = f.get('index', 0)
    module = f.get('resolved_module', f.get('module', '<unknown>'))
    offset = f.get('resolved_offset', f.get('pc_offset'))
    symbol = f.get('symbol', '')

    if module and module not in ('<unknown>', '<invalid>'):
        name = module.rsplit('/', 1)[-1] if '/' in module else module
        cls = 'resolved'
    elif module == '<invalid>':
        name = '<invalid>'
        cls = 'invalid'
    else:
        name = '<unknown>'
        cls = 'unknown'

    off_str = f'0x{offset:x}' if offset is not None else '?'
    sym_str = f'  ({_esc(symbol)})' if symbol else ''

    return f'<span class="{cls}">#{idx:02d}  {_esc(name)} + {off_str}{sym_str}</span>\n'


def _html_foot():
    return '''
<script>
function switchTab(id, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tabs button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + id).classList.add('active');
  btn.classList.add('active');
}
function filterTable(input, tableId) {
  const q = input.value.toLowerCase();
  const rows = document.getElementById(tableId).querySelectorAll('tr:not(:first-child)');
  rows.forEach(r => {
    r.style.display = r.textContent.toLowerCase().includes(q) ? '' : 'none';
  });
}
</script>
</body></html>'''
