"""Reconstruct process memory map from multiple sources:

1. Zygote baseline: dump /proc/$(pidof zygote64)/maps before app starts
2. mmap syscall events: track openat→fd, mmap(PROT_EXEC)→region
3. APK SO parsing: resolve split_config.arm64_v8a.apk+offset → libfoo.so+offset

Provides resolve(addr) → (so_path, offset) for symbolizing backtraces.
"""

import os
import re
import struct
import zipfile
from typing import Any, Dict, List, Optional, Tuple


# ARM64 user space max address (48-bit VA)
_USER_ADDR_MAX = 0x0000_FFFF_FFFF_FFFF


def is_valid_user_addr(addr: int) -> bool:
    """Check if address looks like a valid ARM64 user-space address."""
    return 0 < addr < _USER_ADDR_MAX


class ApkSoResolver:
    """Resolve APK-internal offsets to specific SO files.

    When extractNativeLibs=false, the linker mmap's SO directly from APK.
    Maps shows: .apk + offset. We need to find which SO that offset falls in.
    """

    def __init__(self):
        # apk_path → list of (so_offset_in_apk, so_size, so_name)
        self._apk_entries: Dict[str, List[Tuple[int, int, str]]] = {}

    def load_apk(self, apk_path: str) -> bool:
        """Parse APK to find embedded SO file offsets."""
        if apk_path in self._apk_entries:
            return True
        if not os.path.isfile(apk_path):
            return False
        try:
            entries = []
            with zipfile.ZipFile(apk_path, 'r') as zf:
                for info in zf.infolist():
                    name = info.filename
                    if name.endswith('.so') and '/arm64' in name:
                        # header_offset is the start of the local file header
                        # The actual data starts after the local file header
                        # For stored (uncompressed) files, we can calculate this
                        if info.compress_type == 0:  # STORED, not compressed
                            # Local file header: 30 bytes fixed + filename + extra
                            data_offset = (info.header_offset + 30
                                           + len(info.filename.encode('utf-8'))
                                           + len(info.extra))
                            so_name = name.rsplit('/', 1)[-1]
                            entries.append((data_offset, info.file_size, so_name))
            entries.sort(key=lambda x: x[0])
            self._apk_entries[apk_path] = entries
            return bool(entries)
        except (zipfile.BadZipFile, OSError):
            return False

    def resolve(self, apk_path: str, apk_offset: int) -> Optional[Tuple[str, int]]:
        """Resolve APK offset to (so_name, so_offset).

        apk_offset is the offset within the APK file that was mmap'd.
        We need to find which SO contains this offset.
        """
        entries = self._apk_entries.get(apk_path, [])
        for so_start, so_size, so_name in entries:
            if so_start <= apk_offset < so_start + so_size:
                return (so_name, apk_offset - so_start)
        return None


class MapsReconstructor:
    """Reconstruct memory map from zygote baseline + syscall events + APK parsing."""

    def __init__(self):
        # Memory regions: list of (base_addr, size, path, file_offset)
        self._regions: List[Tuple[int, int, str, int]] = []
        # fd → file path mapping (per-process, not per-tid)
        self._fd_to_path: Dict[int, str] = {}
        # Pending openat entries: tid → path
        self._pending_openat: Dict[int, str] = {}
        # Pending mmap entries: tid → (length, prot, fd, offset)
        self._pending_mmap: Dict[int, Tuple[int, int, int, int]] = {}
        # APK resolver
        self._apk_resolver = ApkSoResolver()
        # Local APK cache: device_path → local_path
        self._local_apks: Dict[str, str] = {}

    def load_baseline_maps(self, maps_text: str) -> int:
        """Load zygote/baseline maps from /proc/pid/maps text.

        Returns number of executable regions loaded.
        """
        count = 0
        for line in maps_text.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format: addr_start-addr_end perms offset dev inode path
            parts = line.split(None, 5)
            if len(parts) < 5:
                continue
            addr_range = parts[0]
            perms = parts[1]
            offset_str = parts[2]
            path = parts[5] if len(parts) > 5 else ''

            if 'x' not in perms:
                continue
            if not path or path.startswith('['):
                continue

            try:
                start_str, end_str = addr_range.split('-')
                start = int(start_str, 16)
                end = int(end_str, 16)
                offset = int(offset_str, 16)
                size = end - start
                if size > 0:
                    self._regions.append((start, size, path, offset))
                    count += 1
            except ValueError:
                continue
        return count

    def load_baseline_file(self, filepath: str) -> int:
        """Load baseline maps from a file."""
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            return self.load_baseline_maps(f.read())

    def register_local_apk(self, device_path: str, local_path: str) -> bool:
        """Register a locally pulled APK for SO resolution."""
        self._local_apks[device_path] = local_path
        return self._apk_resolver.load_apk(local_path)

    def process_event(self, ev: Dict[str, Any]) -> None:
        """Process a single merged trace event."""
        sc = ev.get('syscall', '')
        tid = ev.get('tid', 0)
        is_ret = ev.get('is_return', False)
        args = ev.get('args', {})

        if sc == 'openat':
            self._handle_openat(ev, tid, is_ret, args)
        elif sc == 'close':
            self._handle_close(ev, tid, is_ret, args)
        elif sc == 'mmap':
            self._handle_mmap(ev, tid, is_ret, args)
        elif sc in ('dup2', 'dup3'):
            self._handle_dup(ev, tid, is_ret, args)

    def process_events(self, events: List[Dict[str, Any]]) -> None:
        """Process all events in order."""
        for ev in events:
            self.process_event(ev)

    def _handle_openat(self, ev, tid, is_ret, args):
        if not is_ret:
            path = ev.get('pathname')
            if path:
                self._pending_openat[tid] = path
        else:
            ret = ev.get('ret')
            path = ev.get('pathname')
            if path and ret is not None and ret >= 0:
                self._fd_to_path[ret] = path
            elif ret is not None and ret >= 0:
                pending_path = self._pending_openat.pop(tid, None)
                if pending_path:
                    self._fd_to_path[ret] = pending_path

    def _handle_close(self, ev, tid, is_ret, args):
        if not is_ret:
            fd_str = args.get('fd', '').strip()
            if fd_str:
                try:
                    self._fd_to_path.pop(int(fd_str), None)
                except ValueError:
                    pass

    def _handle_mmap(self, ev, tid, is_ret, args):
        if not is_ret:
            try:
                length = _parse_int(args.get('length', '0'))
                prot = _parse_prot(args.get('prot', '0'))
                fd = _parse_int(args.get('fd', '-1'))
                offset = _parse_int(args.get('offset', '0'))
                self._pending_mmap[tid] = (length, prot, fd, offset)
            except (ValueError, TypeError):
                pass
        else:
            ret = ev.get('ret')
            pending = self._pending_mmap.pop(tid, None)

            if pending is None:
                try:
                    length = _parse_int(args.get('length', '0'))
                    prot = _parse_prot(args.get('prot', '0'))
                    fd = _parse_int(args.get('fd', '-1'))
                    offset = _parse_int(args.get('offset', '0'))
                    pending = (length, prot, fd, offset)
                except (ValueError, TypeError):
                    return

            if ret is None or ret == 0:
                return

            length, prot, fd, offset = pending

            if not (prot & 0x4):  # PROT_EXEC
                return
            if fd < 0:
                return

            path = self._fd_to_path.get(fd)
            if not path:
                return
            if not any(path.endswith(ext) for ext in
                       ('.so', '.oat', '.apk', '.vdex', '.odex')):
                return

            self._regions.append((ret, length, path, offset))

    def _handle_dup(self, ev, tid, is_ret, args):
        if is_ret:
            return
        try:
            oldfd = _parse_int(args.get('oldfd', '-1'))
            newfd = _parse_int(args.get('newfd', '-1'))
            if oldfd >= 0 and newfd >= 0 and oldfd in self._fd_to_path:
                self._fd_to_path[newfd] = self._fd_to_path[oldfd]
        except (ValueError, TypeError):
            pass

    def resolve(self, addr: int) -> Optional[Tuple[str, int]]:
        """Resolve absolute address to (module_path, file_offset).

        The returned offset is the offset within the SO/APK FILE, not the
        offset within the mmap'd region. This is what addr2line expects.

        Formula: file_offset_of_addr = (addr - base_addr) + mmap_file_offset
        """
        if not is_valid_user_addr(addr):
            return None

        for base, size, path, file_offset in self._regions:
            if base <= addr < base + size:
                # Offset within the FILE = region displacement + file offset
                so_offset = (addr - base) + file_offset
                # For APK mappings, try to resolve to specific SO
                if path.endswith('.apk'):
                    for device_path, local_path in self._local_apks.items():
                        if path.endswith(device_path.rsplit('/', 1)[-1]) or \
                           device_path.endswith(path.rsplit('/', 1)[-1]):
                            result = self._apk_resolver.resolve(local_path, so_offset)
                            if result:
                                return result
                    return (path, so_offset)
                return (path, so_offset)
        return None

    def resolve_or_unknown(self, addr: int) -> Tuple[str, int]:
        """Like resolve but returns ('<unknown>', addr) for unresolved."""
        if not is_valid_user_addr(addr):
            return ('<invalid>', addr)
        result = self.resolve(addr)
        return result if result else ('<unknown>', addr)

    @property
    def regions(self) -> List[Tuple[int, int, str, int]]:
        return list(self._regions)

    @property
    def fd_map(self) -> Dict[int, str]:
        return dict(self._fd_to_path)

    def get_region_summary(self) -> List[Dict[str, Any]]:
        result = []
        for base, size, path, file_offset in sorted(self._regions, key=lambda r: r[0]):
            result.append({
                'base': f'0x{base:x}',
                'size': size,
                'size_hex': f'0x{size:x}',
                'end': f'0x{base + size:x}',
                'file_offset': f'0x{file_offset:x}',
                'path': path,
                'name': path.rsplit('/', 1)[-1] if '/' in path else path,
            })
        return result


def _parse_int(s: str) -> int:
    s = s.strip()
    if not s:
        return 0
    if s.startswith('0x') or s.startswith('0X'):
        return int(s, 16)
    return int(s)


def _parse_prot(s: str) -> int:
    s = s.strip()
    m = re.match(r'(0x[\da-fA-F]+|-?\d+)', s)
    if m:
        val = m.group(1)
        if val.startswith('0x') or val.startswith('0X'):
            return int(val, 16)
        return int(val)
    return 0


def symbolize_backtrace(bt: List[Dict[str, Any]],
                        recon: 'MapsReconstructor') -> List[Dict[str, Any]]:
    """Symbolize backtrace frames using reconstructed memory map.

    Key insight: when stackplz outputs `#00 pc 0000007df1e60898  <unknown>`,
    the pc value is an ABSOLUTE address, not an offset. We must try to resolve
    it against the baseline maps.
    """
    result = []
    for frame in bt:
        f = dict(frame)

        module = f.get('module', '')
        pc_offset = f.get('pc_offset')
        abs_addr = f.get('abs_addr')

        if module and module not in ('<unknown>', '<invalid>'):
            # stackplz resolved to a known module
            f['resolved_module'] = module
            f['resolved_offset'] = pc_offset

            # APK → try to resolve to specific SO inside
            if module.endswith('.apk') and pc_offset is not None:
                for device_path, local_path in recon._local_apks.items():
                    mod_name = module.rsplit('/', 1)[-1]
                    dev_name = device_path.rsplit('/', 1)[-1]
                    if mod_name == dev_name:
                        so_result = recon._apk_resolver.resolve(
                            local_path, pc_offset)
                        if so_result:
                            f['resolved_module'] = so_result[0]
                            f['resolved_offset'] = so_result[1]
                        break

        elif module == '<unknown>' and pc_offset is not None:
            # stackplz couldn't resolve — pc_offset is actually ABSOLUTE addr
            addr = pc_offset
            if not is_valid_user_addr(addr):
                f['resolved_module'] = '<invalid>'
                f['resolved_offset'] = addr
            else:
                resolved = recon.resolve(addr)
                if resolved:
                    f['resolved_module'] = resolved[0]
                    f['resolved_offset'] = resolved[1]
                else:
                    f['resolved_module'] = '<unknown>'
                    f['resolved_offset'] = addr

        elif abs_addr:
            addr = abs_addr
            if not is_valid_user_addr(addr):
                f['resolved_module'] = '<invalid>'
                f['resolved_offset'] = addr
            else:
                resolved = recon.resolve(addr)
                if resolved:
                    f['resolved_module'] = resolved[0]
                    f['resolved_offset'] = resolved[1]
                else:
                    f['resolved_module'] = '<unknown>'
                    f['resolved_offset'] = addr
        else:
            f['resolved_module'] = '<unknown>'
            f['resolved_offset'] = 0

        result.append(f)
    return result


def format_backtrace_line(frame: Dict[str, Any]) -> str:
    """Format a single backtrace frame as human-readable string."""
    idx = frame.get('index', 0)
    module = frame.get('resolved_module', frame.get('module', '<unknown>'))
    offset = frame.get('resolved_offset', frame.get('pc_offset'))
    symbol = frame.get('symbol')

    # Extract filename
    if module and module not in ('<unknown>', '<invalid>'):
        name = module.rsplit('/', 1)[-1] if '/' in module else module
    else:
        name = module or '<unknown>'

    if offset is not None:
        offset_str = f'0x{offset:x}'
    else:
        addr = frame.get('abs_addr', 0)
        offset_str = f'0x{addr:x}'

    line = f'#{idx:02d}  {name} + {offset_str}'
    if symbol:
        line += f'  ({symbol})'
    return line
