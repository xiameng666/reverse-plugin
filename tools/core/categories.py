"""Syscall categories from SVCMonitors project. Shared by CLI and HTML report."""

SYSCALL_CATEGORIES = {
    '文件操作': {
        'icon': '📁',
        'syscalls': ['openat', 'faccessat', 'unlinkat', 'readlinkat',
                     'getdents64', 'newfstatat', 'statx',
                     'renameat2', 'mkdirat', 'close'],
    },
    '读写操作': {
        'icon': '📖',
        'syscalls': ['read', 'write', 'pread64', 'pwrite64',
                     'readv', 'writev', 'lseek'],
    },
    '进程管理': {
        'icon': '⚙',
        'syscalls': ['clone', 'clone3', 'execve', 'execveat', 'exit',
                     'exit_group', 'wait4', 'prctl', 'ptrace'],
    },
    '内存管理': {
        'icon': '🧠',
        'syscalls': ['mmap', 'mprotect', 'munmap', 'brk', 'mincore',
                     'madvise', 'memfd_create', 'process_vm_readv',
                     'process_vm_writev'],
    },
    '网络通信': {
        'icon': '🌐',
        'syscalls': ['socket', 'bind', 'listen', 'connect', 'accept',
                     'accept4', 'sendto', 'recvfrom', 'sendmsg', 'recvmsg'],
    },
    '信号处理': {
        'icon': '📡',
        'syscalls': ['kill', 'tgkill', 'rt_sigaction'],
    },
    '安全相关': {
        'icon': '🔒',
        'syscalls': ['seccomp', 'setns', 'unshare', 'bpf'],
    },
    '系统杂项': {
        'icon': '➕',
        'syscalls': ['ioctl', 'fcntl', 'pipe2', 'dup', 'dup3', 'futex',
                     'setsockopt', 'getsockopt', 'prlimit64', 'sendfile',
                     'mount', 'umount2', 'capget', 'capset', 'setuid',
                     'setgid', 'finit_module', 'init_module', 'delete_module'],
    },
    '环境检测': {
        'icon': '🔍',
        'syscalls': ['openat', 'faccessat', 'newfstatat', 'readlinkat', 'statfs',
                     'read', 'getdents64', 'ptrace', 'prctl', 'kill', 'tgkill',
                     'clone', 'wait4', 'mprotect', 'rt_sigaction'],
    },
}

# Reverse lookup: syscall_name → category_name
SC_TO_CAT = {}
for _cat, _info in SYSCALL_CATEGORIES.items():
    for _sc in _info['syscalls']:
        SC_TO_CAT[_sc] = _cat
