"""Syscall categories from SVCMonitors project. Shared by CLI and HTML report."""

SYSCALL_CATEGORIES = {
    '文件操作': {
        'icon': '📁',
        'syscalls': ['openat', 'faccessat', 'unlinkat', 'readlinkat',
                     'getdents64', 'newfstatat', 'statx',
                     'renameat2', 'mkdirat'],
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
                     'accept4', 'sendto', 'recvfrom'],
    },
    '信号处理': {
        'icon': '📡',
        'syscalls': ['kill', 'tgkill', 'rt_sigaction'],
    },
    '安全相关': {
        'icon': '🔒',
        'syscalls': ['seccomp', 'setns', 'unshare', 'bpf'],
    },
    'Tier2': {
        'icon': '➕',
        'syscalls': ['ioctl', 'lseek', 'readv', 'writev', 'fcntl', 'sendfile',
                     'sendmsg', 'recvmsg', 'setsockopt', 'getsockopt', 'mount',
                     'umount2', 'prlimit64', 'capget', 'capset', 'setuid',
                     'setgid', 'finit_module', 'init_module', 'delete_module'],
    },
}

# Reverse lookup: syscall_name → category_name
SC_TO_CAT = {}
for _cat, _info in SYSCALL_CATEGORIES.items():
    for _sc in _info['syscalls']:
        SC_TO_CAT[_sc] = _cat
