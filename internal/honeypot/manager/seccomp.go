package manager

// DefaultSeccompProfile 生成默认白名单 seccomp profile JSON
func DefaultSeccompProfile() string {
	return `{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {
      "names": [
        "accept", "accept4", "bind", "brk", "close",
        "connect", "epoll_create1", "epoll_ctl", "epoll_pwait",
        "exit_group", "fstat", "futex", "getpid", "gettid",
        "listen", "mmap", "mprotect", "munmap", "nanosleep",
        "openat", "read", "recvfrom", "recvmsg", "rt_sigaction",
        "rt_sigprocmask", "sendto", "sendmsg", "setsockopt",
        "socket", "write", "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}`
}
