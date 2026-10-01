#include "seccomp.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SECCOMP

#include <errno.h>
#include <seccomp.h>

static const int SCANNER_SYSCALLS[] = {
    SCMP_SYS(socket), SCMP_SYS(bind), SCMP_SYS(listen), SCMP_SYS(accept),
    SCMP_SYS(accept4), SCMP_SYS(connect), SCMP_SYS(shutdown),
    SCMP_SYS(getsockopt), SCMP_SYS(setsockopt),
    SCMP_SYS(recvfrom), SCMP_SYS(recvmsg), SCMP_SYS(sendto), SCMP_SYS(sendmsg),
    SCMP_SYS(read), SCMP_SYS(readv), SCMP_SYS(write), SCMP_SYS(writev),
    SCMP_SYS(poll), SCMP_SYS(ppoll), SCMP_SYS(select), SCMP_SYS(pselect6),
    SCMP_SYS(epoll_create1), SCMP_SYS(epoll_ctl), SCMP_SYS(epoll_wait),
    SCMP_SYS(epoll_pwait),

    SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(openat2), SCMP_SYS(close),
    SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(lseek), SCMP_SYS(fsync),
    SCMP_SYS(fdatasync), SCMP_SYS(fstat), SCMP_SYS(newfstatat),
    SCMP_SYS(stat), SCMP_SYS(lstat), SCMP_SYS(statx),
    SCMP_SYS(unlink), SCMP_SYS(unlinkat), SCMP_SYS(rename), SCMP_SYS(renameat),
    SCMP_SYS(renameat2), SCMP_SYS(chmod), SCMP_SYS(fchmod), SCMP_SYS(fchmodat),
    SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(dup), SCMP_SYS(dup2), SCMP_SYS(dup3),
    SCMP_SYS(fcntl), SCMP_SYS(pipe), SCMP_SYS(pipe2),
    SCMP_SYS(ftruncate), SCMP_SYS(flock),
    SCMP_SYS(getdents), SCMP_SYS(getdents64),
    SCMP_SYS(readlink), SCMP_SYS(readlinkat),

    SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(mprotect), SCMP_SYS(mremap),
    SCMP_SYS(brk), SCMP_SYS(madvise), SCMP_SYS(mlock), SCMP_SYS(munlock),

    SCMP_SYS(clock_gettime), SCMP_SYS(clock_nanosleep), SCMP_SYS(nanosleep),
    SCMP_SYS(gettimeofday), SCMP_SYS(time),

    SCMP_SYS(clone), SCMP_SYS(clone3),
    SCMP_SYS(futex), SCMP_SYS(set_robust_list), SCMP_SYS(get_robust_list),
    SCMP_SYS(rseq),
    SCMP_SYS(sched_yield), SCMP_SYS(sched_getaffinity),
    SCMP_SYS(gettid), SCMP_SYS(tgkill),

    SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask), SCMP_SYS(rt_sigreturn),
    SCMP_SYS(rt_sigpending), SCMP_SYS(rt_sigtimedwait), SCMP_SYS(rt_sigsuspend),
    SCMP_SYS(sigaltstack),

    SCMP_SYS(getpid), SCMP_SYS(getppid), SCMP_SYS(getuid), SCMP_SYS(geteuid),
    SCMP_SYS(getgid), SCMP_SYS(getegid), SCMP_SYS(getgroups),
    SCMP_SYS(exit), SCMP_SYS(exit_group),

    SCMP_SYS(fork), SCMP_SYS(vfork), SCMP_SYS(execve), SCMP_SYS(execveat),
    SCMP_SYS(wait4), SCMP_SYS(waitid),
    SCMP_SYS(kill),

    SCMP_SYS(getrandom),

    SCMP_SYS(uname), SCMP_SYS(prlimit64), SCMP_SYS(getrlimit),
    SCMP_SYS(arch_prctl), SCMP_SYS(prctl),
    SCMP_SYS(set_tid_address), SCMP_SYS(ioctl),
    SCMP_SYS(memfd_create),

    SCMP_SYS(access), SCMP_SYS(faccessat), SCMP_SYS(faccessat2),
    SCMP_SYS(getrusage), SCMP_SYS(pread64), SCMP_SYS(pwrite64),
    SCMP_SYS(statfs), SCMP_SYS(fstatfs), SCMP_SYS(sysinfo),
    SCMP_SYS(clock_getres),
    SCMP_SYS(sched_setaffinity), SCMP_SYS(sched_getparam),
    SCMP_SYS(sched_setparam), SCMP_SYS(sched_setattr),
    SCMP_SYS(sched_getattr), SCMP_SYS(sched_get_priority_max),
    SCMP_SYS(sched_get_priority_min), SCMP_SYS(getcpu),
    SCMP_SYS(membarrier),

    SCMP_SYS(seccomp),
};

static const int SIGNER_SYSCALLS[] = {
    SCMP_SYS(socket), SCMP_SYS(bind), SCMP_SYS(listen), SCMP_SYS(accept),
    SCMP_SYS(accept4), SCMP_SYS(shutdown), SCMP_SYS(getsockopt), SCMP_SYS(setsockopt),
    SCMP_SYS(recvfrom), SCMP_SYS(recvmsg), SCMP_SYS(sendto), SCMP_SYS(sendmsg),
    SCMP_SYS(read), SCMP_SYS(readv), SCMP_SYS(write), SCMP_SYS(writev),
    SCMP_SYS(poll), SCMP_SYS(ppoll),
    SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(openat2), SCMP_SYS(close),
    SCMP_SYS(lseek), SCMP_SYS(fsync), SCMP_SYS(fdatasync),
    SCMP_SYS(fstat), SCMP_SYS(newfstatat), SCMP_SYS(stat), SCMP_SYS(statx),
    SCMP_SYS(statfs), SCMP_SYS(fstatfs),
    SCMP_SYS(unlink), SCMP_SYS(unlinkat), SCMP_SYS(rename), SCMP_SYS(renameat2),
    SCMP_SYS(mkdir), SCMP_SYS(mkdirat), SCMP_SYS(fchmod), SCMP_SYS(chmod),
    SCMP_SYS(fcntl), SCMP_SYS(getdents64), SCMP_SYS(readlink), SCMP_SYS(readlinkat),
    SCMP_SYS(pread64), SCMP_SYS(pwrite64), SCMP_SYS(access), SCMP_SYS(faccessat),
    SCMP_SYS(faccessat2),
    SCMP_SYS(mmap), SCMP_SYS(munmap), SCMP_SYS(mprotect), SCMP_SYS(mremap),
    SCMP_SYS(brk), SCMP_SYS(madvise), SCMP_SYS(mlock), SCMP_SYS(munlock),
    SCMP_SYS(clock_gettime), SCMP_SYS(clock_nanosleep), SCMP_SYS(clock_getres),
    SCMP_SYS(nanosleep), SCMP_SYS(gettimeofday), SCMP_SYS(time),
    SCMP_SYS(clone), SCMP_SYS(clone3), SCMP_SYS(futex),
    SCMP_SYS(set_robust_list), SCMP_SYS(get_robust_list), SCMP_SYS(rseq),
    SCMP_SYS(sched_yield), SCMP_SYS(sched_getaffinity), SCMP_SYS(getcpu),
    SCMP_SYS(gettid), SCMP_SYS(tgkill),
    SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask), SCMP_SYS(rt_sigreturn),
    SCMP_SYS(rt_sigtimedwait), SCMP_SYS(sigaltstack),
    SCMP_SYS(getpid), SCMP_SYS(getppid), SCMP_SYS(getuid), SCMP_SYS(geteuid),
    SCMP_SYS(getgid), SCMP_SYS(getegid), SCMP_SYS(getgroups),
    SCMP_SYS(getrandom), SCMP_SYS(getrusage),
    SCMP_SYS(prctl), SCMP_SYS(arch_prctl), SCMP_SYS(set_tid_address),
    SCMP_SYS(prlimit64), SCMP_SYS(getrlimit), SCMP_SYS(uname),
    SCMP_SYS(ioctl), SCMP_SYS(sysinfo),
    SCMP_SYS(exit), SCMP_SYS(exit_group), SCMP_SYS(seccomp),
};

int pigcloud_seccomp_install(int is_signer)
{
    const int *allow = is_signer ? SIGNER_SYSCALLS : SCANNER_SYSCALLS;
    size_t n_allow = is_signer
        ? sizeof(SIGNER_SYSCALLS) / sizeof(SIGNER_SYSCALLS[0])
        : sizeof(SCANNER_SYSCALLS) / sizeof(SCANNER_SYSCALLS[0]);

    const char *mode = getenv("TEE_SECCOMP_MODE");
    if (mode && strcmp(mode, "off") == 0) {
        fprintf(stderr, "INFO: seccomp filter skipped (TEE_SECCOMP_MODE=off)\n");
        return 0;
    }
    uint32_t default_action = SCMP_ACT_LOG;
    int enforcing = 0;
    if (mode && strcmp(mode, "enforce") == 0) {
        default_action = SCMP_ACT_KILL_PROCESS;
        enforcing = 1;
    }

    scmp_filter_ctx ctx = seccomp_init(default_action);
    if (!ctx) {
        if (enforcing) {
            fprintf(stderr, "FATAL: seccomp_init failed with TEE_SECCOMP_MODE=enforce: refusing to run unfiltered\n");
            return -1;
        }
        fprintf(stderr, "WARN: seccomp_init failed: filter not installed\n");
        return 0;
    }

    for (size_t i = 0; i < n_allow; i++) {
        if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, allow[i], 0) != 0) {
        }
    }

    int load_rc = seccomp_load(ctx);
    if (load_rc != 0) {
        seccomp_release(ctx);
        if (enforcing) {
            fprintf(stderr, "FATAL: seccomp_load failed (%s) with TEE_SECCOMP_MODE=enforce: refusing to run unfiltered\n",
                    strerror(-load_rc));
            return -1;
        }
        fprintf(stderr, "WARN: seccomp_load failed (%s): filter not installed\n",
                strerror(-load_rc));
        return 0;
    }

    fprintf(stderr, "INFO: seccomp %s filter installed (%s mode, %zu allowed syscalls)\n",
            is_signer ? "signer" : "scanner",
            enforcing ? "enforce" : "log",
            n_allow);

    seccomp_release(ctx);
    return 0;
}

#else

int pigcloud_seccomp_install(int is_signer)
{
    (void)is_signer;
    const char *mode = getenv("TEE_SECCOMP_MODE");
    if (mode && strcmp(mode, "enforce") == 0) {
        fprintf(stderr, "FATAL: TEE_SECCOMP_MODE=enforce but built without libseccomp: refusing to start\n");
        return -1;
    }
    return 0;
}

#endif
