#ifndef PIGCLOUD_TEE_MEMFD_HELPERS_H
#define PIGCLOUD_TEE_MEMFD_HELPERS_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>

#define TEE_SUBPROC_OK        0
#define TEE_SUBPROC_FAIL     -1
#define TEE_SUBPROC_TIMEOUT  -2

void tee_subproc_progress_tick(void);

static inline int tee_memfd_create(const char *name, char *path_buf, size_t path_size)
{
    int fd = memfd_create(name, MFD_CLOEXEC);
    if (fd < 0) return -1;
    snprintf(path_buf, path_size, "/proc/self/fd/%d", fd);
    return fd;
}

static inline void tee_keep_after_exec(int fd)
{
    int flags = fcntl(fd, F_GETFD);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFD, flags & ~FD_CLOEXEC);
    }
}

static inline void tee_harden_child(rlim_t cpu_secs)
{
    struct rlimit no_core = { 0, 0 };
    (void)setrlimit(RLIMIT_CORE, &no_core);
    if (cpu_secs > 0) {
        struct rlimit cpu = { cpu_secs, cpu_secs };
        (void)setrlimit(RLIMIT_CPU, &cpu);
    }
    (void)prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
}

static inline int tee_secs_until(const struct timespec *deadline)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    long secs = (long)(deadline->tv_sec - now.tv_sec);
    return secs > 0 ? (int)secs : 0;
}

static inline int tee_wait_child(pid_t pid, int timeout_secs, int *status_out)
{
    struct timespec deadline;
    clock_gettime(CLOCK_MONOTONIC, &deadline);
    deadline.tv_sec += timeout_secs;

    int status = 0;
    for (;;) {
        pid_t wr = waitpid(pid, &status, WNOHANG);
        if (wr == pid) {
            if (status_out) *status_out = status;
            return (WIFEXITED(status) && WEXITSTATUS(status) == 0)
                       ? TEE_SUBPROC_OK : TEE_SUBPROC_FAIL;
        }
        if (wr < 0) {
            if (errno == EINTR) continue;
            if (status_out) *status_out = status;
            return TEE_SUBPROC_FAIL;
        }
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
            break;
        }
        tee_subproc_progress_tick();
        struct timespec poll_iv = { 0, 200L * 1000L * 1000L };
        (void)nanosleep(&poll_iv, NULL);
    }

    kill(pid, SIGKILL);
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR) { }
    if (status_out) *status_out = status;
    return TEE_SUBPROC_TIMEOUT;
}

static inline unsigned char *tee_read_memfd(int fd, size_t *out_len, size_t max_len)
{
    *out_len = 0;

    off_t size = lseek(fd, 0, SEEK_END);
    if (size <= 0) return NULL;
    if ((unsigned long long)size > (unsigned long long)max_len) return NULL;
    if (lseek(fd, 0, SEEK_SET) != 0) return NULL;

    unsigned char *buf = malloc((size_t)size);
    if (!buf) return NULL;

    size_t total = 0;
    while (total < (size_t)size) {
        ssize_t rd = read(fd, buf + total, (size_t)size - total);
        if (rd <= 0) {
            free(buf);
            return NULL;
        }
        total += (size_t)rd;
    }

    *out_len = total;
    return buf;
}

static inline int tee_memfd_write(int fd, const unsigned char *data, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t wr = write(fd, data + total, len - total);
        if (wr <= 0) return -1;
        total += (size_t)wr;
    }
    return 0;
}

#endif
