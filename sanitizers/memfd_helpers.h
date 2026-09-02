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
#define TEE_SUBPROC_SPAWN_FAIL -3

#define TEE_MEMFD_PATH_MAX   64

static const char *const TEE_FFMPEG_CANDIDATES[] = {
    "/usr/local/lib/pigcloud-tee/ffmpeg",
    "/usr/bin/ffmpeg",
    "/usr/local/bin/ffmpeg",
    "ffmpeg",
    NULL
};

static const char *const TEE_GS_CANDIDATES[] = {
    "/usr/bin/gs",
    "/usr/local/bin/gs",
    "gs",
    NULL
};

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

static inline void tee_deadline_start(struct timespec *deadline, int budget_secs)
{
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec += budget_secs;
}

static inline int tee_secs_within(const struct timespec *deadline, int per_attempt_cap)
{
    int secs = tee_secs_until(deadline);
    return secs > per_attempt_cap ? per_attempt_cap : secs;
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

static inline int tee_memfd_finish_output(int out_fd, unsigned char **out, size_t *out_len,
                                          size_t max_len, const char *empty_reason,
                                          char *reason, size_t reason_size)
{
    *out = tee_read_memfd(out_fd, out_len, max_len);
    close(out_fd);
    if (!*out || *out_len == 0) {
        free(*out);
        *out = NULL;
        *out_len = 0;
        snprintf(reason, reason_size, "%s", empty_reason);
        return -1;
    }
    return 0;
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

static inline const char *tee_find_binary(const char *const *candidates)
{
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) {
            return candidates[i];
        }
    }
    return NULL;
}

typedef struct {
    int  in_fd;
    int  out_fd;
    char in_path[TEE_MEMFD_PATH_MAX];
    char out_path[TEE_MEMFD_PATH_MAX];
} tee_memfd_pair_t;

static inline void tee_memfd_close(int *fd)
{
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

static inline int tee_memfd_pair_open(tee_memfd_pair_t *p,
                                      const char *in_name, const char *out_name,
                                      const unsigned char *data, size_t len,
                                      const char **reason_out)
{
    p->in_fd = -1;
    p->out_fd = -1;
    p->in_path[0] = '\0';
    p->out_path[0] = '\0';

    p->in_fd = tee_memfd_create(in_name, p->in_path, sizeof(p->in_path));
    if (p->in_fd < 0) {
        *reason_out = "memfd_create_failed";
        return -1;
    }
    p->out_fd = tee_memfd_create(out_name, p->out_path, sizeof(p->out_path));
    if (p->out_fd < 0) {
        tee_memfd_close(&p->in_fd);
        *reason_out = "memfd_create_failed";
        return -1;
    }
    if (tee_memfd_write(p->in_fd, data, len) != 0) {
        tee_memfd_close(&p->in_fd);
        tee_memfd_close(&p->out_fd);
        *reason_out = "memfd_write_failed";
        return -1;
    }
    return 0;
}

static inline int tee_spawn_converter(const char *bin, char *const argv[],
                                      int timeout_secs,
                                      const int *keep_fds, size_t n_keep)
{
    if (timeout_secs <= 0) return TEE_SUBPROC_TIMEOUT;

    pid_t pid = fork();
    if (pid < 0) return TEE_SUBPROC_SPAWN_FAIL;

    if (pid == 0) {
        int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (devnull >= 0) {
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        for (size_t i = 0; i < n_keep; i++) {
            tee_keep_after_exec(keep_fds[i]);
        }
        tee_harden_child((rlim_t)timeout_secs * 4 + 30);
        execv(bin, argv);
        _exit(127);
    }

    int status = 0;
    return tee_wait_child(pid, timeout_secs, &status);
}

#endif
