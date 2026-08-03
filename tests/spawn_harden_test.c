#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "../sanitizers/memfd_helpers.h"

void tee_subproc_progress_tick(void) { }

static int g_failures = 0;

static void check(int cond, const char *what)
{
    printf("  [%s] %s\n", cond ? "PASS" : "FAIL", what);
    if (!cond) g_failures++;
}

#define SH "/bin/sh"
#define MARKER "PIGCLOUD_SPAWN_MARKER"

static int run_sh(const char *script, int timeout_secs,
                  const int *keep_fds, size_t n_keep)
{
    char *const argv[] = { (char *)SH, "-c", (char *)script, NULL };
    return tee_spawn_converter(SH, argv, timeout_secs, keep_fds, n_keep);
}

static long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int main(void)
{
    printf("spawn hardening (tee_spawn_converter)\n");

    int core_armed = 0;
    {
        struct rlimit cur;
        if (getrlimit(RLIMIT_CORE, &cur) == 0) {
            struct rlimit raised = { cur.rlim_max, cur.rlim_max };
            if (cur.rlim_max == 0) {
                printf("  [SKIP] hard RLIMIT_CORE is 0, cannot arm the core-dump check\n");
            } else if (setrlimit(RLIMIT_CORE, &raised) == 0) {
                core_armed = 1;
            }
        }
    }

    {
        struct rusage ru;
        char *const argv[] = { (char *)"/bin/true", NULL };
        check(tee_spawn_converter(argv[0], argv, 0, NULL, 0) == TEE_SUBPROC_TIMEOUT,
              "timeout_secs == 0 never returns OK (budget spent)");
        check(tee_spawn_converter(argv[0], argv, -5, NULL, 0) == TEE_SUBPROC_TIMEOUT,
              "negative timeout never returns OK");
        getrusage(RUSAGE_CHILDREN, &ru);
        check(ru.ru_minflt == 0 && ru.ru_majflt == 0 &&
              ru.ru_nvcsw == 0 && ru.ru_nivcsw == 0 &&
              ru.ru_utime.tv_sec == 0 && ru.ru_utime.tv_usec == 0,
              "a spent budget forks no child at all");
    }

    check(run_sh("exit 0", 5, NULL, 0) == TEE_SUBPROC_OK, "clean exit maps to OK");
    check(run_sh("exit 3", 5, NULL, 0) == TEE_SUBPROC_FAIL, "nonzero exit maps to FAIL");

    {
        char *const argv[] = { (char *)"/nonexistent/pigcloud-tee-no-such-bin", NULL };
        check(tee_spawn_converter(argv[0], argv, 5, NULL, 0) == TEE_SUBPROC_FAIL,
              "failed exec maps to FAIL via _exit(127)");
    }

    check(run_sh("exec 9>&1; [ \"$(readlink /proc/self/fd/9)\" = /dev/null ]", 5, NULL, 0)
              == TEE_SUBPROC_OK,
          "child stdout is /dev/null");
    check(run_sh("[ \"$(readlink /proc/self/fd/2)\" = /dev/null ]", 5, NULL, 0)
              == TEE_SUBPROC_OK,
          "child stderr is /dev/null");

    if (core_armed) {
        check(run_sh("[ \"$(ulimit -c)\" = 0 ]", 5, NULL, 0) == TEE_SUBPROC_OK,
              "RLIMIT_CORE is 0 (a crash cannot spill plaintext to a core file)");
    } else {
        printf("  [SKIP] RLIMIT_CORE check not armed\n");
    }
    check(run_sh("[ \"$(ulimit -t)\" = 50 ]", 5, NULL, 0) == TEE_SUBPROC_OK,
          "RLIMIT_CPU backstop is timeout_secs * 4 + 30");

    {
        tee_memfd_pair_t io;
        const char *why = NULL;
        if (tee_memfd_pair_open(&io, "spawn_test_in", "spawn_test_out",
                                (const unsigned char *)MARKER, strlen(MARKER), &why) != 0) {
            printf("  [FAIL] tee_memfd_pair_open: %s\n", why ? why : "?");
            return 1;
        }
        int hi = fcntl(io.in_fd, F_DUPFD_CLOEXEC, 51);
        if (hi < 0) {
            printf("  [FAIL] F_DUPFD_CLOEXEC\n");
            return 1;
        }
        lseek(hi, 0, SEEK_SET);

        char script[128];
        snprintf(script, sizeof(script),
                 "[ \"$(cat /proc/self/fd/%d)\" = %s ]", hi, MARKER);

        check(run_sh(script, 5, (const int[]){hi}, 1) == TEE_SUBPROC_OK,
              "a kept fd survives exec and carries the plaintext");

        lseek(hi, 0, SEEK_SET);
        check(run_sh(script, 5, NULL, 0) != TEE_SUBPROC_OK,
              "an unlisted fd is CLOEXEC-closed before exec");

        int flags = fcntl(hi, F_GETFD);
        check(flags >= 0 && (flags & FD_CLOEXEC),
              "parent's fd keeps FD_CLOEXEC after a spawn that kept it");

        close(hi);
        tee_memfd_close(&io.in_fd);
        tee_memfd_close(&io.out_fd);
    }

    {
        long t0 = now_ms();
        int rc = run_sh("sleep 30", 1, NULL, 0);
        long elapsed = now_ms() - t0;
        check(rc == TEE_SUBPROC_TIMEOUT, "a wedged converter maps to TIMEOUT");
        check(elapsed < 5000, "the deadline kill fires promptly (no watchdog wait)");
    }

    printf("\n%s (%d failure%s)\n", g_failures ? "FAILURES" : "ALL PASSED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
