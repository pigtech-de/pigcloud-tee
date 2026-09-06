#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <dirent.h>
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

static int open_fd_count(void)
{
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    while (readdir(d) != NULL) n++;
    closedir(d);
    return n;
}

static int chain_open(tee_attempt_chain_t *c, int budget_secs, int per_attempt_cap)
{
    tee_memfd_pair_t io;
    const char *why = NULL;
    if (tee_memfd_pair_open(&io, "chain_test_in", "chain_test_out",
                            (const unsigned char *)MARKER, strlen(MARKER), &why) != 0) {
        printf("  [FAIL] tee_memfd_pair_open: %s\n", why ? why : "?");
        return -1;
    }
    tee_chain_begin(c, SH, &io, budget_secs, per_attempt_cap);
    return 0;
}

static int chain_write_attempt(tee_attempt_chain_t *c, const char *out_path,
                               const char *payload, int exit_code)
{
    char script[256];
    snprintf(script, sizeof(script), "printf %s > %s; exit %d", payload, out_path, exit_code);
    char *const argv[] = { (char *)SH, "-c", script, NULL };
    return tee_chain_run(c, argv);
}

static void chain_cases(void)
{
    printf("\nconverter attempt chain (tee_attempt_chain_t)\n");
    const int base = open_fd_count();

    {
        tee_attempt_chain_t c;
        if (chain_open(&c, 30, 5) != 0) { g_failures++; return; }
        char *first = tee_chain_next_output(&c, NULL);
        check(first != NULL && strcmp(first, c.out_path) == 0,
              "the first attempt writes to the pair's own output fd");
        chain_write_attempt(&c, first, "ONE", 0);
        check(c.ok == 1, "a clean first attempt wins the chain");

        unsigned char *out = NULL;
        size_t out_len = 0;
        char reason[64] = "";
        check(tee_chain_finish(&c, &out, &out_len, 1 << 20, "empty", reason, sizeof(reason)) == 0,
              "finish reads the winning output back");
        check(out_len == 3 && memcmp(out, "ONE", 3) == 0,
              "the bytes returned are the winning attempt's, not the input's");
        free(out);
        check(open_fd_count() == base,
              "a won chain leaves no fd open (input and output both closed)");
    }

    {
        tee_attempt_chain_t c;
        if (chain_open(&c, 30, 5) != 0) { g_failures++; return; }
        char *first = tee_chain_next_output(&c, NULL);
        chain_write_attempt(&c, first, "ONE", 3);
        check(c.ok == 0, "a failing attempt does not win the chain");
        check(lseek(c.out_fd, 0, SEEK_END) == 3, "the failing attempt did write to its output");
        int after_attempt = open_fd_count();

        char *retry = tee_chain_next_output(&c, "chain_test_retry");
        check(retry != NULL, "a retry gets an output fd");
        check(lseek(c.out_fd, 0, SEEK_END) == 0,
              "the retry writes to a fresh memfd, not the spent attempt's leftovers");
        check(open_fd_count() == after_attempt,
              "a retry closes the output it replaced instead of leaking it");

        chain_write_attempt(&c, retry, "TWO", 0);
        unsigned char *out = NULL;
        size_t out_len = 0;
        char reason[64] = "";
        check(tee_chain_finish(&c, &out, &out_len, 1 << 20, "empty", reason, sizeof(reason)) == 0
                  && out_len == 3 && memcmp(out, "TWO", 3) == 0,
              "the retry's output is what finish returns");
        free(out);
        check(open_fd_count() == base, "a retried chain leaves no fd open");
    }

    {
        tee_attempt_chain_t c;
        if (chain_open(&c, 30, 5) != 0) { g_failures++; return; }
        chain_write_attempt(&c, tee_chain_next_output(&c, NULL), "ONE", 3);
        chain_write_attempt(&c, tee_chain_next_output(&c, "chain_test_retry"), "TWO", 4);
        check(c.ok == 0 && c.timed_out == 0, "every attempt failing is not a timeout");
        check(strcmp(tee_chain_failure_reason(&c, "decode_failed"), "decode_failed") == 0,
              "a plain all-attempts failure keeps the caller's reason");
        tee_chain_abort(&c);
        check(open_fd_count() == base, "abort closes both fds after a lost chain");
    }

    {
        tee_attempt_chain_t c;
        if (chain_open(&c, 30, 1) != 0) { g_failures++; return; }
        char *first = tee_chain_next_output(&c, NULL);
        char script[128];
        snprintf(script, sizeof(script), "sleep 30 > %s", first);
        char *const argv[] = { (char *)SH, "-c", script, NULL };
        check(tee_chain_run(&c, argv) == TEE_SUBPROC_TIMEOUT, "a wedged attempt maps to TIMEOUT");
        check(c.timed_out == 1, "the chain remembers the deadline kill");
        check(strcmp(tee_chain_failure_reason(&c, "decode_failed"), "ffmpeg_timeout") == 0,
              "a deadline kill reports ffmpeg_timeout, never the decode reason");

        chain_write_attempt(&c, tee_chain_next_output(&c, "chain_test_retry"), "TWO", 0);
        check(c.ok == 1, "a later attempt can still win after one timed out");
        check(strcmp(tee_chain_failure_reason(&c, "decode_failed"), "ffmpeg_timeout") == 0,
              "the timeout flag survives a retry, so a mixed chain still audits as a hang");
        tee_chain_abort(&c);
        check(open_fd_count() == base, "abort closes both fds after a timed-out chain");
    }
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

    chain_cases();

    printf("\n%s (%d failure%s)\n", g_failures ? "FAILURES" : "ALL PASSED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
