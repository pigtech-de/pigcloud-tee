#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>

#include "../admission.h"

#define MAX_JOBS 4096
enum { RES_PENDING = 0, RES_DONE, RES_BUSY };

static work_queue_t q;
static long long g_job_size[MAX_JOBS];
static atomic_int g_job_result[MAX_JOBS];

static atomic_llong g_inflight_bytes = 0;
static atomic_llong g_committed_bytes = 0;
static atomic_llong g_peak_committed = 0;
static atomic_ulong g_busy = 0;
static atomic_ulong g_done = 0;
static atomic_int   g_oom = 0;

static void bump_peak(atomic_llong *peak, long long v)
{
    long long cur = atomic_load(peak);
    while (v > cur && !atomic_compare_exchange_weak(peak, &cur, v)) { }
}

static void reset_state(void)
{
    atomic_store(&g_inflight_bytes, 0);
    atomic_store(&g_committed_bytes, 0);
    atomic_store(&g_peak_committed, 0);
    atomic_store(&g_busy, 0);
    atomic_store(&g_done, 0);
    atomic_store(&g_oom, 0);
    for (int i = 0; i < MAX_JOBS; i++) {
        atomic_store(&g_job_result[i], RES_PENDING);
    }
    tee_queue_init(&q);
}

static void run_job(int id, unsigned scan_us)
{
    long long reserve = g_job_size[id] * TEE_SCAN_MEM_RESERVE_MULT;
    if (tee_admission_reserve(&g_inflight_bytes, reserve) != 0) {
        atomic_fetch_add(&g_busy, 1);
        atomic_store(&g_job_result[id], RES_BUSY);
        return;
    }
    long long committed = atomic_fetch_add(&g_committed_bytes, reserve) + reserve;
    bump_peak(&g_peak_committed, committed);
    if (committed > (long long)TEE_MEMORYMAX_BYTES) {
        atomic_store(&g_oom, 1);
    }
    if (scan_us) {
        usleep(scan_us);
    }
    atomic_fetch_sub(&g_committed_bytes, reserve);
    tee_admission_release(&g_inflight_bytes, reserve);
    atomic_fetch_add(&g_done, 1);
    atomic_store(&g_job_result[id], RES_DONE);
}

static unsigned g_scan_us = 3000;

static void *worker_loop(void *arg)
{
    (void)arg;
    for (;;) {
        int id = tee_queue_pop(&q);
        if (id < 0) {
            return NULL;
        }
        run_job(id, g_scan_us);
    }
}

static long long now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

static int g_failures = 0;
static void check(const char *name, int ok)
{
    printf("  [%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) {
        g_failures++;
    }
}

static void test_budget_shed(void)
{
    printf("(a) memory budget sheds instead of OOM\n");
    reset_state();
    g_scan_us = 4000;
    pthread_t w[WORKER_POOL_SIZE];
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        pthread_create(&w[i], NULL, worker_loop, NULL);
    }
    const int n = 200;
    for (int i = 0; i < n; i++) {
        g_job_size[i] = (long long)TEE_MAX_PLAINTEXT_SIZE;
        while (tee_queue_try_push(&q, i) != 0) {
            usleep(200);
        }
    }
    tee_queue_shutdown(&q);
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        pthread_join(w[i], NULL);
    }
    check("no OOM: committed never exceeded MemoryMax", atomic_load(&g_oom) == 0);
    check("peak committed stayed within budget",
          atomic_load(&g_peak_committed) <= (long long)TEE_SCAN_MEM_BUDGET_BYTES);
    check("some large scans shed busy", atomic_load(&g_busy) > 0);
    check("every job resolved (done or busy)",
          (long)(atomic_load(&g_done) + atomic_load(&g_busy)) == n);
    check("committed drained to zero", atomic_load(&g_committed_bytes) == 0);
    check("inflight accumulator drained to zero", atomic_load(&g_inflight_bytes) == 0);
    printf("      done=%lu busy=%lu peak_committed=%lldGB\n",
           atomic_load(&g_done), atomic_load(&g_busy),
           atomic_load(&g_peak_committed) / (1024 * 1024 * 1024));
}

static void test_full_queue_nonblocking(void)
{
    printf("(b) full queue sheds immediately without blocking producer\n");
    reset_state();
    int filled_ok = 1;
    for (int i = 0; i < WORK_QUEUE_CAPACITY; i++) {
        if (tee_queue_try_push(&q, i) != 0) {
            filled_ok = 0;
        }
    }
    check("every queue slot accepted", filled_ok);
    long long t0 = now_us();
    int rc = tee_queue_try_push(&q, 9999);
    long long elapsed = now_us() - t0;
    check("push on full queue returns -1", rc == -1);
    check("push on full queue returned immediately (<2ms)", elapsed < 2000);
    printf("      capacity=%d, full-queue push took %lld us\n",
           WORK_QUEUE_CAPACITY, elapsed);
}

static void test_watchdog_not_starved(void)
{
    printf("(c) accept-thread watchdog pings never starved by a full queue\n");
    reset_state();
    g_scan_us = 6000;
    pthread_t w[WORKER_POOL_SIZE];
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        pthread_create(&w[i], NULL, worker_loop, NULL);
    }
    long g_pings = 0;
    long shed = 0;
    long long deadline = now_us() + 150000;
    int job = 0;
    long pings_at_first_full = -1;
    while (now_us() < deadline && job < MAX_JOBS) {
        g_pings++;
        g_job_size[job] = 64 * 1024 * 1024;
        if (tee_queue_try_push(&q, job) != 0) {
            shed++;
            if (pings_at_first_full < 0) {
                pings_at_first_full = g_pings;
            }
        } else {
            job++;
        }
        usleep(50);
    }
    long pings_after = g_pings;
    tee_queue_shutdown(&q);
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        pthread_join(w[i], NULL);
    }
    check("queue actually saturated during the run", shed > 0);
    check("pings kept advancing after the queue first filled",
          pings_at_first_full > 0 && pings_after > pings_at_first_full + 10);
    printf("      pings=%ld shed=%ld (first full at ping %ld)\n",
           pings_after, shed, pings_at_first_full);
}

static void test_normal_scans_complete(void)
{
    printf("(d) normal scans enqueue and complete\n");
    reset_state();
    g_scan_us = 500;
    pthread_t w[WORKER_POOL_SIZE];
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        pthread_create(&w[i], NULL, worker_loop, NULL);
    }
    const int n = 500;
    for (int i = 0; i < n; i++) {
        g_job_size[i] = 8 * 1024 * 1024;
        while (tee_queue_try_push(&q, i) != 0) {
            usleep(100);
        }
    }
    tee_queue_shutdown(&q);
    for (int i = 0; i < WORKER_POOL_SIZE; i++) {
        pthread_join(w[i], NULL);
    }
    check("all normal scans completed", (long)atomic_load(&g_done) == n);
    check("no normal scan shed busy", atomic_load(&g_busy) == 0);
}

static void test_busy_reply_shape(void)
{
    printf("(e) scanner_busy reply is wire-distinguishable\n");
    cJSON *busy = tee_admission_busy_response();
    if (!busy) {
        check("tee_admission_busy_response allocated a reply", 0);
        return;
    }
    const cJSON *verdict = cJSON_GetObjectItemCaseSensitive(busy, "verdict");
    const cJSON *reason  = cJSON_GetObjectItemCaseSensitive(busy, "reason");
    const cJSON *flag    = cJSON_GetObjectItemCaseSensitive(busy, "busy");
    const cJSON *retry   = cJSON_GetObjectItemCaseSensitive(busy, "retry_after_ms");

    check("verdict stays error so pre-busy clients fail closed",
          cJSON_IsString(verdict) && strcmp(verdict->valuestring, VERDICT_ERROR) == 0);
    check("reason is the scanner_busy protocol constant",
          cJSON_IsString(reason) && strcmp(reason->valuestring, REASON_SCANNER_BUSY) == 0);
    check("busy is a JSON true, not a string",
          flag != NULL && cJSON_IsTrue(flag));
    check("retry_after_ms is a positive number",
          cJSON_IsNumber(retry) && retry->valuedouble > 0);

    char *json = cJSON_PrintUnformatted(busy);
    if (json) {
        printf("      %s\n", json);
        free(json);
    }
    cJSON_Delete(busy);
}

static void test_monitor_cron_pool_size(void)
{
    printf("(f) monitor-cron.sh POOL_SIZE tracks WORKER_POOL_SIZE\n");
    FILE *f = fopen(TEE_MONITOR_CRON, "r");
    if (!f) {
        printf("      could not open %s\n", TEE_MONITOR_CRON);
        check("monitor-cron.sh readable", 0);
        return;
    }
    char line[512];
    long found = -1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "POOL_SIZE=", 10) == 0) {
            found = strtol(line + 10, NULL, 10);
            break;
        }
    }
    fclose(f);
    if (found < 0) {
        check("monitor-cron.sh declares POOL_SIZE", 0);
        return;
    }
    printf("      script POOL_SIZE=%ld, WORKER_POOL_SIZE=%d\n", found, WORKER_POOL_SIZE);
    check("POOL_SIZE equals WORKER_POOL_SIZE", found == WORKER_POOL_SIZE);
}

static void test_deadline_rejected_wins(void)
{
    printf("(g) per-scan deadline never overrides a rejected verdict\n");
    uint64_t cap_ms = (uint64_t)TEE_SCAN_WALL_CAP_SECS * 1000u;

    check("under the cap, no verdict yet: scan continues",
          tee_scan_past_deadline(NULL, cap_ms - 1) == 0);
    check("past the cap, no verdict yet: deadline fires",
          tee_scan_past_deadline(NULL, cap_ms + 1) == 1);
    check("exactly at the cap: scan continues (strict >)",
          tee_scan_past_deadline(NULL, cap_ms) == 0);
    check("past the cap, rejected verdict: rejection wins",
          tee_scan_past_deadline(VERDICT_REJECTED, cap_ms + 1) == 0);
    check("past the cap, clean verdict: deadline fires",
          tee_scan_past_deadline(VERDICT_CLEAN, cap_ms + 1) == 1);
    check("past the cap, sanitized verdict: deadline fires",
          tee_scan_past_deadline(VERDICT_SANITIZED, cap_ms + 1) == 1);
    check("past the cap, error verdict: deadline fires",
          tee_scan_past_deadline(VERDICT_ERROR, cap_ms + 1) == 1);
}

int main(void)
{
    printf("SCALE-21 admission-control harness "
           "(budget=%lluGB, MemoryMax=%lluGB, pool=%d, queue=%d)\n\n",
           (unsigned long long)(TEE_SCAN_MEM_BUDGET_BYTES / (1024 * 1024 * 1024)),
           (unsigned long long)(TEE_MEMORYMAX_BYTES / (1024 * 1024 * 1024)),
           WORKER_POOL_SIZE, WORK_QUEUE_CAPACITY);
    test_budget_shed();
    test_full_queue_nonblocking();
    test_watchdog_not_starved();
    test_normal_scans_complete();
    test_busy_reply_shape();
    test_monitor_cron_pool_size();
    test_deadline_rejected_wins();
    printf("\n%s (%d failure%s)\n", g_failures ? "FAILED" : "ALL PASSED",
           g_failures, g_failures == 1 ? "" : "s");
    return g_failures ? 1 : 0;
}
