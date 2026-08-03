#ifndef PIGCLOUD_TEE_ADMISSION_H
#define PIGCLOUD_TEE_ADMISSION_H

#include <pthread.h>
#include <stdatomic.h>

#include "protocol.h"
#include "vendor/cjson/cJSON.h"

#define WORKER_POOL_SIZE 4
#define WORK_QUEUE_CAPACITY 64

#define TEE_MEMORYMAX_BYTES        (32ULL * 1024 * 1024 * 1024)
#define TEE_SCAN_MEM_BUDGET_BYTES  (TEE_MEMORYMAX_BYTES / 2)

#define TEE_SCAN_MEM_RESERVE_MULT  3
_Static_assert(TEE_SCAN_MEM_RESERVE_MULT * TEE_MAX_PLAINTEXT_SIZE <= TEE_SCAN_MEM_BUDGET_BYTES,
    "memory budget must admit one worst-case scan on an idle daemon");

typedef struct {
    int fds[WORK_QUEUE_CAPACITY];
    int head;
    int tail;
    int count;
    int shutdown;
    pthread_mutex_t mu;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} work_queue_t;

void tee_queue_init(work_queue_t *q);

void tee_queue_push(work_queue_t *q, int fd);

int tee_queue_try_push(work_queue_t *q, int fd);

int tee_queue_pop(work_queue_t *q);

void tee_queue_shutdown(work_queue_t *q);

int tee_admission_reserve(atomic_llong *inflight_bytes, long long reserve_bytes);

void tee_admission_release(atomic_llong *inflight_bytes, long long reserve_bytes);

cJSON *tee_admission_busy_response(void);

int tee_scan_past_deadline(const char *verdict, uint64_t elapsed_ms);

#endif
