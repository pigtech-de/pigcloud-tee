#include <string.h>
#include <unistd.h>

#include "admission.h"

void tee_queue_init(work_queue_t *q)
{
    q->head = q->tail = q->count = 0;
    q->shutdown = 0;
    pthread_mutex_init(&q->mu, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);
}

void tee_queue_push(work_queue_t *q, int fd)
{
    pthread_mutex_lock(&q->mu);
    while (q->count == WORK_QUEUE_CAPACITY && !q->shutdown) {
        pthread_cond_wait(&q->not_full, &q->mu);
    }
    if (q->shutdown) {
        close(fd);
        pthread_mutex_unlock(&q->mu);
        return;
    }
    q->fds[q->tail] = fd;
    q->tail = (q->tail + 1) % WORK_QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mu);
}

int tee_queue_try_push(work_queue_t *q, int fd)
{
    pthread_mutex_lock(&q->mu);
    if (q->shutdown || q->count == WORK_QUEUE_CAPACITY) {
        pthread_mutex_unlock(&q->mu);
        return -1;
    }
    q->fds[q->tail] = fd;
    q->tail = (q->tail + 1) % WORK_QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->not_empty);
    pthread_mutex_unlock(&q->mu);
    return 0;
}

int tee_queue_pop(work_queue_t *q)
{
    pthread_mutex_lock(&q->mu);
    while (q->count == 0 && !q->shutdown) {
        pthread_cond_wait(&q->not_empty, &q->mu);
    }
    if (q->count == 0 && q->shutdown) {
        pthread_mutex_unlock(&q->mu);
        return -1;
    }
    int fd = q->fds[q->head];
    q->head = (q->head + 1) % WORK_QUEUE_CAPACITY;
    q->count--;
    pthread_cond_signal(&q->not_full);
    pthread_mutex_unlock(&q->mu);
    return fd;
}

void tee_queue_shutdown(work_queue_t *q)
{
    pthread_mutex_lock(&q->mu);
    q->shutdown = 1;
    pthread_cond_broadcast(&q->not_empty);
    pthread_cond_broadcast(&q->not_full);
    pthread_mutex_unlock(&q->mu);
}

int tee_admission_reserve(atomic_llong *inflight_bytes, long long reserve_bytes)
{
    long long after = atomic_fetch_add(inflight_bytes, reserve_bytes) + reserve_bytes;
    if (after > (long long)TEE_SCAN_MEM_BUDGET_BYTES) {
        atomic_fetch_sub(inflight_bytes, reserve_bytes);
        return -1;
    }
    return 0;
}

void tee_admission_release(atomic_llong *inflight_bytes, long long reserve_bytes)
{
    atomic_fetch_sub(inflight_bytes, reserve_bytes);
}

int tee_scan_past_deadline(const char *verdict, uint64_t elapsed_ms)
{
    if (verdict && strcmp(verdict, VERDICT_REJECTED) == 0) {
        return 0;
    }
    return elapsed_ms > (uint64_t)TEE_SCAN_WALL_CAP_SECS * 1000u;
}

cJSON *tee_admission_busy_response(void)
{
    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        return NULL;
    }
    cJSON_AddStringToObject(resp, "verdict", VERDICT_ERROR);
    cJSON_AddStringToObject(resp, "reason", REASON_SCANNER_BUSY);
    cJSON_AddBoolToObject(resp, "busy", 1);
    cJSON_AddNumberToObject(resp, "retry_after_ms", TEE_BUSY_RETRY_AFTER_MS);
    return resp;
}
