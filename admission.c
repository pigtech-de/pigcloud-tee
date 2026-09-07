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

static cJSON *busy_response_with_reason(const char *reason)
{
    cJSON *resp = cJSON_CreateObject();
    if (!resp) {
        return NULL;
    }
    cJSON_AddStringToObject(resp, "verdict", VERDICT_ERROR);
    cJSON_AddStringToObject(resp, "reason", reason);
    cJSON_AddBoolToObject(resp, "busy", 1);
    cJSON_AddNumberToObject(resp, "retry_after_ms", TEE_BUSY_RETRY_AFTER_MS);
    return resp;
}

cJSON *tee_admission_busy_response(void)
{
    return busy_response_with_reason(REASON_SCANNER_BUSY);
}

cJSON *tee_admission_user_busy_response(void)
{
    return busy_response_with_reason(REASON_SCANNER_USER_BUSY);
}

void tee_submitter_table_init(tee_submitter_table_t *t)
{
    memset(t->slots, 0, sizeof(t->slots));
    pthread_mutex_init(&t->mu, NULL);
}

int tee_submitter_acquire(tee_submitter_table_t *t, uint64_t user_id)
{
    if (user_id == 0) {
        return -1;
    }
    pthread_mutex_lock(&t->mu);
    int free_idx = -1;
    for (int i = 0; i < TEE_SUBMITTER_TABLE_SIZE; i++) {
        if (t->slots[i].user_id == user_id) {
            if (t->slots[i].count >= TEE_MAX_INFLIGHT_SCANS_PER_USER) {
                pthread_mutex_unlock(&t->mu);
                return -1;
            }
            t->slots[i].count++;
            pthread_mutex_unlock(&t->mu);
            return 0;
        }
        if (free_idx < 0 && t->slots[i].user_id == 0) {
            free_idx = i;
        }
    }
    if (free_idx < 0) {
        pthread_mutex_unlock(&t->mu);
        return -1;
    }
    t->slots[free_idx].user_id = user_id;
    t->slots[free_idx].count = 1;
    pthread_mutex_unlock(&t->mu);
    return 0;
}

void tee_submitter_release(tee_submitter_table_t *t, uint64_t user_id)
{
    if (user_id == 0) {
        return;
    }
    pthread_mutex_lock(&t->mu);
    for (int i = 0; i < TEE_SUBMITTER_TABLE_SIZE; i++) {
        if (t->slots[i].user_id == user_id) {
            if (t->slots[i].count > 0) {
                t->slots[i].count--;
            }
            if (t->slots[i].count == 0) {
                t->slots[i].user_id = 0;
            }
            break;
        }
    }
    pthread_mutex_unlock(&t->mu);
}

unsigned tee_submitter_inflight(tee_submitter_table_t *t, uint64_t user_id)
{
    unsigned held = 0;
    pthread_mutex_lock(&t->mu);
    for (int i = 0; i < TEE_SUBMITTER_TABLE_SIZE; i++) {
        if (user_id != 0 && t->slots[i].user_id == user_id) {
            held = t->slots[i].count;
            break;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return held;
}

int tee_submitter_table_used(tee_submitter_table_t *t)
{
    int used = 0;
    pthread_mutex_lock(&t->mu);
    for (int i = 0; i < TEE_SUBMITTER_TABLE_SIZE; i++) {
        if (t->slots[i].user_id != 0) {
            used++;
        }
    }
    pthread_mutex_unlock(&t->mu);
    return used;
}
