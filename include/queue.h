#ifndef QUEUE_H
#define QUEUE_H

#include "common.h"

typedef struct {
    int client_fd;
    request_t request;
} job_t;

typedef struct {
    job_t items[MAX_QUEUE_DEPTH];
    size_t head;
    size_t tail;
    size_t count;
    bool stop;
    pthread_mutex_t lock;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} job_queue_t;

void queue_init(job_queue_t *queue);
int queue_push(job_queue_t *queue, const job_t *job);
int queue_pop(job_queue_t *queue, job_t *job);
void queue_stop(job_queue_t *queue);

#endif
