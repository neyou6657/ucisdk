#include "queue.h"

#include <string.h>

void queue_init(job_queue_t *queue) {
    memset(queue, 0, sizeof(*queue));
    pthread_mutex_init(&queue->lock, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
}

int queue_push(job_queue_t *queue, const job_t *job) {
    pthread_mutex_lock(&queue->lock);
    while (!queue->stop && queue->count >= MAX_QUEUE_DEPTH) {
        pthread_cond_wait(&queue->not_full, &queue->lock);
    }
    if (queue->stop) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }
    queue->items[queue->tail] = *job;
    queue->tail = (queue->tail + 1) % MAX_QUEUE_DEPTH;
    queue->count++;
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->lock);
    return 0;
}

int queue_pop(job_queue_t *queue, job_t *job) {
    pthread_mutex_lock(&queue->lock);
    while (!queue->stop && queue->count == 0) {
        pthread_cond_wait(&queue->not_empty, &queue->lock);
    }
    if (queue->stop && queue->count == 0) {
        pthread_mutex_unlock(&queue->lock);
        return -1;
    }
    *job = queue->items[queue->head];
    queue->head = (queue->head + 1) % MAX_QUEUE_DEPTH;
    queue->count--;
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
    return 0;
}

void queue_stop(job_queue_t *queue) {
    pthread_mutex_lock(&queue->lock);
    queue->stop = true;
    pthread_cond_broadcast(&queue->not_empty);
    pthread_cond_broadcast(&queue->not_full);
    pthread_mutex_unlock(&queue->lock);
}
