#ifndef SERVER_H
#define SERVER_H

#include "queue.h"
#include "scheduler.h"

typedef struct {
    const char *socket_path;
    int server_fd;
    job_queue_t queue;
    scheduler_t scheduler;
    pthread_t workers[DEFAULT_WORKERS];
    size_t worker_count;
} server_t;

int server_run(server_t *server,
               const char *socket_path,
               resource_registry_t *registry,
               const gateway_settings_t *gateway_settings,
               size_t worker_count);

#endif
