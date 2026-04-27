#include "server.h"

#include "log.h"
#include "protocol.h"

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static volatile sig_atomic_t g_stop = 0;

static void on_signal(int signo) {
    (void)signo;
    g_stop = 1;
}

static int read_line(int fd, char *buf, size_t buf_sz) {
    size_t i = 0;
    while (i + 1 < buf_sz) {
        char c;
        ssize_t n = read(fd, &c, 1);
        if (n == 0) {
            break;
        }
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -1;
        }
        if (c == '\n') {
            break;
        }
        buf[i++] = c;
    }
    buf[i] = '\0';
    return (int)i;
}

static void write_response_and_close(int fd, const response_t *resp) {
    char json[MAX_RESPONSE_LEN + 512];
    int n = response_to_json(resp, json, sizeof(json));
    if (n > 0) {
        (void)write(fd, json, (size_t)n);
        (void)write(fd, "\n", 1U);
    }
    close(fd);
}

static void *worker_main(void *arg) {
    server_t *server = (server_t *)arg;
    for (;;) {
        job_t job;
        response_t resp;
        memset(&resp, 0, sizeof(resp));
        if (queue_pop(&server->queue, &job) != 0) {
            return NULL;
        }
        scheduler_execute(&server->scheduler, &job.request, &resp);
        write_response_and_close(job.client_fd, &resp);
    }
}

static int create_server_socket(const char *socket_path) {
    int fd;
    struct sockaddr_un addr;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", socket_path);
    unlink(socket_path);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        close(fd);
        return -1;
    }
    if (listen(fd, 64) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int server_run(server_t *server,
               const char *socket_path,
               resource_registry_t *registry,
               const gateway_settings_t *gateway_settings,
               size_t worker_count) {
    size_t i;
    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    memset(server, 0, sizeof(*server));
    server->socket_path = socket_path;
    server->worker_count = worker_count > DEFAULT_WORKERS ? DEFAULT_WORKERS : worker_count;
    queue_init(&server->queue);
    scheduler_init(&server->scheduler, registry, gateway_settings);

    server->server_fd = create_server_socket(socket_path);
    if (server->server_fd < 0) {
        log_error("failed to create server socket at %s", socket_path);
        return -1;
    }

    for (i = 0; i < server->worker_count; ++i) {
        pthread_create(&server->workers[i], NULL, worker_main, server);
    }

    log_info("listening on %s", socket_path);
    while (!g_stop) {
        int client_fd;
        char line[2048];
        job_t job;
        char errbuf[256];
        response_t resp;

        client_fd = accept(server->server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }

        if (read_line(client_fd, line, sizeof(line)) <= 0) {
            memset(&resp, 0, sizeof(resp));
            snprintf(resp.request_id, sizeof(resp.request_id), "%s", "unknown");
            resp.status = STATUS_BAD_REQUEST;
            snprintf(resp.result, sizeof(resp.result), "%s", "empty request");
            write_response_and_close(client_fd, &resp);
            continue;
        }

        memset(&job, 0, sizeof(job));
        if (parse_request_json(line, &job.request, errbuf, sizeof(errbuf)) != 0) {
            memset(&resp, 0, sizeof(resp));
            snprintf(resp.request_id, sizeof(resp.request_id), "%s", "unknown");
            resp.status = STATUS_BAD_REQUEST;
            snprintf(resp.result, sizeof(resp.result), "%s", errbuf);
            write_response_and_close(client_fd, &resp);
            continue;
        }
        job.client_fd = client_fd;
        if (queue_push(&server->queue, &job) != 0) {
            memset(&resp, 0, sizeof(resp));
            snprintf(resp.request_id, sizeof(resp.request_id), "%s", job.request.request_id);
            resp.status = STATUS_BACKEND_FAIL;
            snprintf(resp.result, sizeof(resp.result), "%s", "queue stopped");
            write_response_and_close(client_fd, &resp);
            continue;
        }
    }

    queue_stop(&server->queue);
    for (i = 0; i < server->worker_count; ++i) {
        pthread_join(server->workers[i], NULL);
    }
    close(server->server_fd);
    unlink(socket_path);
    return 0;
}
