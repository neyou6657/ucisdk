#ifndef RESOURCE_H
#define RESOURCE_H

#include "common.h"

typedef struct {
    api_domain_t domain;
    api_action_t action;
    char algorithm[MAX_FIELD_LEN];
} capability_t;

typedef struct {
    char device_id[MAX_FIELD_LEN];
    device_type_t type;
    char backend_profile[MAX_FIELD_LEN];
    int priority;
    bool enabled;
    int max_inflight;
    int inflight;
    int security_score;
    int efficiency_score;
    capability_t caps[MAX_CAPS];
    size_t cap_count;
} device_resource_t;

typedef struct {
    device_resource_t devices[MAX_DEVICES];
    size_t count;
    pthread_mutex_t lock;
} resource_registry_t;

void registry_init(resource_registry_t *registry);
int registry_add(resource_registry_t *registry, const device_resource_t *device);
int registry_find_by_id(resource_registry_t *registry, const char *device_id, device_resource_t **out);
int registry_acquire_candidate(resource_registry_t *registry,
                               api_domain_t domain,
                               api_action_t action,
                               const char *algorithm,
                               const char *device_hint,
                               preference_t preference,
                               const device_type_t *fallback_order,
                               size_t fallback_len,
                               device_resource_t **out);
void registry_release(resource_registry_t *registry, const char *device_id);
int device_supports(const device_resource_t *device,
                    api_domain_t domain,
                    api_action_t action,
                    const char *algorithm);

#endif
