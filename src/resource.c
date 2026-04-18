#include "resource.h"

#include <stdio.h>
#include <string.h>

void registry_init(resource_registry_t *registry) {
    memset(registry, 0, sizeof(*registry));
    pthread_mutex_init(&registry->lock, NULL);
}

int registry_add(resource_registry_t *registry, const device_resource_t *device) {
    pthread_mutex_lock(&registry->lock);
    if (registry->count >= MAX_DEVICES) {
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }
    registry->devices[registry->count++] = *device;
    pthread_mutex_unlock(&registry->lock);
    return 0;
}

int registry_find_by_id(resource_registry_t *registry, const char *device_id, device_resource_t **out) {
    size_t i;
    for (i = 0; i < registry->count; ++i) {
        if (strcmp(registry->devices[i].device_id, device_id) == 0) {
            *out = &registry->devices[i];
            return 0;
        }
    }
    return -1;
}

int device_supports(const device_resource_t *device,
                    api_domain_t domain,
                    api_action_t action,
                    const char *algorithm) {
    size_t i;
    for (i = 0; i < device->cap_count; ++i) {
        if (device->caps[i].domain != domain) {
            continue;
        }
        if (device->caps[i].action != action) {
            continue;
        }
        if (strcmp(device->caps[i].algorithm, algorithm) == 0 || strcmp(device->caps[i].algorithm, "auto") == 0) {
            return 1;
        }
    }
    return 0;
}

static int better_candidate(const device_resource_t *best,
                            const device_resource_t *cand,
                            preference_t preference) {
    if (best == NULL) {
        return 1;
    }
    if (preference == PREF_SECURE) {
        if (cand->security_score != best->security_score) {
            return cand->security_score > best->security_score;
        }
    } else if (preference == PREF_EFFICIENT) {
        if (cand->efficiency_score != best->efficiency_score) {
            return cand->efficiency_score > best->efficiency_score;
        }
    }
    if (cand->priority != best->priority) {
        return cand->priority < best->priority;
    }
    if (cand->inflight != best->inflight) {
        return cand->inflight < best->inflight;
    }
    return strcmp(cand->device_id, best->device_id) < 0;
}

int registry_acquire_candidate(resource_registry_t *registry,
                               api_domain_t domain,
                               api_action_t action,
                               const char *algorithm,
                               const char *device_hint,
                               preference_t preference,
                               const device_type_t *fallback_order,
                               size_t fallback_len,
                               device_resource_t **out) {
    size_t order_i;
    pthread_mutex_lock(&registry->lock);

    if (device_hint != NULL && device_hint[0] != '\0') {
        size_t i;
        for (i = 0; i < registry->count; ++i) {
            device_resource_t *d = &registry->devices[i];
            if (strcmp(d->device_id, device_hint) == 0 && d->enabled && d->inflight < d->max_inflight &&
                device_supports(d, domain, action, algorithm)) {
                d->inflight++;
                *out = d;
                pthread_mutex_unlock(&registry->lock);
                return 0;
            }
        }
        pthread_mutex_unlock(&registry->lock);
        return -1;
    }

    for (order_i = 0; order_i < fallback_len; ++order_i) {
        device_resource_t *best = NULL;
        size_t i;
        for (i = 0; i < registry->count; ++i) {
            device_resource_t *d = &registry->devices[i];
            if (!d->enabled) continue;
            if (fallback_order[order_i] != DEV_UNKNOWN && d->type != fallback_order[order_i]) continue;
            if (d->inflight >= d->max_inflight) continue;
            if (!device_supports(d, domain, action, algorithm)) continue;
            if (better_candidate(best, d, preference)) {
                best = d;
            }
        }
        if (best != NULL) {
            best->inflight++;
            *out = best;
            pthread_mutex_unlock(&registry->lock);
            return 0;
        }
    }

    pthread_mutex_unlock(&registry->lock);
    return -1;
}

void registry_release(resource_registry_t *registry, const char *device_id) {
    size_t i;
    pthread_mutex_lock(&registry->lock);
    for (i = 0; i < registry->count; ++i) {
        if (strcmp(registry->devices[i].device_id, device_id) == 0) {
            if (registry->devices[i].inflight > 0) {
                registry->devices[i].inflight--;
            }
            break;
        }
    }
    pthread_mutex_unlock(&registry->lock);
}
