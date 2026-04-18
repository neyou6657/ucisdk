#ifndef SCHEDULER_H
#define SCHEDULER_H

#include "driver.h"
#include "resource.h"

typedef struct {
    resource_registry_t *registry;
    const gateway_settings_t *gateway_settings;
} scheduler_t;

void scheduler_init(scheduler_t *scheduler,
                    resource_registry_t *registry,
                    const gateway_settings_t *gateway_settings);
int scheduler_execute(scheduler_t *scheduler, const request_t *req, response_t *resp);

#endif
