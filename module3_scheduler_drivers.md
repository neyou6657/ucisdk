# module3_scheduler_drivers

Scheduler and resource code now lives in the service layer:

- `src/server/service/resource.c`
- `src/server/service/scheduler.c`

Driver and adapter code now lives in the driver layer:

- `src/server/driver/driver_dispatch.c`
- `src/server/driver/driver_classic.c`
- `src/server/driver/driver_pqc.c`
- `src/server/driver/skf_adapter.c`

The service layer selects the target device and translated backend call. The driver layer isolates vendor-specific or algorithm-specific behavior.
