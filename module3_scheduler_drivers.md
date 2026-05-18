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

## 密钥归属与调度约束

调度器先执行网关 PIN 校验，再解析 `key_ref`。内部索引密钥请求必须能解析到具体设备；托管密钥请求由 `key_id` 映射到设备和密钥位置；外部密钥请求可以按能力表自由选择支持外部密钥的后端。设备能力支持三段式 `domain:action:algorithm` 和四段式 `domain:action:algorithm:key_source`，例如软件库可声明 `asym:sign:sm2:external_key`，从而在调度阶段拒绝内部索引密钥。adapter 的不支持返回只作为兜底。
