# module2_protocol_translation

Protocol parsing now belongs to `src/server/gateway/protocol.c`.

Translation from unified API to backend call names belongs to `src/server/service/translator.c`.

Client request flow:

- `src/client/api/client_api.c`
- `src/client/core/client_core.c`
- `src/client/transport/client_transport.c`

Server request flow:

- `src/server/gateway/server.c`
- `src/server/gateway/protocol.c`
- `src/server/service/translator.c`

## key_ref 协议语义

客户端仍只调用 `CCM_*`。封装层把 `Unif_KeyRef` 序列化为 `key_ref`，其中可包含 `source`、`key_index`、`key_handle`、`external_key`、`key_id` 和 `device_id`。协议层不把底层设备 PIN 暴露给客户端；服务端根据 `key_ref` 的 `key_id/device_id/source` 约束后端选择。

示例：托管签名请求中的 `key_ref` 应为 `source=4;key_id=tenant-a-sm2-sign-001`，而不是无归属的 `k1`。
