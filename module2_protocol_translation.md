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
