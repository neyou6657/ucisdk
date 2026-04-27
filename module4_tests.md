# module4_tests

Build and test targets have been updated for the new source layout.

The gateway binary is built from:

- `src/server/gateway/`
- `src/server/service/`
- `src/server/driver/`
- `src/common/`

The client binary is built from:

- `src/client/api/`
- `src/client/core/`
- `src/client/transport/`
- `src/common/`

Run:

```bash
make
make test
```
