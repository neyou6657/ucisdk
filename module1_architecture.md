# module1_architecture

统一 API 采用 `domain + action + algorithm`。

- `domain`: auth/device/key/asym/sym/hash/file/pqc
- `action`: sign/verify/encrypt/decrypt/kem_encap/kem_decap etc.
- `algorithm`: sm2/sm4-cbc/dilithium3/mlkem768 etc.

Source layout:

- `src/client/api/`: client API layer
- `src/client/core/`: client wrapper layer
- `src/client/transport/`: client communication layer
- `src/server/gateway/`: server gateway layer
- `src/server/service/`: server service layer
- `src/server/driver/`: server driver layer
- `src/common/`: shared code

Adapters live under `src/server/driver/`.
