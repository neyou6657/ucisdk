# module1_architecture

统一 API 采用 `domain + action + algorithm`。

- `domain`：auth/device/key/asym/sym/hash/file/pqc
- `action`：sign/verify/encrypt/decrypt/kem_encap/kem_decap 等
- `algorithm`：sm2/sm4-cbc/dilithium3/mlkem768 等

Adapter 需要完整覆盖 7 大类函数族。
