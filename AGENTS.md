# AGENTS.md

## 总体约束

1. 必须保持统一 API 为 `domain + action + algorithm`。
2. 不得把网关 PIN 当成底层密码机 PIN 透传。
3. adapter 层必须保留 7 大类 handler：
   - device_manage
   - key_manage
   - asym_crypto
   - sym_crypto
   - hash_ops
   - file_ops
   - pqc_ops
4. 新设备接入优先方式：
   - 先补 `configs/devices.conf`
   - 再补 translator 映射表
   - 若函数参数不兼容，再新增 adapter 文件
5. 每次改动后必须：
   - `make`
   - `make test`
6. 修改架构时同步更新：
   - `overall_architecture_zh.md`
   - `README.md`
   - `PLAN.md`
