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

## 托管路由测试

新增测试覆盖托管密钥路由约束：内部索引密钥缺少设备绑定时失败；带 `device_id` 的内部密钥覆盖偏好并路由到指定设备；只支持外部密钥的软件库拒绝内部索引密钥；外部密钥可以路由到软件库。完整验证命令为 `make clean && make && make test`。
