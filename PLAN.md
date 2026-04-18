# PLAN.md

## 当前阶段

- [x] 统一 API 改成 `domain + action + algorithm`
- [x] 网关 PIN 校验与设备 PIN 解耦
- [x] 两个 adapter 完整覆盖 7 大类接口骨架
- [x] 设备能力改成 `domain:action:algorithm` 声明
- [x] 编译通过
- [x] 单元测试通过
- [x] e2e 通过

## 下一阶段

- [ ] 将 classic adapter 接入真实 `libswsds.so`
- [ ] 将 pqc adapter 接入真实 `libswsds.so`
- [ ] 加入真实错误码映射
- [ ] 加入真实会话与设备生命周期管理
