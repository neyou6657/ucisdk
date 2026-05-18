# Managed Key Routing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn UCiSDK into a托管式统一密码服务平台 while keeping the upper interface strictly as `CCM_*` functions.

**Architecture:** The client continues to call `CCM_*` only. `Unif_KeyRef` carries managed key identity or device-bound internal key metadata. The gateway scheduler resolves key ownership and filters device capability before adapter dispatch; adapter rejection remains only a final safety net.

**Tech Stack:** C11, Makefile, existing gateway scheduler/resource registry, existing test runner.

---

### Task 1: RED - prove internal key indexes cannot be routed globally

**Files:**
- Modify: `tests/test_runner.c`

- [ ] **Step 1: Add failing scheduler tests**

Add tests that prove an internal key without device binding is rejected, and an internal key with `device_id=pqc-1` overrides classic-first preference for shared hash capability.

- [ ] **Step 2: Run RED**

Run: `make test`
Expected: FAIL because scheduler currently ignores `key_ref` ownership metadata.

### Task 2: GREEN - route by key ownership before capability dispatch

**Files:**
- Modify: `src/server/service/scheduler.c`

- [ ] **Step 1: Parse semicolon key_ref tokens**

Implement local helpers to extract `source`, `device_id`, and `key_id` from `key_ref`.

- [ ] **Step 2: Resolve effective device hint**

For `source=1` internal index, require `device_id` in `key_ref` or existing request `device_hint`; otherwise return failure before registry selection.

- [ ] **Step 3: Run GREEN**

Run: `make test`
Expected: PASS.

### Task 3: RED - prove software-library-style external-only devices reject internal keys at scheduling

**Files:**
- Modify: `tests/test_runner.c`
- Modify: `configs/devices.conf`

- [ ] **Step 1: Add softlib external-key-only capability to config**

Add `softlib-1` with `asym:sign:sm2:external_key`.

- [ ] **Step 2: Add failing test**

Test that `device_hint=softlib-1` with `source=1` internal key is rejected before adapter dispatch.

- [ ] **Step 3: Run RED**

Run: `make test`
Expected: FAIL because capability parser and matcher do not understand key-source constraints yet.

### Task 4: GREEN - add key-source-aware capabilities

**Files:**
- Modify: `include/resource.h`
- Modify: `src/server/service/config.c`
- Modify: `src/server/service/resource.c`
- Modify: `src/server/service/scheduler.c`

- [ ] **Step 1: Extend `capability_t`**

Add a key source mask field; three-part capabilities keep current behavior, four-part capabilities constrain key source.

- [ ] **Step 2: Parse fourth capability token**

Support `internal_index`, `session_handle`, `external_key`, and `managed_key`.

- [ ] **Step 3: Filter candidates by key source**

Pass `key_ref` into registry selection and reject candidates whose capability does not support the requested key source.

- [ ] **Step 4: Run GREEN**

Run: `make test`
Expected: PASS.

### Task 5: CCM API metadata and docs

**Files:**
- Modify: `include/ccm.h`
- Modify: `src/client/api/ccm_api.c`
- Modify: `README.md`
- Modify: `PLAN.md`
- Modify: `overall_architecture_zh.md`

- [ ] **Step 1: Extend `Unif_KeyRef`**

Add `szKeyId` and `szDeviceId` so upper callers still use `CCM_*` functions while passing platform key identity or internal-key ownership.

- [ ] **Step 2: Serialize new key fields**

Append `key_id` and `device_id` into `key_ref` when present.

- [ ] **Step 3: Document platform boundary**

State that UCiSDK is a托管式统一密码服务平台: gateway PIN is not device PIN, internal keys require ownership binding, software libraries declare only supported key-source capabilities.

- [ ] **Step 4: Run final verification**

Run: `make && make test && git status --short`.

### Task 6: Commit and push

**Files:** all changed files.

- [ ] **Step 1: Commit**

Run: `git add . && git commit -m "feat: add managed key routing constraints"`

- [ ] **Step 2: Push**

Run: `git push`
