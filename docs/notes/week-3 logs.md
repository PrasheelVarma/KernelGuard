## Day 1 — Monday — Policy Model & JSON Configuration

**Goal for the day:** Establish the JSON policy format and implement a loadable policy engine for network and filesystem allowlists.

### Policy configuration

Created the root-level `policy.json` configuration file with separate allowlists for:

- Network destination IP addresses.
- Filesystem paths permitted for access.

The policy structure provides a clear configuration source for the policy engine.

### Policy engine

Implemented `kernelguard/policy.py` with:

- JSON policy loading.
- Policy file existence checking.
- JSON parsing and error handling.
- Policy structure validation.
- Network IP allowlist evaluation.
- Filesystem path allowlist evaluation.
- Filesystem path normalization for consistent comparisons.
- Explicit deny behavior for resources that are not present in the allowlists.

The policy engine raises dedicated policy exceptions for missing files, invalid JSON, and invalid policy structures.

### Verification

The policy engine was tested directly against both allowed and unlisted resources.

Verified behavior:

```text
1.1.1.1: True
10.0.0.1: False
/tmp/kernelguard-test.txt: True
/etc/passwd: False
```

This confirmed that configured resources are allowed while resources not present in the allowlists are denied.

`kernelguard/policy.py` was also successfully compiled with Python bytecode compilation.

### End-of-day status

- [x] JSON policy format defined.
- [x] Policy-loading module implemented.
- [x] Network IP allowlist implemented.
- [x] Filesystem path allowlist implemented.
- [x] Default deny behavior for unlisted resources implemented.
- [x] Policy validation and error handling implemented.
- [x] Direct policy tests passed.
- [x] Policy module compilation verified.

**Day 1 Policy Model & JSON Configuration complete.**

### Next

Ready for Day 2: **Policy Engine Integration** — connect the policy engine to the existing KernelGuard controller and begin evaluating intercepted network and filesystem events against the loaded policy.
