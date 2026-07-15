# LEP TLV types (draft)

IDs Relay understands today. Upstream protocol may renumber later.

| Type | Name | Notes |
|------|------|--------|
| 0 | reserved | rejected |
| 1–3 | app | not decoded by core |
| 4 | CPU_CONTEXT | arch-specific registers |
| 5 | FAULT_REGISTERS | arch-specific fault regs |
| 6 | RTOS_TASKS | task list |
| 7 | RTOS_CURRENT | current task |
| 8 | MEMORY_MAP | optional regions |
| 0x0010 | BUILD_ID | GNU build-id or UUID |
| 0x0011 | PROJECT_ID | UTF-8 |
| 0x0012 | RELEASE_ID | UTF-8 |
| 0x0013 | FIRMWARE_HASH | SHA-256 of image |
| 0x0020 | ATTACHMENT_META | id, size, hash |
| 0x0021 | ATTACHMENT_CHUNK | index / total / data |
| 0x0030 | PROBE_WAVEFORM | reserved |

Unknown TLVs are kept and ignored by analysis.
