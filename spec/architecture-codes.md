# Architecture codes (v1 frozen)

Canonical = Latch producer table + protocol registry.

| Code | Name |
|------|------|
| 0 | unknown |
| 1 | cortex-m |
| 2 | riscv |
| 3 | xtensa |
| 4 | linux |
| 5 | arm-a (future / analysis) |
| 6 | avr |
| 7 | pic |
| 8 | nxp |
| 9 | renesas |

CPU context (TLV 4) and fault regs (TLV 5) use the Latch multi-arch container for codes 1–4.
See protocol `architectures/` and `registry/tlv-types.md`.
