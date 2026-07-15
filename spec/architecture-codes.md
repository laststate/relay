# Architecture codes (draft)

| Code | Name |
|------|------|
| 0 | unknown |
| 1 | cortex-m |
| 2 | riscv |
| 3 | arm-a |
| 4 | xtensa |
| 5 | avr |
| 6 | pic |
| 7 | nxp (family tag) |
| 8 | renesas (family tag) |

CPU context (TLV 4) and fault regs (TLV 5) layouts depend on the architecture.
See `internal/analysis`.
