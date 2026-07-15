// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package analysis

// Architecture codes — see spec/architecture-codes.md.
const (
	ArchUnknown uint8 = 0
	ArchCortexM uint8 = 1
	ArchRISCV   uint8 = 2
	ArchARMA    uint8 = 3
	ArchXtensa  uint8 = 4
	ArchAVR     uint8 = 5
	ArchPIC     uint8 = 6
	ArchNXP     uint8 = 7
	ArchRenesas uint8 = 8
)

func ArchitectureName(code uint8) string {
	switch code {
	case ArchCortexM:
		return "cortex-m"
	case ArchRISCV:
		return "riscv"
	case ArchARMA:
		return "arm-a"
	case ArchXtensa:
		return "xtensa"
	case ArchAVR:
		return "avr"
	case ArchPIC:
		return "pic"
	case ArchNXP:
		return "nxp"
	case ArchRenesas:
		return "renesas"
	default:
		return "unknown"
	}
}

// MemoryRegion classifies addresses for fault analysis.
type MemoryRegion struct {
	Name  string
	Start uint64
	End   uint64 // exclusive
	Class string // flash, ram, peripheral, invalid, ...
}

func ClassifyAddress(address uint64, regions []MemoryRegion) string {
	for _, region := range regions {
		if address >= region.Start && address < region.End {
			if region.Class != "" {
				return region.Class
			}
			return region.Name
		}
	}
	return "unknown"
}
