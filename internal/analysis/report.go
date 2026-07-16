// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

// Package analysis decodes crash TLVs into readable reports.
package analysis

import (
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/laststate/relay/internal/lep"
	"github.com/laststate/relay/internal/symbolicate"
)

// Report is the structured offline analysis result for one LEP incident.
type Report struct {
	ProtocolVersion  uint8               `json:"protocol_version"`
	EventID          uint32              `json:"event_id"`
	Sequence         uint32              `json:"sequence"`
	EventType        uint8               `json:"event_type"`
	Architecture     uint8               `json:"architecture"`
	ArchitectureName string              `json:"architecture_name,omitempty"`
	CPU              *CPU                `json:"cpu,omitempty"`
	Fault            *Fault              `json:"fault,omitempty"`
	Frames           []symbolicate.Frame `json:"frames,omitempty"`
	Tasks            []Task              `json:"tasks,omitempty"`
	CurrentTask      string              `json:"current_task,omitempty"`
	RTOS             string              `json:"rtos,omitempty"`
	Confidence       float64             `json:"confidence,omitempty"`
	MemoryClass      string              `json:"memory_class,omitempty"`
	Warnings         []string            `json:"warnings,omitempty"`
}

type CPU struct {
	Architecture uint8  `json:"architecture"`
	Fault        uint8  `json:"fault"`
	LR           uint32 `json:"lr"`
	PC           uint32 `json:"pc"`
	SP           uint32 `json:"sp,omitempty"`
}

type Fault struct {
	CFSR  uint32 `json:"cfsr,omitempty"`
	HFSR  uint32 `json:"hfsr,omitempty"`
	MMFAR uint32 `json:"mmfar,omitempty"`
	BFAR  uint32 `json:"bfar,omitempty"`
	// RISC-V style
	MCAUSE     uint32   `json:"mcause,omitempty"`
	MEPC       uint32   `json:"mepc,omitempty"`
	MTVAL      uint32   `json:"mtval,omitempty"`
	Causes     []string `json:"causes,omitempty"`
	Probable   string   `json:"probable_cause,omitempty"`
	MMFARValid bool     `json:"mmfar_valid,omitempty"`
	BFARValid  bool     `json:"bfar_valid,omitempty"`
}

type AnalyzeOptions struct {
	ArtifactPath string
	MemoryMap    []MemoryRegion
	PathMap      symbolicate.PathMap
	Cache        *symbolicate.Cache
	ArtifactSHA  string
	Keyring      lep.Keyring
}

func Analyze(raw []byte) (Report, error) { return AnalyzeWithArtifact(raw, "") }

func AnalyzeWithArtifact(raw []byte, artifactPath string) (Report, error) {
	return AnalyzeWithOptions(raw, AnalyzeOptions{ArtifactPath: artifactPath})
}

func AnalyzeWithOptions(raw []byte, opts AnalyzeOptions) (Report, error) {
	envelope, err := lep.Validate(raw)
	if err != nil {
		return Report{}, err
	}
	report := Report{
		ProtocolVersion:  envelope.Version,
		EventID:          envelope.EventID,
		Sequence:         envelope.Sequence,
		EventType:        envelope.Type,
		Architecture:     envelope.Architecture,
		ArchitectureName: ArchitectureName(envelope.Architecture),
		Confidence:       0.5,
	}
	fields, err := lep.DecodeTLVs(raw, opts.Keyring)
	if err != nil {
		// Fall back to plain TLVs for unauthenticated envelopes.
		fields, err = lep.TLVs(raw)
		if err != nil {
			report.Warnings = append(report.Warnings, err.Error())
			return report, nil
		}
	}
	arch := envelope.Architecture
	for _, field := range fields {
		switch field.Type {
		case 4: // LS_TLV_CPU_CONTEXT
			cpu, warn := decodeCPU(field.Value, arch)
			if warn != "" {
				report.Warnings = append(report.Warnings, warn)
			}
			if cpu != nil {
				report.CPU = cpu
				if cpu.Architecture != 0 {
					arch = cpu.Architecture
					report.ArchitectureName = ArchitectureName(arch)
				}
			}
		case 5: // LS_TLV_FAULT_REGISTERS
			fault, warn := decodeFault(field.Value, arch)
			if warn != "" {
				report.Warnings = append(report.Warnings, warn)
			}
			report.Fault = fault
		case TLVRTOSTasks:
			tasks, rtos, warns := ParseRTOSTasks(field.Value)
			report.Tasks = tasks
			report.RTOS = rtos
			report.Warnings = append(report.Warnings, warns...)
		case TLVRTOSCurrent:
			name, warns := ParseRTOSCurrent(field.Value)
			report.CurrentTask = name
			report.Warnings = append(report.Warnings, warns...)
			for i := range report.Tasks {
				if report.Tasks[i].Name == name {
					report.Tasks[i].Current = true
				}
			}
		}
	}
	if report.CPU != nil && len(opts.MemoryMap) > 0 {
		report.MemoryClass = ClassifyAddress(uint64(report.CPU.PC), opts.MemoryMap)
	}
	report.Confidence = scoreConfidence(report)

	if opts.ArtifactPath != "" && report.CPU != nil {
		addresses := []uint64{uint64(report.CPU.PC &^ 1)}
		if report.CPU.LR != 0 {
			addresses = append(addresses, uint64(report.CPU.LR&^1))
		}
		symOpts := symbolicate.Options{PathMap: opts.PathMap, Cache: opts.Cache, ArtifactSHA: opts.ArtifactSHA}
		frames, warns, err := symbolicate.ResolveDebugFile(opts.ArtifactPath, addresses, symOpts)
		report.Warnings = append(report.Warnings, warns...)
		if err != nil {
			report.Warnings = append(report.Warnings, "symbolication: "+err.Error())
		} else {
			report.Frames = frames
		}
	}
	return report, nil
}

func decodeCPU(value []byte, arch uint8) (*CPU, string) {
	if len(value) < 2 {
		return nil, fmt.Sprintf("CPU context TLV is truncated (%d bytes)", len(value))
	}
	cpuArch := value[0]
	if cpuArch == 0 {
		cpuArch = arch
	}
	cpu := &CPU{Architecture: cpuArch, Fault: value[1]}
	switch cpuArch {
	case ArchRISCV:
		// proposal: lr@8, pc@12, sp@16 when enough bytes; else fall through to cortex offsets
		if len(value) >= 20 {
			cpu.LR = binary.LittleEndian.Uint32(value[8:12])
			cpu.PC = binary.LittleEndian.Uint32(value[12:16])
			cpu.SP = binary.LittleEndian.Uint32(value[16:20])
			return cpu, ""
		}
	case ArchAVR, ArchPIC:
		// Short experimental layouts (not Latch multi-arch container).
		if len(value) >= 12 {
			cpu.PC = binary.LittleEndian.Uint32(value[4:8])
			cpu.LR = binary.LittleEndian.Uint32(value[8:12])
			return cpu, ""
		}
	}
	// Default Latch multi-arch CPU TLV (Cortex-M / RISC-V / Xtensa / Linux).
	if len(value) >= 138 {
		cpu.LR = binary.LittleEndian.Uint32(value[130:134])
		cpu.PC = binary.LittleEndian.Uint32(value[134:138])
		if len(value) >= 130 {
			cpu.SP = binary.LittleEndian.Uint32(value[126:130])
		}
		return cpu, ""
	}
	if len(value) >= 12 {
		cpu.PC = binary.LittleEndian.Uint32(value[4:8])
		cpu.LR = binary.LittleEndian.Uint32(value[8:12])
		return cpu, fmt.Sprintf("CPU context used short layout (%d bytes)", len(value))
	}
	return nil, fmt.Sprintf("CPU context TLV is truncated (%d bytes)", len(value))
}

func decodeFault(value []byte, arch uint8) (*Fault, string) {
	switch arch {
	case ArchRISCV:
		if len(value) >= 12 {
			fault := &Fault{
				MCAUSE: binary.LittleEndian.Uint32(value[0:4]),
				MEPC:   binary.LittleEndian.Uint32(value[4:8]),
				MTVAL:  binary.LittleEndian.Uint32(value[8:12]),
			}
			fault.Causes, fault.Probable = decodeRISCVFault(fault.MCAUSE)
			return fault, ""
		}
		return nil, fmt.Sprintf("RISC-V fault TLV truncated (%d bytes)", len(value))
	default:
		if len(value) >= 24 {
			fault := &Fault{
				CFSR:  binary.LittleEndian.Uint32(value[0:4]),
				HFSR:  binary.LittleEndian.Uint32(value[4:8]),
				MMFAR: binary.LittleEndian.Uint32(value[16:20]),
				BFAR:  binary.LittleEndian.Uint32(value[20:24]),
			}
			fault.Causes, fault.Probable, fault.MMFARValid, fault.BFARValid = decodeCortexMFault(fault.CFSR, fault.HFSR)
			return fault, ""
		}
		return nil, fmt.Sprintf("fault-register TLV is truncated (%d bytes)", len(value))
	}
}

func decodeRISCVFault(mcause uint32) (causes []string, probable string) {
	interrupt := mcause>>31 != 0
	code := mcause & 0x7fffffff
	if interrupt {
		probable = fmt.Sprintf("interrupt cause %d", code)
		causes = []string{probable}
		return causes, probable
	}
	names := map[uint32]string{
		0:  "instruction address misaligned",
		1:  "instruction access fault",
		2:  "illegal instruction",
		3:  "breakpoint",
		4:  "load address misaligned",
		5:  "load access fault",
		6:  "store/AMO address misaligned",
		7:  "store/AMO access fault",
		8:  "environment call from U-mode",
		11: "environment call from M-mode",
	}
	if name, ok := names[code]; ok {
		return []string{name}, name
	}
	probable = fmt.Sprintf("exception cause %d", code)
	return []string{probable}, probable
}

func decodeCortexMFault(cfsr, hfsr uint32) (causes []string, probable string, mmfarValid, bfarValid bool) {
	bits := []struct {
		mask uint32
		text string
	}{
		{1 << 0, "instruction access violation"}, {1 << 1, "data access violation"},
		{1 << 3, "MemManage unstacking error"}, {1 << 4, "MemManage stacking error"},
		{1 << 5, "MemManage lazy floating-point preservation error"},
		{1 << 8, "instruction bus error"}, {1 << 9, "precise data bus error"},
		{1 << 10, "imprecise data bus error"}, {1 << 11, "BusFault unstacking error"},
		{1 << 12, "BusFault stacking error"}, {1 << 13, "BusFault lazy floating-point preservation error"},
		{1 << 16, "undefined instruction"}, {1 << 17, "invalid execution state"},
		{1 << 18, "invalid exception return"}, {1 << 19, "coprocessor access error"},
		{1 << 24, "unaligned access"}, {1 << 25, "division by zero"},
	}
	for _, bit := range bits {
		if cfsr&bit.mask != 0 {
			causes = append(causes, bit.text)
		}
	}
	mmfarValid = cfsr&(1<<7) != 0
	bfarValid = cfsr&(1<<15) != 0
	if hfsr&(1<<30) != 0 {
		causes = append(causes, "configurable fault escalated to HardFault")
	}
	if hfsr&(1<<1) != 0 {
		causes = append(causes, "vector table read fault")
	}
	if hfsr&(1<<31) != 0 {
		causes = append(causes, "debug event generated HardFault")
	}
	if len(causes) > 0 {
		probable = causes[0]
	}
	return causes, probable, mmfarValid, bfarValid
}

func scoreConfidence(report Report) float64 {
	score := 0.4
	if report.CPU != nil && report.CPU.PC != 0 {
		score += 0.2
	}
	if report.Fault != nil && report.Fault.Probable != "" {
		score += 0.2
	}
	if len(report.Frames) > 0 && report.Frames[0].Function != "" {
		score += 0.15
	}
	if report.MemoryClass != "" && report.MemoryClass != "unknown" {
		score += 0.05
	}
	if score > 1 {
		score = 1
	}
	return score
}

func (report Report) Text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Last State incident\n\nEvent ID: %d\nSequence: %d\nArchitecture: %s (%d)\nConfidence: %.2f\n",
		report.EventID, report.Sequence, report.ArchitectureName, report.Architecture, report.Confidence)
	if report.CPU != nil {
		fmt.Fprintf(&b, "CPU PC: 0x%08x\nCPU LR: 0x%08x\n", report.CPU.PC, report.CPU.LR)
	}
	if report.MemoryClass != "" {
		fmt.Fprintf(&b, "PC memory class: %s\n", report.MemoryClass)
	}
	if report.Fault != nil {
		if report.Fault.CFSR != 0 || report.Fault.HFSR != 0 {
			fmt.Fprintf(&b, "Fault CFSR: 0x%08x\nFault HFSR: 0x%08x\n", report.Fault.CFSR, report.Fault.HFSR)
		}
		if report.Fault.MCAUSE != 0 || report.Fault.MEPC != 0 {
			fmt.Fprintf(&b, "Fault MCAUSE: 0x%08x\nFault MEPC: 0x%08x\nFault MTVAL: 0x%08x\n", report.Fault.MCAUSE, report.Fault.MEPC, report.Fault.MTVAL)
		}
		if report.Fault.Probable != "" {
			fmt.Fprintf(&b, "Probable cause: %s\n", report.Fault.Probable)
		}
		for _, cause := range report.Fault.Causes {
			fmt.Fprintf(&b, "  - %s\n", cause)
		}
		if report.Fault.MMFARValid {
			fmt.Fprintf(&b, "MMFAR: 0x%08x\n", report.Fault.MMFAR)
		}
		if report.Fault.BFARValid {
			fmt.Fprintf(&b, "BFAR: 0x%08x\n", report.Fault.BFAR)
		}
	}
	if report.RTOS != "" {
		fmt.Fprintf(&b, "\nRTOS: %s\n", report.RTOS)
	}
	if report.CurrentTask != "" {
		fmt.Fprintf(&b, "Current task: %s\n", report.CurrentTask)
	}
	for _, task := range report.Tasks {
		fmt.Fprintf(&b, "  task %s state=%s prio=%d stack_hw=0x%x\n", task.Name, task.State, task.Priority, task.StackHigh)
	}
	if len(report.Frames) > 0 {
		b.WriteString("\nSymbolication\n")
		for _, frame := range report.Frames {
			location := frame.File
			if frame.Line > 0 {
				location = fmt.Sprintf("%s:%d", location, frame.Line)
			}
			inline := ""
			if frame.Inline {
				inline = " [inline]"
			}
			fmt.Fprintf(&b, "  0x%08x  %s%s  %s\n", frame.Address, defaultString(frame.Function, "<unknown>"), inline, location)
		}
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(&b, "Warning: %s\n", warning)
	}
	return b.String()
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
