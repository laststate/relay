// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package analysis

import (
	"encoding/binary"
	"fmt"
)

// RTOS-related TLV type IDs.
const (
	TLVRTOSTasks   uint16 = 6
	TLVRTOSCurrent uint16 = 7
)

type Task struct {
	Name      string `json:"name,omitempty"`
	State     string `json:"state,omitempty"`
	Priority  uint32 `json:"priority,omitempty"`
	StackHigh uint32 `json:"stack_high_water,omitempty"`
	StackBase uint32 `json:"stack_base,omitempty"`
	StackTop  uint32 `json:"stack_top,omitempty"`
	Current   bool   `json:"current,omitempty"`
	RTOS      string `json:"rtos,omitempty"`
}

// ParseRTOSTasks decodes a compact task table:
//
//	u8 rtos_id (1=FreeRTOS, 2=Zephyr, 3=ThreadX, 4=NuttX, 5=CMSIS-RTOS)
//	u8 count
//	repeated:
//	  u8 name_len + name
//	  u8 state
//	  u32 priority
//	  u32 stack_high
func ParseRTOSTasks(value []byte) ([]Task, string, []string) {
	var warnings []string
	if len(value) < 2 {
		return nil, "", []string{"rtos tasks TLV too short"}
	}
	rtos := rtosName(value[0])
	count := int(value[1])
	offset := 2
	tasks := make([]Task, 0, count)
	for i := 0; i < count; i++ {
		if offset >= len(value) {
			warnings = append(warnings, "rtos tasks truncated")
			break
		}
		nameLen := int(value[offset])
		offset++
		if offset+nameLen+1+4+4 > len(value) {
			warnings = append(warnings, "rtos task entry truncated")
			break
		}
		name := string(value[offset : offset+nameLen])
		offset += nameLen
		state := taskState(value[offset], rtos)
		offset++
		priority := binary.LittleEndian.Uint32(value[offset : offset+4])
		offset += 4
		stackHigh := binary.LittleEndian.Uint32(value[offset : offset+4])
		offset += 4
		tasks = append(tasks, Task{Name: name, State: state, Priority: priority, StackHigh: stackHigh, RTOS: rtos})
	}
	return tasks, rtos, warnings
}

func ParseRTOSCurrent(value []byte) (string, []string) {
	if len(value) == 0 {
		return "", []string{"rtos current TLV empty"}
	}
	return string(value), nil
}

func rtosName(id uint8) string {
	switch id {
	case 1:
		return "freertos"
	case 2:
		return "zephyr"
	case 3:
		return "threadx"
	case 4:
		return "nuttx"
	case 5:
		return "cmsis-rtos"
	default:
		return "unknown"
	}
}

func taskState(code uint8, rtos string) string {
	// FreeRTOS eTaskState-ish mapping for id 1; generic otherwise.
	if rtos == "freertos" {
		switch code {
		case 0:
			return "running"
		case 1:
			return "ready"
		case 2:
			return "blocked"
		case 3:
			return "suspended"
		case 4:
			return "deleted"
		}
	}
	if rtos == "zephyr" {
		switch code {
		case 0:
			return "dummy"
		case 1:
			return "pending"
		case 2:
			return "prestart"
		case 3:
			return "dead"
		case 4:
			return "suspended"
		case 5:
			return "aborting"
		case 6:
			return "queued"
		}
	}
	return fmt.Sprintf("state-%d", code)
}
