// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package analysis

import (
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestAnalyzeCortexMFields(t *testing.T) {
	cpu := make([]byte, 138)
	cpu[0] = 1
	cpu[1] = 3
	binary.LittleEndian.PutUint32(cpu[130:134], 0x08001234)
	binary.LittleEndian.PutUint32(cpu[134:138], 0x08005678)
	payload := append([]byte{4, 0, byte(len(cpu)), 0}, cpu...)
	raw := makeEnvelope(payload)
	report, err := Analyze(raw)
	if err != nil {
		t.Fatal(err)
	}
	if report.CPU == nil || report.CPU.PC != 0x08005678 || report.CPU.LR != 0x08001234 {
		t.Fatalf("report: %#v", report)
	}
}

func makeEnvelope(payload []byte) []byte {
	raw := make([]byte, 24+len(payload)+4)
	copy(raw, "LSTP")
	raw[4], raw[5] = 1, 2
	binary.LittleEndian.PutUint32(raw[8:12], 7)
	binary.LittleEndian.PutUint32(raw[12:16], 9)
	binary.LittleEndian.PutUint32(raw[16:20], uint32(len(payload)))
	binary.LittleEndian.PutUint32(raw[20:24], crc32.ChecksumIEEE(raw[:20]))
	copy(raw[24:], payload)
	binary.LittleEndian.PutUint32(raw[24+len(payload):], crc32.ChecksumIEEE(payload))
	return raw
}
