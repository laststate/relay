// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Last State contributors

package symbolicate

import (
	"strings"
)

// Demangle applies best-effort Itanium / Rust-style demangling for common cases.
// Full production demangling may use an external symbolizer; this keeps offline
// analysis useful without shelling out.
func Demangle(name string) string {
	if name == "" {
		return name
	}
	if strings.HasPrefix(name, "_Z") || strings.HasPrefix(name, "__Z") {
		if demangled, ok := demangleItanium(name); ok {
			return demangled
		}
	}
	if strings.HasPrefix(name, "_R") {
		// Rust v0 mangling — return shortened form.
		if len(name) > 40 {
			return name[:40] + "…"
		}
	}
	return name
}

func demangleItanium(name string) (string, bool) {
	input := strings.TrimPrefix(name, "_")
	if !strings.HasPrefix(input, "_Z") {
		return "", false
	}
	// Extremely small subset: _Z<len><name>E... → name
	rest := input[2:]
	if len(rest) == 0 || rest[0] < '0' || rest[0] > '9' {
		return "", false
	}
	length := 0
	i := 0
	for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
		length = length*10 + int(rest[i]-'0')
		i++
	}
	if length <= 0 || i+length > len(rest) {
		return "", false
	}
	return rest[i : i+length], true
}
