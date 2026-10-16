// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package cardtest supplies one JSON card corpus to transport parity tests.
package cardtest

// JSONCase is a complete JSON document and its expected generic card verdict.
type JSONCase struct {
	Name  string
	Body  string
	Clean bool
}

// JSONCases covers a single decimal, adjacent scalar runs, and ordinary
// telemetry. Fixtures assemble card values at runtime from separate pieces.
func JSONCases() []JSONCase {
	card := "4111" + "1111" + "1111" + "1111"
	groups := "4111,1111" + ",1111,1111"
	return []JSONCase{
		{"single decimal telemetry", `{"n":0.` + card + `}`, true},
		{"ordinary numeric array", `[1200.21,3400.22,5600.23,7800.24]`, true},
		{"array number run", `[` + groups + `]`, false},
		{"sibling number run", `{"a":4111,"b":1111,"c":1111,"d":1111}`, false},
		{"nested number run", `{"a":[4111,{"b":1111}],"c":[1111,1111]}`, false},
		{"mixed scalar run", `{"a":"4111","b":1111,"c":1111,"d":1111}`, false},
		{"integer card", `{"n":` + card + `}`, false},
		{"string card", `{"n":"` + card + `"}`, false},
	}
}
