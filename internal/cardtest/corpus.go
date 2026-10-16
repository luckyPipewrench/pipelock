// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package cardtest supplies one JSON card corpus to transport parity tests.
package cardtest

import "strconv"

// JSONCase is a complete JSON document and its expected generic card verdict.
type JSONCase struct {
	Name  string
	Body  string
	Clean bool
	Warn  bool // detected number-only run; forward with a record
}

// JSONCases covers a single decimal, adjacent scalar runs, and ordinary
// telemetry. Fixtures assemble card values at runtime from separate pieces.
func JSONCases() []JSONCase {
	card := "4111" + "1111" + "1111" + "1111"
	groups := "4111,1111" + ",1111,1111"
	return []JSONCase{
		{Name: "single decimal telemetry", Body: `{"n":0.` + card + `}`, Clean: true},
		{Name: "ordinary numeric array", Body: `[1200.21,3400.22,5600.23,7800.24]`, Clean: true},
		{Name: "array number run", Body: `[` + groups + `]`, Warn: true},
		{Name: "two number pieces", Body: `[` + card[:8] + `,` + card[8:] + `]`, Warn: true},
		{Name: "sibling number run", Body: `{"a":4111,"b":1111,"c":1111,"d":1111}`, Warn: true},
		{Name: "nested number run", Body: `{"a":[4111,{"b":1111}],"c":[1111,1111]}`, Warn: true},
		{Name: "integral decimal groups", Body: `[4111.0,1111.0,1111.0,1111.0]`, Warn: true},
		{Name: "fractional groups", Body: `[4111.21,1111.22,1111.23,1111.24]`, Warn: true},
		{Name: "digit string run", Body: `["4111","1111","1111","1111"]`},
		{Name: "mixed scalar run", Body: `{"a":"4111","b":1111,"c":1111,"d":1111}`},
		{Name: "trailing string run", Body: `[4111,1111,1111,"1111"]`},
		{Name: "negative integer card", Body: `{"n":-` + card + `.1}`},
		{Name: "integer card", Body: `{"n":` + card + `}`},
		{Name: "integer decimal card", Body: `{"n":` + card + `.0}`},
		{Name: "integer fraction card", Body: `{"n":` + card + `.25}`},
		{Name: "integer exponent card", Body: `{"n":` + card + `e-2}`},
		{Name: "string card", Body: `{"n":"` + card + `"}`},
		{Name: "number run and string card", Body: `{"ids":[` + groups + `],"card":"` + card + `"}`},
		{Name: "number run and single card", Body: `{"ids":[` + groups + `],"card":` + card + `}`},
	}
}

// StringifiedJSONCases models a terminal result whose output is serialized JSON.
func StringifiedJSONCases() []JSONCase {
	var cases []JSONCase
	for _, c := range JSONCases() {
		if c.Clean {
			continue
		}
		c.Name = "serialized output/" + c.Name
		c.Body = `{"output":` + strconv.Quote(c.Body) + `,"exit_code":0,"error":null}`
		cases = append(cases, c)
	}
	return cases
}
