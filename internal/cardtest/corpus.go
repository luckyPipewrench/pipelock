// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package cardtest supplies one JSON card corpus to transport parity tests.
package cardtest

import (
	"strconv"
	"strings"
)

// JSONCase is a complete JSON document and its expected generic card verdict.
type JSONCase struct {
	Name  string
	Body  string
	Clean bool
	Warn  bool // informational evidence; forward with a record
}

// JSONCases covers a single decimal, adjacent scalar runs, and ordinary
// telemetry. Fixtures assemble card values at runtime from separate pieces.
func JSONCases() []JSONCase {
	card := Number()
	visa19 := card + "110"
	groups := "4111,1111" + ",1111,1111"
	cases := []JSONCase{
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
	cases = append(cases,
		JSONCase{Name: "eight digit string pieces", Body: `["` + card[:8] + `","` + card[8:] + `"]`},
		JSONCase{Name: "uneven string pieces", Body: `["` + card[:2] + `","` + card[2:9] + `","` + card[9:] + `"]`, Warn: true},
		JSONCase{Name: "uneven mixed pieces", Body: `["` + card[:2] + `",` + card[2:9] + `,` + card[9:] + `]`, Warn: true},
		JSONCase{Name: "uneven then whole card", Body: `[["` + card[:2] + `","` + card[2:9] + `","` + card[9:] + `"],"break","` + card + `"]`},
		JSONCase{Name: "numeric separator between string halves", Body: `["` + card[:8] + `",0,"` + card[8:] + `"]`, Clean: true},
		JSONCase{Name: "boolean separator between string halves", Body: `["` + card[:8] + `",false,"` + card[8:] + `"]`, Clean: true},
		JSONCase{Name: "partial piece match stays informational", Body: `["` + visa19[:2] + `","` + visa19[2:] + `"]`, Warn: true},
		JSONCase{Name: "uneven run after boundary text", Body: `{"prefix":"/","values":["` + card[:2] + `","` + card[2:9] + `","` + card[9:] + `"]}`, Warn: true},
		JSONCase{Name: "non digit prefix in piece", Body: `["x` + card[:4] + `","` + card[4:8] + `","` + card[8:12] + `","` + card[12:] + `"]`, Clean: true},
		JSONCase{Name: "non digit suffix in piece", Body: `["` + card[:4] + `,","` + card[4:8] + `","` + card[8:12] + `","` + card[12:] + `"]`, Clean: true},
		JSONCase{Name: "negative partial number then strings", Body: `[-` + card[:4] + `,"` + card[4:8] + `","` + card[8:12] + `","` + card[12:] + `"]`, Clean: true},
		JSONCase{Name: "changed check digit", Body: `["` + card[:8] + `","` + card[8:15] + `2"]`, Clean: true},
		JSONCase{Name: "non digit break", Body: `["` + card[:8] + `","break","` + card[8:] + `"]`, Clean: true},
		JSONCase{Name: "version component batch", Body: `["2","14","62","9","20","93","3","14","4","4","0","69","2","28","47","0","26","75","4","0","34","0","13","52","4","3","90","5","21","15"]`, Warn: true},
		JSONCase{Name: "phone component glue-only batch", Body: `["1","837","441","7365","1","862","723","2830","1","245","841","9159"]`, Warn: true},
		JSONCase{Name: "date component batch", Body: `["2024","02","16","2029","08","27","2026","01","16","2022","06","18"]`, Warn: true},
		JSONCase{Name: "phone batch matching shipped rule", Body: `["1","637","636","5534","1","675","924","0178","1","441","851","1665"]`},
		JSONCase{Name: "space grouped string halves", Body: `["` + card[:4] + ` ` + card[4:8] + `","` + card[8:12] + ` ` + card[12:] + `"]`},
		JSONCase{Name: "dash grouped string halves", Body: `["` + card[:4] + `-` + card[4:8] + `","` + card[8:12] + `-` + card[12:] + `"]`},
		JSONCase{Name: "grouped string then group", Body: `["` + card[:4] + ` ` + card[4:8] + ` ` + card[8:12] + `","` + card[12:] + `"]`},
		JSONCase{Name: "grouped uneven string pieces", Body: `["` + card[:2] + ` ` + card[2:9] + `","` + card[9:] + `"]`, Warn: true},
	)
	var counters []string
	for i := 0; i <= 20; i++ {
		counters = append(counters, strconv.Quote(strconv.Itoa(i)))
	}
	cases = append(cases, JSONCase{Name: "counter strings", Body: `{"list":[` + strings.Join(counters, ",") + `]}`, Warn: true})
	return cases
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
