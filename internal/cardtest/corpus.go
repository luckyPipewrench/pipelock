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
		{Name: "sibling number run", Body: `{"a":4111,"b":1111,"c":1111,"d":1111}`, Clean: true},
		{Name: "nested number run", Body: `{"a":[4111,{"b":1111}],"c":[1111,1111]}`, Clean: true},
		{Name: "integral decimal groups", Body: `[4111.0,1111.0,1111.0,1111.0]`, Warn: true},
		{Name: "fractional groups", Body: `[4111.21,1111.22,1111.23,1111.24]`, Warn: true},
		{Name: "digit string run", Body: `["4111","1111","1111","1111"]`},
		{Name: "mixed scalar run", Body: `{"a":"4111","b":1111,"c":1111,"d":1111}`, Clean: true},
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
		JSONCase{Name: "negative partial number then strings", Body: `[-` + card[:4] + `,"` + card[4:8] + `","` + card[8:12] + `","` + card[12:] + `"]`},
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
	cases = append(cases, UnionCases()...)
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

// UnionCases exercises both enforcing readings and literal scalar barriers.
func UnionCases() []JSONCase {
	// UNION keeps complete-piece candidates as well as greedy shipped-rule
	// windows over literal scalar context. Keys occupy the same stream as values.
	card := Number()
	groups := card[:4] + "," + card[4:8] + "," + card[8:12] + "," + card[12:]
	high := "4111" + strings.Repeat("9", 12)
	q := strconv.Quote
	a, b, c, d := card[:4], card[4:8], card[8:12], card[12:]
	strings4 := q(a) + "," + q(b) + "," + q(c) + "," + q(d)
	return []JSONCase{
		{Name: "context prefixed split", Body: `[` + q("card "+a) + `,` + q(b+" "+c+" "+d) + `]`},
		{Name: "context prefixed invalid checksum", Body: `[` + q("card "+a) + `,` + q(b+" "+c+" "+d[:3]+"2") + `]`, Clean: true},
		{Name: "greedy invalid window keeps ordinary FindAll", Body: `[` + q("card "+a) + `,` + q(b) + `,` + q(c) + `,` + q(d) + `,"1"]`, Clean: true},
		{Name: "prepended digit padding", Body: `["1",` + strings4 + `]`},
		{Name: "appended digit padding", Body: `[` + strings4 + `,"1"]`},
		{Name: "prepended four digit padding", Body: `["1000",` + strings4 + `]`},
		{Name: "twelve plus four strings", Body: `[` + q(card[:12]) + `,` + q(card[12:]) + `]`},
		{Name: "leading space piece", Body: `[` + q(a) + `,` + q(" "+b) + `,` + q(c) + `,` + q(d) + `]`, Clean: true},
		{Name: "leading dash piece", Body: `[` + q(a) + `,` + q(b) + `,` + q(c) + `,` + q("-"+d) + `]`, Clean: true},
		{Name: "null interruption", Body: `[` + q(a) + `,null,` + q(b) + `,` + q(c) + `,` + q(d) + `]`, Clean: true},
		{Name: "empty string interruption", Body: `[` + q(a) + `,"",` + q(b) + `,` + q(c) + `,` + q(d) + `]`, Clean: true},
		{Name: "boolean interruption", Body: `[` + q(a) + `,true,` + q(b) + `,` + q(c) + `,` + q(d) + `]`, Clean: true},
		{Name: "string interruption", Body: `[` + q(a) + `,"break",` + q(b) + `,` + q(c) + `,` + q(d) + `]`, Clean: true},
		{Name: "mixed first string", Body: `[` + q(a) + `,` + b + `,` + c + `,` + d + `]`},
		{Name: "mixed middle string", Body: `[` + a + `,` + q(b) + `,` + c + `,` + d + `]`},
		{Name: "context string outside numeric hit", Body: `["context",` + groups + `]`, Warn: true},
		{Name: "non digit key interruption", Body: `[` + q(card[:8]) + `,{"break":` + q(card[8:]) + `}]`, Clean: true},
		{Name: "JSON looking text preserves key barriers", Body: `{"a":` + q("["+q("card "+a)+",") + `,"b":` + q(q(b+" "+c+" "+d)+"]") + `}`, Clean: true},
		{Name: "non digit key between numbers", Body: `[` + card[:8] + `,{"break":` + card[8:] + `}]`, Clean: true},
		{Name: "nested array remains adjacent", Body: `[[` + q(a) + `],[` + q(b) + `,[` + q(c) + `]],` + q(d) + `]`},
		{Name: "digit key joins values in source order", Body: `{"` + a + `":` + q(b) + `,"` + c + `":` + q(d) + `}`},
		{Name: "reversed object keys retain source order", Body: `{"` + b + `":` + q(c) + `,"` + a + `":` + q(d) + `,"end":false}`, Clean: true},
		{Name: "sorting cannot create card", Body: `[` + q(high[4:8]) + `,` + q(high[:4]) + `,` + q(high[8:12]) + `,` + q(high[12:]) + `,false]`, Clean: true},
		{Name: "sorting card positive control", Body: `[` + q(high[:4]) + `,` + q(high[4:8]) + `,` + q(high[8:12]) + `,` + q(high[12:]) + `]`},
	}
}
