// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"syscall/js"

	"github.com/luckyPipewrench/pipelock/internal/playground"
)

type wasmCheck struct {
	Name string `json:"name"`
	Pass bool   `json:"pass"`
}

type wasmResult struct {
	Valid    bool        `json:"valid"`
	Checks   []wasmCheck `json:"checks"`
	RunNonce string      `json:"runNonce,omitempty"`
	Observed int         `json:"observed"`
	Error    string      `json:"error,omitempty"`
}

func main() {
	js.Global().Set("pipelockVerifyBundle", js.FuncOf(verifyBundle))
	select {}
}

func verifyBundle(_ js.Value, args []js.Value) (ret any) {
	defer func() {
		if r := recover(); r != nil {
			ret = resultValue(wasmResult{Valid: false, Error: fmt.Sprintf("verify panic: %v", r)})
		}
	}()
	if len(args) != 1 {
		return resultValue(wasmResult{Valid: false, Error: "expected one bundle argument"})
	}
	bundle, err := bundleBytes(args[0])
	if err != nil {
		return resultValue(wasmResult{Valid: false, Error: err.Error()})
	}
	rep, err := playground.VerifyPublishedBundleBytes(bundle)
	if err != nil {
		return resultValue(wasmResult{Valid: false, Error: err.Error()})
	}
	out := wasmResult{
		Valid:    rep.OK,
		RunNonce: rep.RunNonce,
		Observed: rep.ObservedCount,
	}
	for _, check := range rep.Checks {
		out.Checks = append(out.Checks, wasmCheck{Name: check.Name, Pass: check.OK})
		if !check.OK && out.Error == "" {
			out.Error = check.Reason
		}
	}
	return resultValue(out)
}

func bundleBytes(v js.Value) ([]byte, error) {
	uint8Array := js.Global().Get("Uint8Array")
	arrayBuffer := js.Global().Get("ArrayBuffer")
	switch {
	case v.Type() == js.TypeString:
		return stringBundleBytes(v.String())
	case uint8Array.Truthy() && v.InstanceOf(uint8Array):
		out := make([]byte, v.Get("byteLength").Int())
		js.CopyBytesToGo(out, v)
		return out, nil
	case arrayBuffer.Truthy() && v.InstanceOf(arrayBuffer):
		u8 := uint8Array.New(v)
		out := make([]byte, u8.Get("byteLength").Int())
		js.CopyBytesToGo(out, u8)
		return out, nil
	default:
		return nil, fmt.Errorf("bundle must be a Uint8Array, ArrayBuffer, or base64 string")
	}
}

func stringBundleBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ','); strings.HasPrefix(s, "data:") && i >= 0 {
		s = s[i+1:]
	}
	s = strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', ' ':
			return -1
		default:
			return r
		}
	}, s)
	if s == "" {
		return nil, fmt.Errorf("bundle string is empty")
	}
	if decoded, err := base64.StdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(s); err == nil {
		return decoded, nil
	}
	return []byte(s), nil
}

func resultValue(result wasmResult) js.Value {
	data, err := json.Marshal(result)
	if err != nil {
		data = []byte(`{"valid":false,"error":"marshal result"}`)
	}
	return js.Global().Get("JSON").Call("parse", string(data))
}
