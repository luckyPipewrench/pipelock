// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package exec

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/launchcontract"
)

func printEnvironment(out io.Writer, format string, inherited []string, vars []launchcontract.Variable) error {
	set := make(map[string]string, len(vars))
	for _, v := range vars {
		set[v.Name] = v.Value
	}
	kept := make(map[string]bool)
	for _, entry := range launchcontract.Merge(inherited, nil) {
		key, _, _ := strings.Cut(entry, "=")
		kept[key] = true
	}
	remove := make(map[string]bool)
	for _, entry := range inherited {
		key, _, _ := strings.Cut(entry, "=")
		if !kept[key] {
			remove[key] = true
		}
	}
	unset := make([]string, 0, len(remove))
	for key := range remove {
		unset = append(unset, key)
	}
	sort.Strings(unset)
	if format == "json" {
		return json.NewEncoder(out).Encode(struct {
			Set   map[string]string `json:"set"`
			Unset []string          `json:"unset"`
		}{set, unset})
	}
	// Buffer the whole program: an unsupported value must not emit a partial
	// environment that could be sourced despite the nonzero exit status.
	var b strings.Builder
	for _, key := range unset {
		if !validEnvName(key) {
			return errors.New("cannot print an inherited environment key safely; use --print-env json")
		}
		switch format {
		case "sh":
			fmt.Fprintf(&b, "unset %s\n", key)
		case "pwsh":
			fmt.Fprintf(&b, "Remove-Item Env:%s -ErrorAction SilentlyContinue\n", key)
		case "cmd":
			fmt.Fprintf(&b, "set \"%s=\"\r\n", key)
		default:
			return errors.New("unknown environment format")
		}
	}
	for _, v := range vars {
		switch format {
		case "sh":
			fmt.Fprintf(&b, "export %s='%s'\n", v.Name, strings.ReplaceAll(v.Value, "'", "'\"'\"'"))
		case "pwsh":
			fmt.Fprintf(&b, "$env:%s = '%s'\n", v.Name, strings.ReplaceAll(v.Value, "'", "''"))
		case "cmd":
			if strings.ContainsAny(v.Value, "\x00\r\n\"%!") {
				return errors.New("cmd cannot safely represent this value; use --print-env pwsh or json")
			}
			fmt.Fprintf(&b, "set \"%s=%s\"\r\n", v.Name, v.Value)
		default:
			return errors.New("unknown environment format")
		}
	}
	_, err := io.WriteString(out, b.String())
	return err
}

func validEnvName(name string) bool {
	if name == "" {
		return false
	}
	for i, c := range name {
		allowed := c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9'
		if !allowed {
			return false
		}
	}
	return true
}
