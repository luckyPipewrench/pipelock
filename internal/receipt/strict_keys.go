// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

var jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// rejectReceiptAliases checks typed JSON fields before encoding/json's
// case-insensitive struct lookup can collapse distinct signed names.
func rejectReceiptAliases(data []byte) error {
	return rejectStructAliases(data, reflect.TypeFor[Receipt]())
}

func rejectStructAliases(data []byte, typ reflect.Type) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return nil // Let the caller's strict decoder report the schema error.
	}
	for key, value := range fields {
		for i := range typ.NumField() {
			field := typ.Field(i)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				continue
			}
			if key != name && strings.EqualFold(key, name) {
				return fmt.Errorf("%w: %q aliases %q", jsonscan.ErrCaseFoldedKey, key, name)
			}
			if key == name {
				if err := rejectNestedAliases(value, field.Type); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func rejectNestedAliases(data []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
		elem := typ.Elem()
		for elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if elem.Kind() != reflect.Struct || reflect.PointerTo(elem).Implements(jsonUnmarshalerType) {
			return nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := rejectStructAliases(item, elem); err != nil {
				return err
			}
		}
		return nil
	}
	if typ.Kind() == reflect.Struct && !reflect.PointerTo(typ).Implements(jsonUnmarshalerType) {
		return rejectStructAliases(data, typ)
	}
	return nil
}
