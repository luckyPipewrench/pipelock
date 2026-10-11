// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package jsonscan

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// DecodeStrict validates keys before binding one JSON value to a schema.
// Unknown fields reject and numbers retain their original decimal spelling.
func DecodeStrict(data []byte, target any) error {
	if err := ValidateKeys(data, MaxNestingDepth); err != nil {
		return err
	}
	typ := reflect.TypeOf(target)
	if typ == nil || typ.Kind() != reflect.Pointer || reflect.ValueOf(target).IsNil() {
		return &json.InvalidUnmarshalError{Type: typ}
	}
	if err := RejectStructAliases(data, typ); err != nil {
		return err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	return dec.Decode(target)
}

var jsonUnmarshalerType = reflect.TypeFor[json.Unmarshaler]()

// RejectStructAliases refuses noncanonical spellings of typed JSON fields,
// recursively. Map keys remain application data, but map values are checked
// against their declared types. Custom unmarshallers own their nested schema.
func RejectStructAliases(data []byte, typ reflect.Type) error {
	if typ == nil {
		return nil
	}
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return rejectNestedAliases(data, typ)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if fields == nil {
		return nil // Let the caller's strict decoder report the schema error.
	}
	schema := structFields(typ, make(map[reflect.Type]bool))
	for key, value := range fields {
		// An exact field wins before folded lookup, just as in encoding/json.
		if field, ok := schema[key]; ok && !field.ambiguous {
			if err := rejectNestedAliases(value, field.typ); err != nil {
				return err
			}
			continue
		}
		for name, field := range schema {
			if !field.ambiguous && key != name && strings.EqualFold(key, name) {
				return fmt.Errorf("%w: %q aliases %q", ErrCaseFoldedKey, key, name)
			}
		}
	}
	return nil
}

func rejectNestedAliases(data []byte, typ reflect.Type) error {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if reflect.PointerTo(typ).Implements(jsonUnmarshalerType) {
		return nil
	}
	switch typ.Kind() {
	case reflect.Struct:
		return RejectStructAliases(data, typ)
	case reflect.Slice, reflect.Array:
		if typ.Elem().Kind() == reflect.Uint8 {
			return nil
		}
		var items []json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := rejectNestedAliases(item, typ.Elem()); err != nil {
				return err
			}
		}
	case reflect.Map:
		var items map[string]json.RawMessage
		if err := json.Unmarshal(data, &items); err != nil {
			return err
		}
		for _, item := range items {
			if err := rejectNestedAliases(item, typ.Elem()); err != nil {
				return err
			}
		}
	}
	return nil
}

// schemaField records promotion priority without descending through recursive
// embedded pointers indefinitely. Ambiguous promoted fields are ignored by JSON.
type schemaField struct {
	typ       reflect.Type
	depth     int
	tagged    bool
	ambiguous bool
}

func structFields(typ reflect.Type, ancestors map[reflect.Type]bool) map[string]schemaField {
	fields := make(map[string]schemaField)
	if ancestors[typ] {
		return fields
	}
	ancestors[typ] = true
	defer delete(ancestors, typ)
	add := func(name string, candidate schemaField) {
		previous, exists := fields[name]
		if !exists || candidate.depth < previous.depth ||
			(candidate.depth == previous.depth && candidate.tagged && !previous.tagged) {
			fields[name] = candidate
		} else if candidate.depth == previous.depth && candidate.tagged == previous.tagged {
			previous.ambiguous = true
			fields[name] = previous
		}
	}
	for i := range typ.NumField() {
		field := typ.Field(i)
		name := strings.Split(field.Tag.Get("json"), ",")[0]
		if name == "-" || (!field.IsExported() && !field.Anonymous) {
			continue
		}
		embedded := field.Type
		if embedded.Kind() == reflect.Pointer {
			embedded = embedded.Elem()
		}
		if name == "" && field.Anonymous && embedded.Kind() == reflect.Struct {
			for childName, child := range structFields(embedded, ancestors) {
				child.depth++
				add(childName, child)
			}
			continue
		}
		if !field.IsExported() && embedded.Kind() != reflect.Struct {
			continue
		}
		tagged := name != ""
		if !tagged {
			name = field.Name
		}
		add(name, schemaField{typ: field.Type, tagged: tagged})
	}
	return fields
}
