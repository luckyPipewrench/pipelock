// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"reflect"

	"github.com/luckyPipewrench/pipelock/internal/jsonscan"
)

func rejectReceiptAliases(data []byte) error {
	return rejectStructAliases(data, reflect.TypeFor[Receipt]())
}

func rejectStructAliases(data []byte, typ reflect.Type) error {
	return jsonscan.RejectStructAliases(data, typ)
}
