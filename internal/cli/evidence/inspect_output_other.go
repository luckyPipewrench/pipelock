// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package evidence

import (
	"errors"
	"os"
)

type inspectOutput struct{ file *os.File }

func prepareInspectOutput(string, string, string) (*inspectOutput, error) {
	return nil, errors.New("secure inspection output creation is unsupported on this platform")
}

func (*inspectOutput) syncParent() error { return errors.New("unsupported") }
func (*inspectOutput) parentMatches(string) (bool, error) {
	return false, errors.New("unsupported")
}
func (*inspectOutput) remove() error  { return nil }
func (o *inspectOutput) close() error { return o.file.Close() }
