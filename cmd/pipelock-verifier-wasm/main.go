// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"syscall/js"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/playground"
	"github.com/luckyPipewrench/pipelock/internal/receipt"
)

type wasmCheck struct {
	Name string `json:"name"`
	Pass bool   `json:"pass"`
}

type wasmResult struct {
	Valid              bool               `json:"valid"`
	Checks             []wasmCheck        `json:"checks"`
	RunNonce           string             `json:"runNonce,omitempty"`
	Observed           int                `json:"observed"`
	Error              string             `json:"error,omitempty"`
	Reason             string             `json:"reason,omitempty"`
	IntegrityVerified  bool               `json:"integrityVerified,omitempty"`
	ReceiptCount       uint64             `json:"receiptCount,omitempty"`
	FinalSeq           uint64             `json:"finalSeq,omitempty"`
	RootHash           string             `json:"rootHash,omitempty"`
	StartTime          string             `json:"startTime,omitempty"`
	EndTime            string             `json:"endTime,omitempty"`
	FailureKind        string             `json:"failureKind,omitempty"`
	BrokenAtSeq        *uint64            `json:"brokenAtSeq,omitempty"`
	BrokenAtIndex      *int               `json:"brokenAtIndex,omitempty"`
	SignerKeys         []string           `json:"signerKeys,omitempty"`
	Segments           []wasmChainSegment `json:"segments,omitempty"`
	UntrustedSignerKey string             `json:"untrustedSignerKey,omitempty"`
}

type wasmChainSegment struct {
	SignerKey string `json:"signerKey"`
	FirstSeq  uint64 `json:"firstSeq"`
	FinalSeq  uint64 `json:"finalSeq"`
	Count     uint64 `json:"count"`
	Boundary  bool   `json:"boundary"`
}

type wasmGroupResult struct {
	Verdict          receipt.ReceiptGroupVerdict `json:"verdict"`
	Valid            bool                        `json:"valid"`
	GroupID          string                      `json:"groupId"`
	BaseSession      string                      `json:"baseSession,omitempty"`
	OpenManifestSHA  string                      `json:"openManifestSha256,omitempty"`
	CloseManifestSHA string                      `json:"closeManifestSha256,omitempty"`
	ShardCount       int                         `json:"shardCount,omitempty"`
	Error            string                      `json:"error,omitempty"`
}

const (
	maxReceiptGroupArchiveBytes     = 8 << 20
	maxReceiptGroupArchiveFiles     = 4096
	maxReceiptGroupArchiveEntrySize = 32 << 20
	maxReceiptGroupArchiveTotalSize = 32 << 20
)

var errReceiptGroupArchiveUnsupported = errors.New("receipt group archive exceeds browser verifier size limit; use a host verifier")

func main() {
	js.Global().Set("pipelockVerifyBundle", js.FuncOf(verifyBundle))
	js.Global().Set("pipelockVerifyChain", js.FuncOf(verifyChain))
	js.Global().Set("pipelockVerifyReceiptGroup", js.FuncOf(verifyReceiptGroup))
	select {}
}

// verifyReceiptGroup verifies a single group selected from a bounded ZIP
// evidence bundle. The trusted signer keys are supplied separately; keys in
// the archive are evidence, never trust anchors.
func verifyReceiptGroup(_ js.Value, args []js.Value) (ret any) {
	defer func() {
		if r := recover(); r != nil {
			ret = groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, Error: fmt.Sprintf("verify panic: %v", r)})
		}
	}()
	if len(args) != 3 {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, Error: "expected ZIP bundle, group ID, and trusted keys"})
	}
	if args[1].Type() != js.TypeString {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, Error: "group ID must be a string"})
	}
	groupID := args[1].String()
	if _, err := receipt.ReceiptGroupFileName(groupID, "open"); err != nil {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, GroupID: groupID, Error: err.Error()})
	}
	bundle, err := bytesValue(args[0], "bundle", stringBundleBytes)
	if err != nil {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, GroupID: groupID, Error: err.Error()})
	}
	if len(bundle) == 0 {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, GroupID: groupID, Error: "receipt group ZIP is empty"})
	}
	if len(bundle) > maxReceiptGroupArchiveBytes {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupIncomplete, GroupID: groupID, Error: errReceiptGroupArchiveUnsupported.Error()})
	}
	keys, err := trustedKeys(args[2])
	if err != nil {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, GroupID: groupID, Error: err.Error()})
	}
	files, err := receiptGroupArchiveFiles(bundle, groupID)
	if err != nil {
		if errors.Is(err, errReceiptGroupArchiveUnsupported) {
			return groupResultValue(wasmGroupResult{Verdict: receipt.GroupIncomplete, GroupID: groupID, Error: err.Error()})
		}
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, GroupID: groupID, Error: err.Error()})
	}
	if len(files) == 0 {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, GroupID: groupID, Error: "receipt group archive has no matching evidence directory"})
	}
	root, err := os.MkdirTemp("", "pipelock-receipt-group-")
	if err != nil {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, GroupID: groupID, Error: fmt.Sprintf("create in-memory receipt group root: %v", err)})
	}
	defer func() { _ = os.RemoveAll(root) }()
	if err := mountReceiptGroupFiles(root, files); err != nil {
		return groupResultValue(wasmGroupResult{Verdict: receipt.GroupInvalid, GroupID: groupID, Error: err.Error()})
	}
	result := receipt.VerifyReceiptGroup(root, groupID, keys)
	return groupResultValue(wasmGroupResult{
		Verdict:          result.Verdict,
		Valid:            result.Verdict == receipt.GroupValid,
		GroupID:          result.GroupID,
		BaseSession:      result.BaseSession,
		OpenManifestSHA:  result.OpenManifestSHA,
		CloseManifestSHA: result.CloseManifestSHA,
		ShardCount:       result.ShardCount,
		Error:            result.Error,
	})
}

func receiptGroupArchiveFiles(bundle []byte, groupID string) (map[string][]byte, error) {
	r, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		return nil, fmt.Errorf("decode receipt group ZIP: %w", err)
	}
	if len(r.File) == 0 || len(r.File) > maxReceiptGroupArchiveFiles {
		return nil, fmt.Errorf("receipt group ZIP entry count is empty or exceeds %d", maxReceiptGroupArchiveFiles)
	}
	openName, _ := receipt.ReceiptGroupFileName(groupID, "open")
	seen := make(map[string]struct{}, len(r.File))
	directories := make(map[string]bool, len(r.File))
	all := make(map[string][]byte, len(r.File))
	var archiveDirs []string
	var total uint64
	root := ""
	foundRoot := false
	for _, file := range r.File {
		name := file.Name
		if !safeReceiptArchiveName(name) {
			return nil, fmt.Errorf("unsafe receipt group ZIP path %q", name)
		}
		if _, ok := seen[name]; ok {
			return nil, fmt.Errorf("duplicate receipt group ZIP path %q", name)
		}
		seen[name] = struct{}{}
		isDir := file.FileInfo().IsDir()
		trimmedName := strings.TrimSuffix(name, "/")
		for parent := path.Dir(trimmedName); parent != "."; parent = path.Dir(parent) {
			if kind, exists := directories[parent]; exists && !kind {
				return nil, fmt.Errorf("receipt group ZIP file %q is a parent path", parent)
			}
		}
		if prior, exists := directories[trimmedName]; exists && prior != isDir {
			return nil, fmt.Errorf("receipt group ZIP path %q is both a file and directory", trimmedName)
		}
		if !isDir {
			for prior := range directories {
				if strings.HasPrefix(prior, trimmedName+"/") {
					return nil, fmt.Errorf("receipt group ZIP file %q is a parent path", trimmedName)
				}
			}
		}
		directories[trimmedName] = isDir
		if isDir {
			archiveDirs = append(archiveDirs, name)
			continue
		}
		if !file.Mode().IsRegular() || file.UncompressedSize64 > maxReceiptGroupArchiveEntrySize {
			if file.UncompressedSize64 > maxReceiptGroupArchiveEntrySize {
				return nil, fmt.Errorf("%w: entry %q", errReceiptGroupArchiveUnsupported, name)
			}
			return nil, fmt.Errorf("receipt group ZIP entry %q is not a regular file", name)
		}
		total += file.UncompressedSize64
		if total > maxReceiptGroupArchiveTotalSize {
			return nil, errReceiptGroupArchiveUnsupported
		}
		reader, err := file.Open()
		if err != nil {
			return nil, fmt.Errorf("open receipt group ZIP entry %q: %w", name, err)
		}
		data, readErr := io.ReadAll(io.LimitReader(reader, maxReceiptGroupArchiveEntrySize+1))
		closeErr := reader.Close()
		if readErr != nil || closeErr != nil || uint64(len(data)) != file.UncompressedSize64 {
			return nil, fmt.Errorf("read receipt group ZIP entry %q: invalid or truncated content", name)
		}
		all[name] = data
		if path.Base(name) == openName {
			candidate := strings.TrimSuffix(name, openName)
			if foundRoot {
				return nil, fmt.Errorf("receipt group ID %s has multiple openings in the ZIP", groupID)
			}
			root = candidate
			foundRoot = true
		}
	}
	if !foundRoot {
		return nil, fmt.Errorf("receipt group %s opening is missing from ZIP", groupID)
	}
	selected := make(map[string][]byte)
	for _, name := range archiveDirs {
		if strings.HasPrefix(name, root) {
			if relative := strings.TrimPrefix(name, root); relative != "" {
				selected[relative] = nil
			}
		}
	}
	for name, data := range all {
		if strings.HasPrefix(name, root) {
			relative := strings.TrimPrefix(name, root)
			if relative == "" || strings.HasPrefix(relative, "../") {
				return nil, fmt.Errorf("invalid receipt group ZIP root selection")
			}
			selected[relative] = data
		}
	}
	return selected, nil
}

func safeReceiptArchiveName(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\x00") || strings.HasPrefix(name, "/") || strings.Contains(name, ":") {
		return false
	}
	trimmed := strings.TrimSuffix(name, "/")
	if trimmed == "" || path.Clean(trimmed) != trimmed {
		return false
	}
	for _, component := range strings.Split(trimmed, "/") {
		if component == "" || component == "." || component == ".." {
			return false
		}
	}
	return true
}

func mountReceiptGroupFiles(root string, files map[string][]byte) error {
	mount := js.Global().Get("pipelockMountReceiptGroup")
	if mount.Type() != js.TypeFunction {
		return fmt.Errorf("in-memory receipt group filesystem is unavailable")
	}
	entries := js.Global().Get("Object").New()
	for name, data := range files {
		if data == nil {
			entries.Set(name, js.Null())
			continue
		}
		bytes := js.Global().Get("Uint8Array").New(len(data))
		if copied := js.CopyBytesToJS(bytes, data); copied != len(data) {
			return fmt.Errorf("copy receipt group ZIP entry %q into memory", name)
		}
		entries.Set(name, bytes)
	}
	mount.Invoke(root, entries)
	return nil
}

func groupResultValue(result wasmGroupResult) js.Value {
	data, err := json.Marshal(result)
	if err != nil {
		data = []byte(`{"verdict":"GROUP_INVALID","valid":false,"error":"marshal result"}`)
	}
	return js.Global().Get("JSON").Call("parse", string(data))
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

func verifyChain(_ js.Value, args []js.Value) (ret any) {
	defer func() {
		if r := recover(); r != nil {
			ret = resultValue(wasmResult{Valid: false, Error: fmt.Sprintf("verify panic: %v", r)})
		}
	}()
	if len(args) != 2 {
		return resultValue(wasmResult{Valid: false, Error: "expected chain bytes and trusted key argument"})
	}
	chain, err := chainBytes(args[0])
	if err != nil {
		return resultValue(wasmResult{Valid: false, Error: err.Error()})
	}
	keys, err := trustedKeys(args[1])
	if err != nil {
		return resultValue(wasmResult{Valid: false, Error: err.Error()})
	}
	receipts, err := receipt.ExtractReceiptsBytes(chain)
	if err != nil {
		return resultValue(wasmResult{
			Valid:  false,
			Checks: []wasmCheck{{Name: "raw_receipts_extracted", Pass: false}},
			Error:  err.Error(),
		})
	}
	if len(receipts) == 0 {
		return resultValue(wasmResult{
			Valid:  false,
			Checks: []wasmCheck{{Name: "raw_receipts_extracted", Pass: false}},
			Error:  "no receipts found in chain",
		})
	}
	result := receipt.VerifyChainTrusted(receipts, keys)
	out := chainResult(result, len(receipts))
	out.Checks = []wasmCheck{
		{Name: "raw_receipts_extracted", Pass: true},
		{Name: "receipt_chain_verified", Pass: result.Valid},
	}
	return resultValue(out)
}

func bundleBytes(v js.Value) ([]byte, error) {
	return bytesValue(v, "bundle", stringBundleBytes)
}

func chainBytes(v js.Value) ([]byte, error) {
	return bytesValue(v, "chain", stringChainBytes)
}

func bytesValue(v js.Value, label string, stringFn func(string) ([]byte, error)) ([]byte, error) {
	uint8Array := js.Global().Get("Uint8Array")
	arrayBuffer := js.Global().Get("ArrayBuffer")
	switch {
	case v.Type() == js.TypeString:
		return stringFn(v.String())
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
		return nil, fmt.Errorf("%s must be a Uint8Array, ArrayBuffer, or base64 string", label)
	}
}

// tryDecodeBase64 attempts standard then raw (unpadded) base64 decoding of an
// already-whitespace-compacted string. Shared by the bundle and chain string
// paths so the two decode attempts cannot drift; only the non-base64 fallback
// differs between callers (bundle compacts whitespace, chain preserves it for
// JSONL parsing).
func tryDecodeBase64(compact string) ([]byte, bool) {
	if decoded, err := base64.StdEncoding.DecodeString(compact); err == nil {
		return decoded, true
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(compact); err == nil {
		return decoded, true
	}
	return nil, false
}

func stringBundleBytes(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ','); strings.HasPrefix(s, "data:") && i >= 0 {
		s = s[i+1:]
	}
	s = compactASCIIWhitespace(s)
	if s == "" {
		return nil, fmt.Errorf("bundle string is empty")
	}
	if decoded, ok := tryDecodeBase64(s); ok {
		return decoded, nil
	}
	return []byte(s), nil
}

func stringChainBytes(s string) ([]byte, error) {
	raw := strings.TrimSpace(s)
	if i := strings.IndexByte(raw, ','); strings.HasPrefix(raw, "data:") && i >= 0 {
		raw = raw[i+1:]
	}
	if raw == "" {
		return nil, fmt.Errorf("chain string is empty")
	}
	if decoded, ok := tryDecodeBase64(compactASCIIWhitespace(raw)); ok {
		return decoded, nil
	}
	return []byte(raw), nil
}

func compactASCIIWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\r', '\n', '\t', ' ':
			return -1
		default:
			return r
		}
	}, s)
}

func trustedKeys(v js.Value) ([]string, error) {
	if v.Type() == js.TypeString {
		return splitTrustedKeys(v.String())
	}
	array := js.Global().Get("Array")
	if array.Truthy() && array.Call("isArray", v).Bool() {
		keys := make([]string, 0, v.Get("length").Int())
		for i := 0; i < v.Get("length").Int(); i++ {
			item := v.Index(i)
			if item.Type() != js.TypeString {
				return nil, fmt.Errorf("trusted key at index %d must be a hex string", i)
			}
			key := strings.TrimSpace(item.String())
			if key == "" {
				return nil, fmt.Errorf("trusted key at index %d is empty", i)
			}
			keys = append(keys, key)
		}
		if len(keys) == 0 {
			return nil, fmt.Errorf("at least one trusted key is required")
		}
		return keys, nil
	}
	return nil, fmt.Errorf("trusted keys must be a hex string or array of hex strings")
}

func splitTrustedKeys(s string) ([]string, error) {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == '\t' || r == ' '
	})
	keys := make([]string, 0, len(fields))
	for _, field := range fields {
		key := strings.TrimSpace(field)
		if key != "" {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("at least one trusted key is required")
	}
	return keys, nil
}

func chainResult(result receipt.ChainResult, observed int) wasmResult {
	out := wasmResult{
		Valid:              result.Valid,
		Observed:           observed,
		Error:              result.Error,
		Reason:             result.Error,
		IntegrityVerified:  result.IntegrityVerified,
		ReceiptCount:       result.ReceiptCount,
		FinalSeq:           result.FinalSeq,
		RootHash:           result.RootHash,
		FailureKind:        string(result.FailureKind),
		SignerKeys:         result.SignerKeys,
		UntrustedSignerKey: result.UntrustedSignerKey,
	}
	if !result.Valid {
		brokenAtSeq := result.BrokenAtSeq
		brokenAtIndex := result.BrokenAtIndex
		out.BrokenAtSeq = &brokenAtSeq
		out.BrokenAtIndex = &brokenAtIndex
	}
	if !result.StartTime.IsZero() {
		out.StartTime = result.StartTime.Format(time.RFC3339Nano)
	}
	if !result.EndTime.IsZero() {
		out.EndTime = result.EndTime.Format(time.RFC3339Nano)
	}
	if len(result.Segments) > 0 {
		out.Segments = make([]wasmChainSegment, 0, len(result.Segments))
		for _, segment := range result.Segments {
			out.Segments = append(out.Segments, wasmChainSegment{
				SignerKey: segment.SignerKey,
				FirstSeq:  segment.FirstSeq,
				FinalSeq:  segment.FinalSeq,
				Count:     segment.Count,
				Boundary:  segment.Boundary,
			})
		}
	}
	return out
}

func resultValue(result wasmResult) js.Value {
	data, err := json.Marshal(result)
	if err != nil {
		data = []byte(`{"valid":false,"error":"marshal result"}`)
	}
	return js.Global().Get("JSON").Call("parse", string(data))
}
