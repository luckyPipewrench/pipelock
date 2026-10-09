// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package recorder

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Boundary between authoritative history and bounded display reads.
//
// A display budget refuses or truncates complete valid evidence once a
// directory, a shard or a session grows past it. That is the right answer
// for a dashboard page and the wrong one for closing a receipt group,
// verifying a chain or anchoring it, where it becomes an outage that only
// more evidence can trigger. These tests keep the two apart.

// displayBudgetNames are the recorder identifiers that carry a display budget:
// the bounded readers and the budgets themselves.
var displayBudgetNames = map[string]bool{
	"MaxEvidenceReadDirectoryEntries":      true,
	"MaxEvidenceReadFileBytes":             true,
	"MaxEvidenceReadEntries":               true,
	"defaultEntryReadLimits":               true,
	"readEvidenceLocationDirectoryEntries": true,
	"ReadEvidenceLocationEntriesBounded":   true,
	"walkBoundedEntriesAtEvidenceLocation": true,
	"readEntriesAtEvidenceLocation":        true,
	"QuerySession":                         true,
	"QuerySessionResolved":                 true,
	"walkSessionResolved":                  true,
	"ListSessions":                         true,
	"ListSessionsBounded":                  true,
	"ListSessionsBoundedResult":            true,
	"ListSessionsBoundedResultResolved":    true,
	"readBoundedEvidence":                  true,
	"ReadEvidenceFileBounded":              true,
	"ReadEvidenceLocationFileBounded":      true,
	"ReadEntries":                          true,
	"ReadEntriesFromReader":                true,
	"WalkEntries":                          true,
	"WalkEntriesFromReader":                true,
	"ReadHeadEntriesBounded":               true,
	"ReadTailEntriesBounded":               true,
}

// authoritativeRoots are the recorder readers that lifecycle code relies on
// to read complete history. Nothing they reach may name a display budget.
var authoritativeRoots = []string{
	"WithSessionHistorySnapshot",
	"WalkHistorySessions",
	"WalkSessionHistory",
	"WalkSessionHistoryResolved",
	"WalkSessionHistoryFiles",
	"WalkHistoryEntriesFromReader",
	"ReadHistoryEntries",
	"ReadHistoryEntriesFromReader",
	"WalkEvidenceFile",
	"WalkEvidenceFileReader",
	"ValidateEvidenceFile",
}

// historyImplementationFile holds the authoritative readers. Method calls are
// followed only to methods declared there, because selector names alone
// cannot tell a recorder method from an os.File or bufio.Reader method.
const historyImplementationFile = "session_history.go"

// packageFunc is one function or method body: the identifiers it names, and
// the package functions and implementation-file methods it calls.
type packageFunc struct {
	names map[string]bool
	calls map[string]bool
}

// parsedPackage parses the package's non-test files. Package functions are
// keyed by name; methods declared in historyImplementationFile by "." + name.
func parsedPackage(t *testing.T, dir string) map[string]*packageFunc {
	t.Helper()
	fset := token.NewFileSet()
	funcs := make(map[string]*packageFunc)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range entries {
		name := de.Name()
		if de.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			key := fn.Name.Name
			if fn.Recv != nil {
				if name != historyImplementationFile {
					continue
				}
				key = "." + key
			}
			f := &packageFunc{names: map[string]bool{}, calls: map[string]bool{}}
			funcs[key] = f
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.Ident:
					f.names[x.Name] = true
				case *ast.SelectorExpr:
					f.names[x.Sel.Name] = true
				case *ast.CallExpr:
					switch fun := x.Fun.(type) {
					case *ast.Ident:
						f.calls[fun.Name] = true
					case *ast.SelectorExpr:
						f.calls["."+fun.Sel.Name] = true
					}
				}
				return true
			})
		}
	}
	return funcs
}

// TestAuthoritativeHistoryReachesNoDisplayBudget walks the recorder package's
// call graph from every authoritative reader and fails if anything reached
// names a display budget or calls a bounded reader.
func TestAuthoritativeHistoryReachesNoDisplayBudget(t *testing.T) {
	funcs := parsedPackage(t, ".")
	for _, root := range authoritativeRoots {
		if funcs[root] == nil {
			t.Fatalf("authoritative reader %s is not defined; update authoritativeRoots", root)
		}
	}
	reached := map[string]string{}
	queue := append([]string(nil), authoritativeRoots...)
	for _, root := range authoritativeRoots {
		reached[root] = root
	}
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		for name := range funcs[fn].names {
			if displayBudgetNames[name] {
				t.Errorf("authoritative reader path %s -> %s names display budget %s", reached[fn], fn, name)
			}
		}
		for callee := range funcs[fn].calls {
			if funcs[callee] != nil && reached[callee] == "" {
				reached[callee] = reached[fn] + " -> " + fn
				queue = append(queue, callee)
			}
		}
	}
	// The walk must actually reach the shared line parser, or it proves
	// nothing about what the readers call.
	for _, want := range []string{"walkHistoryEntries", "walkEntriesFromReader", "openEvidenceLocationFile", "scanHistoryWindow", ".fill", "inspectJSONLRecords"} {
		if reached[want] == "" {
			t.Errorf("call graph did not reach %s; the boundary walk is not following calls", want)
		}
	}
}

// displayBudgetCaller is one place outside the recorder that calls a display
// budget reader or names a budget, with the reason that is not a lifecycle
// read of session history.
type displayBudgetCaller struct {
	file, function, name string
}

// allowedDisplayBudgetCallers is the complete inventory. A new entry needs a
// reason it is not write, lifecycle, verification or anchoring history:
// a dashboard or list display, an operator diagnostic with its own documented
// budget, a stopped offline ceremony, ingress of one artifact with its own
// size contract, or the writer's rotation size.
var allowedDisplayBudgetCallers = map[displayBudgetCaller]string{
	// Dashboard and operator displays: a bounded page, refusing past the budget.
	{"enterprise/dashboard/readmodel.go", "ReceiptDetail", "receipt.ExtractReceiptsFromSessionDirWithLimits"}:          "dashboard read model",
	{"enterprise/dashboard/readmodel.go", "Session", "receipt.ExtractReceiptsFromSessionDirWithLimits"}:                "dashboard read model",
	{"enterprise/dashboard/readmodel.go", "Sessions", "receipt.ExtractReceiptsFromSessionDirWithLimits"}:               "dashboard read model",
	{"enterprise/dashboard/readmodel.go", "Sessions", "recorder.ListSessionsBounded"}:                                  "dashboard read model",
	{"enterprise/dashboard/rebuild.go", "buildReadModelIndex", "recorder.MaxEvidenceReadFileBytes"}:                    "dashboard index rebuild",
	{"enterprise/dashboard/rebuild.go", "buildReadModelIndex", "recorder.ReadEntriesFromReader"}:                       "dashboard index rebuild",
	{"enterprise/dashboard/rebuild.go", "buildReadModelIndex", "recorder.ReadEvidenceFileBounded"}:                     "dashboard index rebuild",
	{"enterprise/dashboard/trustkeys.go", "TrustKeys", "receipt.ExtractReceiptsFromSessionDirBounded"}:                 "dashboard trust-key view",
	{"enterprise/dashboard/trustkeys.go", "TrustKeys", "recorder.ListSessions"}:                                        "dashboard trust-key view",
	{"internal/cli/evidence/evidence.go", "renderSessionHTML", "receipt.ExtractReceiptsFromResolvedSessionDirBounded"}: "evidence view page",
	{"internal/cli/evidence/evidence.go", "resolveServeSessionResolved", "recorder.ListSessionsBoundedResultResolved"}: "evidence serve session list",
	{"internal/cli/evidence/evidence.go", "resolveSession", "recorder.ListSessionsBoundedResultResolved"}:              "evidence view session list",
	{"internal/cli/evidence/doctor.go", "<package scope>", "recorder.MaxEvidenceReadDirectoryEntries"}:                 "evidence doctor diagnostic with its own documented budget",
	{"internal/cli/evidence/doctor.go", "scanJSONL", "recorder.MaxEvidenceReadFileBytes"}:                              "evidence doctor diagnostic with its own documented budget",
	{"internal/cli/evidence/doctor.go", "scanJSONL", "recorder.ReadEntriesFromReader"}:                                 "evidence doctor diagnostic with its own documented budget",
	{"internal/cli/evidence/doctor.go", "scanJSONL", "recorder.ReadEvidenceLocationFileBounded"}:                       "evidence doctor diagnostic with its own documented budget",
	{"internal/cli/runtime/evidence_health.go", "fileStats", "recorder.MaxEvidenceReadDirectoryEntries"}:               "health warning threshold for display readability; refuses nothing",

	// Stopped, operator-invoked offline compaction: separate input and output
	// limits so its output stays readable by the display readers.
	{"internal/cli/evidence/compact.go", "runCompact", "recorder.MaxEvidenceReadDirectoryEntries"}:                        "offline compaction output limit",
	{"internal/cli/evidence/compact_stream.go", "add", "recorder.MaxEvidenceReadDirectoryEntries"}:                        "offline compaction output limit",
	{"internal/cli/evidence/compact_stream.go", "add", "recorder.MaxEvidenceReadFileBytes"}:                               "offline compaction output shard size",
	{"internal/cli/evidence/compact_stream.go", "compactStreamNames", "recorder.ReadEvidenceLocationEntriesBounded"}:      "offline compaction input limit",
	{"internal/cli/evidence/inspect_epochs.go", "inspectEpochSourceNames", "recorder.ReadEvidenceLocationEntriesBounded"}: "offline compaction input inspection",

	// Ingress of one artifact with its own size contract, not session history.
	{"enterprise/conductor/fleetreport/report.go", "Build", "recorder.ReadEntriesFromReader"}:                                                "one fleet sink payload",
	{"internal/cli/evidence/legacy_epoch_inventory.go", "runVerifyLegacyEpochInventory", "recorder.MaxEvidenceReadFileBytes"}:                "operator --inventory file size",
	{"internal/receipt/chain_set.go", "readClaimFile", "recorder.ReadEvidenceFileBounded"}:                                                   "restart-link sidecar with its own size bound",
	{"internal/receipt/group_manifest.go", "PublishReceiptGroupArtifact", "recorder.ReadEvidenceLocationFileBounded"}:                        "published group artifact read back under its own size bound",
	{"internal/receipt/head_stream.go", "load", "recorder.ReadEvidenceFileBounded"}:                                                          "head-stream sidecar with its own size bound",
	{"internal/receipt/group_legacy_index_wasm.go", "indexRecorderFilesExcludingGroupsSpill", "recorder.ReadEvidenceLocationEntriesBounded"}: "browser archive ingress limit, a documented separate boundary",
	{"internal/replaycapture/assemble.go", "writePacketFiles", "recorder.MaxEvidenceReadFileBytes"}:                                          "replay packet artifact size",
	{"internal/replaycapture/assemble.go", "writePacketFiles", "recorder.ReadEvidenceFileBounded"}:                                           "replay packet artifact size",
	{"internal/replaycapture/verify.go", "VerifyPacketBytes", "recorder.MaxEvidenceReadFileBytes"}:                                           "replay packet artifact size",
	{"internal/replaycapture/verify.go", "VerifyPacketDir", "recorder.MaxEvidenceReadFileBytes"}:                                             "replay packet artifact size",
	{"internal/replaycapture/verify.go", "VerifyPacketDir", "recorder.ReadEvidenceFileBounded"}:                                              "replay packet artifact size",

	// The writer's own resume: an informational bounded head window whose
	// truncation leaves chainStart unset and refuses nothing.
	{"internal/receipt/emitter.go", "resumeChain", "recorder.MaxEvidenceReadEntries"}:   "writer resume informational head window",
	{"internal/receipt/emitter.go", "resumeChain", "recorder.MaxEvidenceReadFileBytes"}: "writer resume informational head window",
	{"internal/receipt/emitter.go", "resumeChain", "recorder.ReadHeadEntriesBounded"}:   "writer resume informational head window",

	// The receipt package's display wrappers themselves.
	{"internal/receipt/chain.go", "ExtractReceiptsFromResolvedSessionDirBounded", "extractReceiptsFromResolvedSessionDirWithLimits"}: "display wrapper",
	{"internal/receipt/chain.go", "extractReceiptsFromResolvedSessionDirWithLimits", "recorder.QuerySessionResolved"}:                "display wrapper",
	{"internal/receipt/chain.go", "ExtractReceiptsFromSessionDirBounded", "ExtractReceiptsFromSessionDirWithLimits"}:                 "display wrapper",
	{"internal/receipt/chain.go", "ExtractReceiptsFromSessionDirWithLimits", "recorder.QuerySession"}:                                "display wrapper",

	// Developer tool, not shipped.
	{"tools/gen-shadow-example/main.go", "extractReceipt", "recorder.ReadEntries"}: "example generator",
}

const (
	modulePath      = "github.com/luckyPipewrench/pipelock"
	recorderImport  = modulePath + "/internal/recorder"
	receiptImport   = modulePath + "/internal/receipt"
	receiptPkgDir   = "internal/receipt"
	recorderPkgDir  = "internal/recorder"
	moduleRootLimit = 6
)

// receiptDisplayWrappers are the receipt package's bounded extraction
// wrappers. Verification uses ExtractReceiptsFromSessionDir instead.
var receiptDisplayWrappers = map[string]bool{
	"ExtractReceiptsFromSessionDirBounded":            true,
	"ExtractReceiptsFromSessionDirWithLimits":         true,
	"ExtractReceiptsFromResolvedSessionDirBounded":    true,
	"extractReceiptsFromResolvedSessionDirWithLimits": true,
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for range moduleRootLimit {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		dir = filepath.Dir(dir)
	}
	t.Fatal("module root not found")
	return ""
}

// findDisplayBudgetCallers parses every non-test Go file in the module,
// whatever its build tags, and returns each function that names a recorder
// display budget or a receipt display wrapper.
func findDisplayBudgetCallers(t *testing.T, root string) map[displayBudgetCaller]bool {
	t.Helper()
	found := make(map[displayBudgetCaller]bool)
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "node_modules", ".design-inputs":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		pkgDir := filepath.ToSlash(filepath.Dir(rel))
		if pkgDir == recorderPkgDir {
			return nil // the recorder's own call graph is checked above
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		aliases := map[string]map[string]bool{}
		for _, imp := range file.Imports {
			ipath, _ := strconv.Unquote(imp.Path.Value)
			var names map[string]bool
			switch ipath {
			case recorderImport:
				names = displayBudgetNames
			case receiptImport:
				names = receiptDisplayWrappers
			default:
				continue
			}
			alias := filepath.Base(ipath)
			if imp.Name != nil {
				alias = imp.Name.Name
			}
			aliases[alias] = names
		}
		inReceipt := pkgDir == receiptPkgDir
		if len(aliases) == 0 && !inReceipt {
			return nil
		}
		record := func(function string, body ast.Node) {
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.SelectorExpr:
					if pkg, ok := x.X.(*ast.Ident); ok && aliases[pkg.Name][x.Sel.Name] {
						found[displayBudgetCaller{rel, function, pkg.Name + "." + x.Sel.Name}] = true
					}
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok && inReceipt && receiptDisplayWrappers[id.Name] {
						found[displayBudgetCaller{rel, function, id.Name}] = true
					}
				}
				return true
			})
		}
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body != nil {
					record(d.Name.Name, d.Body)
				}
			case *ast.GenDecl:
				record("<package scope>", d)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return found
}

// TestLifecycleCodeCallsNoDisplayBudget fails when code outside the recorder
// starts calling a bounded display reader or naming a display budget without
// being added, with a reason, to the inventory; and when an inventory entry
// no longer exists, so the inventory stays exactly true.
func TestLifecycleCodeCallsNoDisplayBudget(t *testing.T) {
	found := findDisplayBudgetCallers(t, moduleRoot(t))
	var unexpected, stale []string
	for c := range found {
		if _, ok := allowedDisplayBudgetCallers[c]; !ok {
			unexpected = append(unexpected, c.file+" "+c.function+" -> "+c.name)
		}
	}
	for c := range allowedDisplayBudgetCallers {
		if !found[c] {
			stale = append(stale, c.file+" "+c.function+" -> "+c.name)
		}
	}
	sort.Strings(unexpected)
	sort.Strings(stale)
	for _, u := range unexpected {
		t.Errorf("unclassified display-budget call: %s\n\tA write, lifecycle, verification or anchoring path must use recorder.WalkSessionHistory or the other authoritative readers. A display path must be added to allowedDisplayBudgetCallers with its reason.", u)
	}
	for _, s := range stale {
		t.Errorf("allowedDisplayBudgetCallers lists a call that no longer exists: %s", s)
	}
}
