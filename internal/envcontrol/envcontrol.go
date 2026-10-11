// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Package envcontrol names the environment variables that make a dynamic
// loader or a language runtime load or run code chosen by the variable's value.
//
// It is the one list behind every Pipelock surface that refuses such a
// variable: the MCP proxy and the sandbox refuse them in --env, and a verified
// local MCP service may not carry them unless its registration pins the value.
// Keeping one list means a variable added for one surface is refused by all.
package envcontrol

import "sort"

// codeLoading names variables whose value selects code for a loader or a
// runtime to load or run.
var codeLoading = []string{
	// glibc dynamic loader and runtime module loading. LD_ORIGIN_PATH redirects
	// $ORIGIN library lookup; GCONV_PATH makes iconv load charset modules from a
	// chosen directory.
	"GCONV_PATH", "LD_AUDIT", "LD_LIBRARY_PATH", "LD_ORIGIN_PATH", "LD_PRELOAD",
	// Node.js, Bun and Electron-as-Node. ELECTRON_RUN_AS_NODE turns an Electron
	// application into a Node interpreter for its arguments.
	"BUN_OPTIONS", "ELECTRON_EXTRA_LAUNCH_ARGS", "ELECTRON_RUN_AS_NODE",
	"NODE_OPTIONS", "NODE_PATH",
	// Python. PYTHONBREAKPOINT imports the callable it names, PYTHONINSPECT runs
	// standard input as code once the script ends, and PYTHONPYCACHEPREFIX moves
	// the bytecode the interpreter loads.
	"PYTHONBREAKPOINT", "PYTHONHOME", "PYTHONINSPECT", "PYTHONPATH",
	"PYTHONPYCACHEPREFIX", "PYTHONSTARTUP", "PYTHONUSERBASE",
	// JVM.
	"CLASSPATH", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS",
	// Ruby, Perl, Lua, PHP.
	"LUA_CPATH", "LUA_INIT", "LUA_PATH", "PERL5LIB", "PERL5OPT", "PERLLIB",
	"PHPRC", "PHP_INI_SCAN_DIR", "RUBYLIB", "RUBYOPT",
	// .NET.
	"CORECLR_ENABLE_PROFILING", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH",
	"DOTNET_ADDITIONAL_DEPS", "DOTNET_SHARED_STORE", "DOTNET_STARTUP_HOOKS",
	// POSIX shells started for scripts.
	"BASH_ENV", "ENV",
}

var codeLoadingSet = func() map[string]struct{} {
	set := make(map[string]struct{}, len(codeLoading))
	for _, name := range codeLoading {
		set[name] = struct{}{}
	}
	return set
}()

// CodeLoadingNames returns the sorted names of the loader and runtime variables
// that load or run code chosen by their value. The list covers the glibc
// loader, Node.js, Bun, Electron, Python, the JVM, Ruby, Perl, Lua, PHP, .NET
// and shell startup files. It is a floor, not a complete inventory of every
// runtime.
func CodeLoadingNames() []string {
	out := make([]string, len(codeLoading))
	copy(out, codeLoading)
	sort.Strings(out)
	return out
}

// IsCodeLoading reports whether name is one of CodeLoadingNames. The match is
// exact: the loaders and runtimes listed read these names case-sensitively.
func IsCodeLoading(name string) bool {
	_, ok := codeLoadingSet[name]
	return ok
}
