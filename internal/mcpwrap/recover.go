// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package mcpwrap

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// WrapperTransport identifies the transport of a child recovered from a proxy
// invocation.
type WrapperTransport int

const (
	// TransportStdio is a subprocess child, recovered from the `--` tail.
	TransportStdio WrapperTransport = iota
	// TransportUpstream is a remote child, recovered from `--upstream URL`.
	TransportUpstream
)

// Proxy subcommand tokens and the argument-list flags a wrapper argv can carry.
// These are exactly the flags pipelock's own installers emit; anything else in a
// proxy invocation is unrecognized and forces a refusal rather than a guess.
const (
	subcmdMCP     = "mcp"
	subcmdProxy   = "proxy"
	argSeparator  = "--"
	flagWorkspace = "--workspace"
	flagEnv       = "--env"
	flagSandbox   = "--sandbox"
)

// RecoveredInner is the child a `pipelock mcp proxy` invocation wraps, read from
// the invocation arguments alone. It deliberately carries no recovered proxy
// flags: --config, --sandbox, --workspace and --env belong to the pipelock that
// wrote the wrapper and are rebuilt fresh by the installer performing the
// re-wrap, so the normalized result is mediated by the CURRENT executable rather
// than inheriting a foreign binary's flags.
type RecoveredInner struct {
	Transport   WrapperTransport
	Command     string   // TransportStdio: the child binary
	Args        []string // TransportStdio: the child arguments
	UpstreamURL string   // TransportUpstream: the remote upstream URL
}

// ErrNotProxyInvocation reports that the arguments are not an `mcp proxy`
// invocation, so there is no wrapper to normalize. Callers distinguish this from
// a refusal: it means "leave the entry as-is", not "refuse the entry".
var ErrNotProxyInvocation = errors.New("mcpwrap: not an mcp proxy invocation")

// ErrCannotNormalize identifies a wrapper the installer cannot safely replace.
var ErrCannotNormalize = errors.New("cannot normalize wrapper")

// RecoverServerInvocation refuses header settings whose use cannot be established
// from the proxy invocation, then recovers the original server from its arguments.
func RecoverServerInvocation(server map[string]interface{}, proxyArgs []string) (RecoveredInner, error) {
	if headers, present := server[FieldHeaders]; present && headers != nil {
		empty := false
		switch h := headers.(type) {
		case map[string]interface{}:
			empty = len(h) == 0
		case map[string]string:
			empty = len(h) == 0
		}
		if !empty {
			return RecoveredInner{}, refusef("wrapper has header settings outside its invocation; restore the original server configuration before installing again")
		}
	}
	return RecoverInner(proxyArgs)
}

// RecoverInner extracts the child that a `mcp proxy` invocation wraps, reading
// only the invocation arguments and never the _pipelock restoration marker (a
// config-controlled value that must not authorize anything).
//
// proxyArgs is the argument list that FOLLOWS the wrapping binary, e.g.
// ["mcp","proxy","--config","p","--","srv","-x"] or
// ["mcp","proxy","--upstream","https://h/mcp"].
//
// It fails closed. Arguments that are not the recognized wrapper flags, a
// wrapper that carries both a `--` child and `--upstream`, an empty child, or a
// `--header-file` credential sidecar (whose contents cannot be reconstructed
// from the command) all return an error carrying an operator remedy. Returning
// ErrNotProxyInvocation means the args are simply not a proxy invocation.
func RecoverInner(proxyArgs []string) (RecoveredInner, error) {
	if len(proxyArgs) < 2 || proxyArgs[0] != subcmdMCP || proxyArgs[1] != subcmdProxy {
		return RecoveredInner{}, ErrNotProxyInvocation
	}

	haveUpstream := false
	var upstream string

	for i := 2; i < len(proxyArgs); i++ {
		arg := proxyArgs[i]
		switch arg {
		case argSeparator:
			if haveUpstream {
				return RecoveredInner{}, refusef("wrapper mixes --upstream and a `--` child command; remove the server and re-add it so pipelock can wrap it freshly")
			}
			tail := proxyArgs[i+1:]
			if len(tail) == 0 || tail[0] == "" {
				return RecoveredInner{}, refusef("wrapper has no child command after `--`; remove the server and re-add the original")
			}
			if len(tail) >= 3 && tail[1] == subcmdMCP && tail[2] == subcmdProxy {
				return RecoveredInner{}, refusef("wrapper contains another proxy invocation; restore the original server configuration before installing again")
			}
			return RecoveredInner{
				Transport: TransportStdio,
				Command:   tail[0],
				Args:      append([]string(nil), tail[1:]...),
			}, nil
		case flagUpstream:
			if haveUpstream {
				return RecoveredInner{}, refusef("wrapper repeats --upstream; restore the original server configuration before installing again")
			}
			value, ok := valueAt(proxyArgs, i+1)
			if !ok {
				return RecoveredInner{}, refusef("wrapper has --upstream with no URL; remove the server and re-add the original")
			}
			upstream = value
			haveUpstream = true
			i++
		case flagConfig, flagWorkspace, flagEnv:
			// Recognized value flag from the wrapping pipelock; the value is
			// rebuilt fresh by the re-wrap, so it is consumed and discarded.
			if value, ok := valueAt(proxyArgs, i+1); !ok || value == "" || strings.HasPrefix(value, "-") {
				return RecoveredInner{}, refusef("wrapper flag %q has no value; remove the server and re-add the original", arg)
			}
			i++
		case flagSandbox:
			// Recognized bool flag; rebuilt fresh by the re-wrap.
		case flagHeaderFile:
			return RecoveredInner{}, refusef(
				"wrapper stores upstream credentials in a header sidecar file that cannot be recovered " +
					"from the command alone; run the installer's remove then install again, or re-add the server by hand")
		default:
			return RecoveredInner{}, refusef(
				"wrapper carries a proxy argument that this pipelock does not recognize; restore the original server configuration before installing again")
		}
	}

	if haveUpstream {
		if upstream == "" {
			return RecoveredInner{}, refusef("wrapper has an empty --upstream URL; remove the server and re-add the original")
		}
		// Match the upstream scheme/host contract in the MCP command.
		u, err := url.Parse(upstream)
		if err != nil || u.Host == "" {
			return RecoveredInner{}, refusef("wrapper has an invalid --upstream URL; restore the original server configuration before installing again")
		}
		switch u.Scheme {
		case "http", "https", "ws", "wss":
		default:
			return RecoveredInner{}, refusef("wrapper has an unsupported --upstream URL scheme; restore the original server configuration before installing again")
		}
		return RecoveredInner{Transport: TransportUpstream, UpstreamURL: upstream}, nil
	}
	return RecoveredInner{}, refusef("wrapper has no child command or upstream; remove the server and re-add the original")
}

// valueAt returns the argument at i and whether the index is in range, so a
// flag's value is read only after a bounds check the analyzer can see.
func valueAt(args []string, i int) (string, bool) {
	if i < 0 || i >= len(args) {
		return "", false
	}
	return args[i], true
}

// refusef builds an unrecoverable-wrapper error. It is distinct from
// ErrNotProxyInvocation: a refusal is an availability failure with a remedy, not
// an instruction to leave the entry alone.
func refusef(format string, args ...interface{}) error {
	return fmt.Errorf("%w: %s", ErrCannotNormalize, fmt.Sprintf(format, args...))
}

// recoverForeignServer adapts a conventional command/args entry for WrapServer.
// The invocation supplies the child; restoration metadata is discarded.
func recoverForeignServer(server map[string]interface{}) (map[string]interface{}, error) {
	if ClassifyServer(server) != WrapperForeign {
		return server, nil
	}
	args, err := stringArgs(server[FieldArgs])
	if err != nil {
		return nil, err
	}
	if _, scalar := server[FieldCommand].(string); !scalar {
		if len(args) > 0 {
			return nil, refusef("command-list wrapper also has a separate args field; restore the original server configuration before installing again")
		}
		command, err := stringArgs(server[FieldCommand])
		if err != nil || len(command) < 2 {
			return nil, refusef("wrapper has an invalid command list; restore the original server configuration before installing again")
		}
		args = command[1:]
	}
	inner, err := RecoverServerInvocation(server, args)
	if err != nil {
		return nil, err
	}
	bare := make(map[string]interface{}, len(server))
	for k, v := range server {
		switch k {
		case FieldCommand, FieldArgs, FieldURL, FieldHeaders, FieldType, FieldPipelock:
		default:
			bare[k] = v
		}
	}
	if inner.Transport == TransportUpstream {
		bare[FieldURL] = inner.UpstreamURL
	} else {
		bare[FieldCommand] = inner.Command
		bare[FieldArgs] = inner.Args
	}
	return bare, nil
}
