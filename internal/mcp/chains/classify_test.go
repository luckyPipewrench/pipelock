package chains

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestClassifyTool(t *testing.T) {
	cfg := &config.ToolChainDetection{}
	tests := []struct {
		name     string
		tool     string
		expected string
	}{
		{"read keyword", "read_file", "read"},
		{"get keyword", "get_contents", "read"},
		{"view keyword", "view_page", "read"},
		{"cat keyword", "cat_file", "read"},
		{"write keyword", "write_file", "write"},
		{"create keyword", "create_document", "write"},
		{"save keyword", "save_changes", "write"},
		{"update keyword", "update_record", "write"},
		{"edit keyword", "edit_file", "write"},
		{"exec shell", "shell_command", "exec"},
		{"exec bash", "bash_exec", "exec"},
		{"exec run", "run_command", "exec"},
		{"exec execute", "execute_script", "exec"},
		{"network fetch", "fetch_url", "network"},
		{"network curl", "curl_request", "network"},
		{"network http", "http_get", "network"},
		{"network send", "send_message", "network"},
		{"list keyword", "list_files", "list"},
		{"list ls", "ls_directory", "list"},
		{"list dir", "dir_contents", "list"},
		{"list find", "find_files", "list"},
		{"env keyword", "env_get", "env"},
		{"env environ", "environ_list", "env"},
		{"env secret", "secret_store", "env"},
		{"env credential", "credential_fetch", "env"},
		{"env token", "token_refresh", "env"},
		{"env password", "password_manager", "env"},
		{"MCP namespaced tool", "mcp__filesystem__read_file", "read"},
		{"MCP namespaced exec", "mcp__shell__bash_exec", "exec"},
		{"MCP namespaced list", "mcp__filesystem__list_directory", "list"},
		{"MCP namespaced network", "mcp__network__fetch_url", "network"},
		{"dot separator", "file.read", "read"},
		{"hyphen separator", "file-read", "read"},
		{"no match returns unknown", "foobar_baz", "unknown"},
		{"empty tool name", "", "unknown"},
		{"single segment match", "read", "read"},
		{"single segment exec", "bash", "exec"},
		{"append keyword write", "append_data", "write"},
		{"insert keyword write", "insert_record", "write"},
		{"download keyword network", "download_file", "network"},
		{"upload keyword network", "upload_data", "network"},
		{"scan keyword list", "scan_directory", "list"},
		{"enumerate keyword list", "enumerate_resources", "list"},
		{"walk keyword list", "walk_tree", "list"},
		{"getenv keyword env", "getenv_value", "env"},
		{"config keyword env", "config_read", "env"},
		{"key keyword env", "key_rotate", "env"},
		{"spawn keyword exec", "spawn_process", "exec"},
		{"eval keyword exec", "eval_expression", "exec"},
		{"powershell keyword exec", "powershell_command", "exec"},
		{"api keyword network", "api_call", "network"},
		{"post keyword network", "post_request", "network"},
		{"open keyword read", "open_file", "read"},
		{"load keyword read", "load_data", "read"},
		{"retrieve keyword read", "retrieve_record", "read"},
		{"access keyword read", "access_resource", "read"},
		{"head keyword read", "head_file", "read"},
		{"tail keyword read", "tail_log", "read"},
		{"glob keyword list", "glob_files", "list"},
		{"search keyword list", "search_codebase", "list"},
		{"sh keyword exec", "sh_run", "exec"},
		{"zsh keyword exec", "zsh_command", "exec"},
		{"cmd keyword exec", "cmd_execute", "exec"},
		{"wget keyword network", "wget_download", "network"},
		{"request keyword network", "request_handler", "network"},
		{"put keyword write", "put_object", "write"},
		{"modify keyword write", "modify_entry", "write"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTool(tt.tool, cfg)
			if got != tt.expected {
				t.Errorf("classifyTool(%q) = %q, want %q", tt.tool, got, tt.expected)
			}
		})
	}
}

func TestClassifyTool_Overrides(t *testing.T) {
	cfg := &config.ToolChainDetection{
		ToolCategories: map[string][]string{
			"exec":    {"my_custom_runner"},
			"network": {"special_*"},
			"env":     {"vault_*", "secret_store_retrieval"},
		},
	}

	tests := []struct {
		name     string
		tool     string
		expected string
	}{
		{"exact match override", "my_custom_runner", "exec"},
		{"glob match override", "special_fetch", "network"},
		{"glob match override 2", "special_upload", "network"},
		{"exact override before keyword", "secret_store_retrieval", "env"},
		{"glob vault", "vault_read", "env"},
		{"not matching glob", "my_special_thing", "unknown"},
		{"keyword fallback when no override", "read_file", "read"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTool(tt.tool, cfg)
			if got != tt.expected {
				t.Errorf("classifyTool(%q) = %q, want %q", tt.tool, got, tt.expected)
			}
		})
	}
}

func TestClassifyTool_Priority(t *testing.T) {
	cfg := &config.ToolChainDetection{}

	// Priority: exec > env > network > write > read > list
	tests := []struct {
		name     string
		tool     string
		expected string
	}{
		// exec wins over everything
		{"exec over read", "run_read", "exec"},
		{"exec over env", "execute_env", "exec"},
		{"exec over network", "bash_fetch", "exec"},
		{"exec over write", "run_write", "exec"},
		{"exec over list", "shell_list", "exec"},
		// env wins over network, write, read, list
		{"env over read", "secret_read", "env"},
		{"env over network", "token_fetch", "env"},
		{"env over write", "env_write", "env"},
		// network wins over write, read, list
		{"network over write", "send_write", "network"},
		{"network over read", "curl_read", "network"},
		// write wins over read, list
		{"write over read", "create_read", "write"},
		{"write over list", "save_list", "write"},
		// read wins over list
		{"read over list", "get_list", "read"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTool(tt.tool, cfg)
			if got != tt.expected {
				t.Errorf("classifyTool(%q) = %q, want %q", tt.tool, got, tt.expected)
			}
		})
	}
}

func TestClassifyTool_Unknown(t *testing.T) {
	cfg := &config.ToolChainDetection{}

	tests := []struct {
		name string
		tool string
	}{
		{"no keywords", "foobar"},
		{"numbers only", "12345"},
		{"random text", "xyzzy_plugh"},
		{"empty string", ""},
		{"single letter", "a"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTool(tt.tool, cfg)
			if got != "unknown" {
				t.Errorf("classifyTool(%q) = %q, want %q", tt.tool, got, "unknown")
			}
		})
	}
}

func TestClassifyTool_Delimiters(t *testing.T) {
	cfg := &config.ToolChainDetection{}

	tests := []struct {
		name     string
		tool     string
		expected string
	}{
		{"underscore delimiter", "read_file", "read"},
		{"hyphen delimiter", "read-file", "read"},
		{"dot delimiter", "file.read", "read"},
		{"double underscore", "mcp__filesystem__read", "read"},
		{"mixed delimiters", "mcp__file.read-data", "read"},
		{"leading delimiter", "_read_file", "read"},
		{"trailing delimiter", "read_file_", "read"},
		{"multiple consecutive", "mcp____read", "read"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTool(tt.tool, cfg)
			if got != tt.expected {
				t.Errorf("classifyTool(%q) = %q, want %q", tt.tool, got, tt.expected)
			}
		})
	}
}
