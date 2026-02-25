package chains

import (
	"testing"

	"github.com/luckyPipewrench/pipelock/internal/config"
)

func TestClassifyTool(t *testing.T) { //nolint:goconst // test value
	cfg := &config.ToolChainDetection{}
	tests := []struct {
		name     string
		tool     string
		expected string
	}{
		{"read keyword", "read_file", "read"},                              //nolint:goconst // test value
		{"get keyword", "get_contents", "read"},                            //nolint:goconst // test value
		{"view keyword", "view_page", "read"},                              //nolint:goconst // test value
		{"cat keyword", "cat_file", "read"},                                //nolint:goconst // test value
		{"write keyword", "write_file", "write"},                           //nolint:goconst // test value
		{"create keyword", "create_document", "write"},                     //nolint:goconst // test value
		{"save keyword", "save_changes", "write"},                          //nolint:goconst // test value
		{"update keyword", "update_record", "write"},                       //nolint:goconst // test value
		{"edit keyword", "edit_file", "write"},                             //nolint:goconst // test value
		{"exec shell", "shell_command", "exec"},                            //nolint:goconst // test value
		{"exec bash", "bash_exec", "exec"},                                 //nolint:goconst // test value
		{"exec run", "run_command", "exec"},                                //nolint:goconst // test value
		{"exec execute", "execute_script", "exec"},                         //nolint:goconst // test value
		{"network fetch", "fetch_url", "network"},                          //nolint:goconst // test value
		{"network curl", "curl_request", "network"},                        //nolint:goconst // test value
		{"network http", "http_get", "network"},                            //nolint:goconst // test value
		{"network send", "send_message", "network"},                        //nolint:goconst // test value
		{"list keyword", "list_files", "list"},                             //nolint:goconst // test value
		{"list ls", "ls_directory", "list"},                                //nolint:goconst // test value
		{"list dir", "dir_contents", "list"},                               //nolint:goconst // test value
		{"list find", "find_files", "list"},                                //nolint:goconst // test value
		{"env keyword", "env_get", "env"},                                  //nolint:goconst // test value
		{"env environ", "environ_list", "env"},                             //nolint:goconst // test value
		{"env secret", "secret_store", "env"},                              //nolint:goconst // test value
		{"env credential", "credential_fetch", "env"},                      //nolint:goconst // test value
		{"env token", "token_refresh", "env"},                              //nolint:goconst // test value
		{"env password", "password_manager", "env"},                        //nolint:goconst // test value
		{"MCP namespaced tool", "mcp__filesystem__read_file", "read"},      //nolint:goconst // test value
		{"MCP namespaced exec", "mcp__shell__bash_exec", "exec"},           //nolint:goconst // test value
		{"MCP namespaced list", "mcp__filesystem__list_directory", "list"}, //nolint:goconst // test value
		{"MCP namespaced network", "mcp__network__fetch_url", "network"},   //nolint:goconst // test value
		{"dot separator", "file.read", "read"},                             //nolint:goconst // test value
		{"hyphen separator", "file-read", "read"},                          //nolint:goconst // test value
		{"no match returns unknown", "foobar_baz", "unknown"},              //nolint:goconst // test value
		{"empty tool name", "", "unknown"},                                 //nolint:goconst // test value
		{"single segment match", "read", "read"},                           //nolint:goconst // test value
		{"single segment exec", "bash", "exec"},                            //nolint:goconst // test value
		{"append keyword write", "append_data", "write"},                   //nolint:goconst // test value
		{"insert keyword write", "insert_record", "write"},                 //nolint:goconst // test value
		{"download keyword network", "download_file", "network"},           //nolint:goconst // test value
		{"upload keyword network", "upload_data", "network"},               //nolint:goconst // test value
		{"scan keyword list", "scan_directory", "list"},                    //nolint:goconst // test value
		{"enumerate keyword list", "enumerate_resources", "list"},          //nolint:goconst // test value
		{"walk keyword list", "walk_tree", "list"},                         //nolint:goconst // test value
		{"getenv keyword env", "getenv_value", "env"},                      //nolint:goconst // test value
		{"config keyword env", "config_read", "env"},                       //nolint:goconst // test value
		{"key keyword env", "key_rotate", "env"},                           //nolint:goconst // test value
		{"spawn keyword exec", "spawn_process", "exec"},                    //nolint:goconst // test value
		{"eval keyword exec", "eval_expression", "exec"},                   //nolint:goconst // test value
		{"powershell keyword exec", "powershell_command", "exec"},          //nolint:goconst // test value
		{"api keyword network", "api_call", "network"},                     //nolint:goconst // test value
		{"post keyword network", "post_request", "network"},                //nolint:goconst // test value
		{"open keyword read", "open_file", "read"},                         //nolint:goconst // test value
		{"load keyword read", "load_data", "read"},                         //nolint:goconst // test value
		{"retrieve keyword read", "retrieve_record", "read"},               //nolint:goconst // test value
		{"access keyword read", "access_resource", "read"},                 //nolint:goconst // test value
		{"head keyword read", "head_file", "read"},                         //nolint:goconst // test value
		{"tail keyword read", "tail_log", "read"},                          //nolint:goconst // test value
		{"glob keyword list", "glob_files", "list"},                        //nolint:goconst // test value
		{"search keyword list", "search_codebase", "list"},                 //nolint:goconst // test value
		{"sh keyword exec", "sh_run", "exec"},                              //nolint:goconst // test value
		{"zsh keyword exec", "zsh_command", "exec"},                        //nolint:goconst // test value
		{"cmd keyword exec", "cmd_execute", "exec"},                        //nolint:goconst // test value
		{"wget keyword network", "wget_download", "network"},               //nolint:goconst // test value
		{"request keyword network", "request_handler", "network"},          //nolint:goconst // test value
		{"put keyword write", "put_object", "write"},                       //nolint:goconst // test value
		{"modify keyword write", "modify_entry", "write"},                  //nolint:goconst // test value
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
			"exec":    {"my_custom_runner"},                  //nolint:goconst // test value
			"network": {"special_*"},                         //nolint:goconst // test value
			"env":     {"vault_*", "secret_store_retrieval"}, //nolint:goconst // test value
		},
	}

	tests := []struct {
		name     string
		tool     string
		expected string
	}{
		{"exact match override", "my_custom_runner", "exec"},               //nolint:goconst // test value
		{"glob match override", "special_fetch", "network"},                //nolint:goconst // test value
		{"glob match override 2", "special_upload", "network"},             //nolint:goconst // test value
		{"exact override before keyword", "secret_store_retrieval", "env"}, //nolint:goconst // test value
		{"glob vault", "vault_read", "env"},                                //nolint:goconst // test value
		{"not matching glob", "my_special_thing", "unknown"},               //nolint:goconst // test value
		{"keyword fallback when no override", "read_file", "read"},         //nolint:goconst // test value
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
		{"exec over read", "run_read", "exec"},      //nolint:goconst // test value
		{"exec over env", "execute_env", "exec"},    //nolint:goconst // test value
		{"exec over network", "bash_fetch", "exec"}, //nolint:goconst // test value
		{"exec over write", "run_write", "exec"},    //nolint:goconst // test value
		{"exec over list", "shell_list", "exec"},    //nolint:goconst // test value
		// env wins over network, write, read, list
		{"env over read", "secret_read", "env"},    //nolint:goconst // test value
		{"env over network", "token_fetch", "env"}, //nolint:goconst // test value
		{"env over write", "env_write", "env"},     //nolint:goconst // test value
		// network wins over write, read, list
		{"network over write", "send_write", "network"}, //nolint:goconst // test value
		{"network over read", "curl_read", "network"},   //nolint:goconst // test value
		// write wins over read, list
		{"write over read", "create_read", "write"}, //nolint:goconst // test value
		{"write over list", "save_list", "write"},   //nolint:goconst // test value
		// read wins over list
		{"read over list", "get_list", "read"}, //nolint:goconst // test value
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
		{"no keywords", "foobar"},      //nolint:goconst // test value
		{"numbers only", "12345"},      //nolint:goconst // test value
		{"random text", "xyzzy_plugh"}, //nolint:goconst // test value
		{"empty string", ""},           //nolint:goconst // test value
		{"single letter", "a"},         //nolint:goconst // test value
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyTool(tt.tool, cfg)
			if got != "unknown" { //nolint:goconst // test value
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
		{"underscore delimiter", "read_file", "read"},          //nolint:goconst // test value
		{"hyphen delimiter", "read-file", "read"},              //nolint:goconst // test value
		{"dot delimiter", "file.read", "read"},                 //nolint:goconst // test value
		{"double underscore", "mcp__filesystem__read", "read"}, //nolint:goconst // test value
		{"mixed delimiters", "mcp__file.read-data", "read"},    //nolint:goconst // test value
		{"leading delimiter", "_read_file", "read"},            //nolint:goconst // test value
		{"trailing delimiter", "read_file_", "read"},           //nolint:goconst // test value
		{"multiple consecutive", "mcp____read", "read"},        //nolint:goconst // test value
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
