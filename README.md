# Sys Tools Plugin for AgentUp

<p align="center">
  <img src="static/logo.png" alt="SYS Tools Plugin" width="400"/>
</p>

This plugin provides safe, controlled access to system operations including file I/O, directory management, and system information retrieval.

If you need any more tool calls or functionality, please create an issue in the repository
or go ahead and implement it yourself!

## Configuration

Add the plugin to your agent's `agentup.yml`. The plugin supports flexible configuration including the ability to unban specific commands from the security denylist:

```yaml
plugins:
  agentup_systools:
    capabilities:
      - capability_id: file_read
        enabled: true
        required_scopes: ["files:read"]
      - capability_id: file_write
        enabled: true
        required_scopes: ["files:write"]
      - capability_id: file_exists
        enabled: true
        required_scopes: ["files:read"]
      - capability_id: file_info
        enabled: true
        required_scopes: ["files:read"]
      - capability_id: list_directory
        enabled: true
        required_scopes: ["files:read"]
      - capability_id: create_directory
        enabled: true
        required_scopes: ["files:write"]
      - capability_id: delete_file
        enabled: true
        required_scopes: ["files:admin"]
      - capability_id: system_info
        enabled: true
        required_scopes: ["system:read"]
      - capability_id: working_directory
        enabled: true
        required_scopes: ["system:read"]
      - capability_id: execute_command
        enabled: true
        required_scopes: ["system:admin"]
      - capability_id: file_hash
        enabled: true
        required_scopes: ["files:read"]
    config:
      # Optional: Restrict operations to specific directory (defaults to cwd)
      workspace_dir: "./workspace"
      # Optional: Maximum file size in bytes (default 10MB)
      max_file_size: 10485760
      # Optional: Commands to remove from the banned list (unban)
      # By default, dangerous commands are banned for security
      # Only unban commands you trust and need
      unbanned_commands:
        - "eval"
        - "exec"
        - "cpio"
```

### Configuration

#### Command Security Configuration

The plugin uses a security-first approach with a comprehensive list of banned commands that are not
accessible to `execute_command`. Most common safe commands (ls, cat, echo, grep, etc.) work by default. You can selectively unban specific commands if needed:

```yaml
plugins:
  agentup_systools:
    config:
      unbanned_commands:
        - "eval"
        - "exec"
        - "cpio"
```

Main commands such as `list_directory`, `create_directory`, and `delete_file` are subject to high security scrutiny (e.g. path traversal protection).


**Important Notes:**
- Commands NOT in the banned list work by default (ls, cat, echo, grep, find, etc.)
- `unbanned_commands` removes specific commands from the banned list
- The plugin will warn about unbanning dangerous commands
- Be extremely careful when unbanning system-critical commands
- Commands are executed with the same permissions as the AgentUp process

## Tool Capabilities

### File Operations
- **Read File** - Read text file contents with size limits and encoding support
- **Write File** - Write content to files with atomic operations and parent directory creation
- **Check File Exists** - Verify if a file or directory exists
- **Get File Info** - Retrieve detailed metadata about files and directories
- **Get File Hash** - Compute cryptographic hashes (MD5, SHA1, SHA256, SHA512) with hex/base64 output

### Directory Operations
- **List Directory** - List directory contents with pattern matching and recursive options
- **Create Directory** - Create directories with parent creation support
- **Delete File/Directory** - Safely delete files and directories with recursive option

### System Operations
- **Get System Info** - Retrieve platform, architecture, and environment information
- **Get Working Directory** - Get current working directory path
- **Execute Command** - Execute whitelisted shell commands with timeout support

### Security and Validation
- Path validation and basic sandboxing to prevent directory traversal
- Configurable workspace restriction
- File size limits (default 10MB)
- Command whitelist for safe execution
- Input sanitization and validation

## Installation

### For Development
```bash
cd system-tools
pip install -e .
```

### From AgentUp Registry or PyPi (when published)
```bash
pip install --extra-index-url https://api.agentup.dev/simple agentup-system-tools
```

## Usage Examples

### Natural Language Usage

The plugin responds to natural language requests:

```
"Read the contents of config.json"
"List all Python files in the src directory"
"Create a new folder called outputs"
"What operating system am I running on?"
"Calculate the SHA256 hash of package.json"
"Get MD5 and SHA1 hashes for data.bin"
"Run ls -la to list files"                  # Works by default (not banned)
"Execute git status to check repository"     # Blocked by default (git is banned, unban if needed)
"Run curl to fetch data from API"           # Blocked by default (curl is banned, unban if needed)
```

## Security Considerations

### Path Security
- All paths are validated to prevent directory traversal attacks
- Operations are restricted to the configured workspace directory
- Symbolic links are detected and reported
- Absolute paths are only allowed when explicitly configured

### Command Execution
- Uses a denylist approach - dangerous commands are banned by default
- **Commands that work by default** (not in banned list):
  - File viewing: `ls`, `cat`, `head`, `tail`, `wc`, `more`, `less`
  - System info: `pwd`, `whoami`, `date`, `uname`, `hostname`, `id`
  - Search: `grep`, `find`, `which`, `locate`, `awk`
  - Environment: `env`, `printenv`, `echo`, `printf`
  - System status: `df`, `du`, `free`, `uptime`, `ps`, `top`
  - Text processing: `sed`, `cut`, `sort`, `uniq`, `tr`
  - Development: `make`, `npm`, `yarn`, `pip`, `python`, `node`, `java`
- **Banned by default** (can be unbanned via config):
  - Network: `curl`, `wget`, `nc`, `ssh`, `scp`, `ftp`
  - System control: `shutdown`, `reboot`, `systemctl`, `service`
  - Dangerous: `dd`, `mkfs`, `fdisk`, `sudo`, `su`, `chmod`
  - Version control: `git` (unban if needed for your workflow)
- **Configuration**: Use `unbanned_commands` to selectively allow banned commands
- Commands are parsed to prevent injection attacks
- Execution timeout prevents hanging processes

### File Size Limits
- Default 10MB limit for file operations
- Configurable via `max_file_size` setting
- Large files are truncated with notification

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## Support

For issues, questions, or contributions:
- Create an issue in the repository
- Refer to AgentUp documentation for plugin development
