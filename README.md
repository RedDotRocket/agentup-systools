# Sys Tools Plugin for AgentUp

<p align="center">
  <img src="static/logo.png" alt="SYS Tools Plugin" width="400"/>
</p>

This plugin provides safe, controlled access to system operations including file I/O, directory management, and system information retrieval.

If you need any more tool calls or functionality, please create an issue in the repository
or go ahead and implement it yourself!

## Configuration

Add the plugin to your agent's `agentup.yml`. The plugin supports flexible configuration including custom command allow-lists to add your own tools:

```yaml
plugins:
  - plugin_id: sys_tools
    name: System Tools
    description: System tools for basic operations
    input_mode: text
    output_mode: texti
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
      # Optional: Custom list of allowed commands for execution
      # If not specified, uses secure defaults
      allowed_commands:
        - "ls"
        - "pwd"
        - "docker"
        - "kubectl"
        - "git"
        - "npm"
        - "pip"
        - "python"
        - "my_custom_script"
```

### Advanced Configuration

#### Custom Command Whitelist

By default, the plugin includes a secure set of commonly-used commands. You can customize this list to include your own tools and scripts:

```yaml
plugins:
  agentup_systools:
    config:
      allowed_commands:
        # Development tools
        - "git"
        - "npm"
        - "pip"
        - "python"
        - "node"
        
        # Container/orchestration tools  
        - "docker"
        - "kubectl"
        - "helm"
        
        # Custom scripts and tools
        - "my_deployment_script"
        - "custom_analyzer"
        
        # Basic system commands
        - "ls"
        - "pwd"
        - "cat"
```

**Important Notes:**
- When you specify `allowed_commands`, it completely replaces the default list
- Always include basic commands like `ls`, `pwd`, `cat` if you need them
- The plugin will validate your configuration and warn about potentially dangerous commands
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
"Run docker ps to show running containers"  # (if docker is in allowed_commands)
"Execute git status to check repository"     # (if git is in allowed_commands)
"Run my_custom_script with --help flag"     # (if my_custom_script is in allowed_commands)
```

## Security Considerations

### Path Security
- All paths are validated to prevent directory traversal attacks
- Operations are restricted to the configured workspace directory
- Symbolic links are detected and reported
- Absolute paths are only allowed when explicitly configured

### Command Execution
- Only whitelisted commands can be executed
- **Default allowed commands**:
  - File viewing: `ls`, `cat`, `head`, `tail`, `wc`
  - System info: `pwd`, `whoami`, `date`, `uname`, `hostname`
  - Search: `grep`, `find`, `which`
  - Environment: `env`, `printenv`
  - System status: `df`, `du`, `free`, `uptime`
  - Container tools: `kubectl`
  - Text processing: `sed`
- **Custom command configuration**: Users can override the default list by specifying `allowed_commands` in their `agentup.yml` config
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
