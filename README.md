# AgentUp System Tools Plugin

A comprehensive system tools plugin for AgentUp that provides secure file operations, directory management, system information, and command execution capabilities.

## Features

### File Operations
- **File Read/Write**: Read and write text files with encoding support
- **File Information**: Get detailed file metadata (size, permissions, timestamps)
- **File Existence**: Check if files or directories exist
- **File Hashing**: Compute cryptographic hashes (MD5, SHA1, SHA256, SHA512)
- **Directory Listing**: List directory contents with optional filtering
- **Directory Creation**: Create directories with parent directory support
- **File Deletion**: Safely delete files and directories

### System Operations
- **System Information**: Get platform, architecture, and system details
- **Working Directory**: Get current working directory
- **Command Execution**: Execute safe shell commands with security restrictions

### Security Features
- **Workspace Isolation**: All operations restricted to configured workspace directory
- **Command Whitelist**: Only pre-approved safe commands can be executed
- **File Size Limits**: Configurable maximum file size for operations
- **Path Validation**: Protection against directory traversal attacks

## Installation

### For Development
```bash
cd agentup-systools
pip install -e .
```

### From PyPI (from AgentUp repository)
```bash
pip install --extra-index-url https://api.agentup.dev/simple agentup-systools
```

## Configuration

Add the plugin to your `agentup.yml` configuration:

```yaml
plugins:
  - plugin_id: agentup_systools
    package: agentup-systools
    name: System Tools
    description: System tools for basic operations
    config:
      workspace_dir: "/path/to/your/workspace"  # Required: Base directory for file operations
      max_file_size: 10485760                   # Optional: Max file size in bytes (default: 10MB)
      debug: false                              # Optional: Enable debug logging
    capabilities:
      # Enable the capabilities you need
      - capability_id: file_read
        enabled: true
        required_scopes: ["files:read"]
      - capability_id: file_write
        enabled: true
        required_scopes: ["files:write"]
      - capability_id: file_hash
        enabled: true
        required_scopes: ["files:read"]
      - capability_id: system_info
        enabled: true
        required_scopes: ["system:read"]
      - capability_id: execute_command
        enabled: true
        required_scopes: ["system:admin"]
      # ... add other capabilities as needed

# Security configuration
security:
  enabled: true
  scope_hierarchy:
    admin: ["*"]
    files:admin: ["files:write", "files:read"]
    files:write: ["files:read"]
    system:admin: ["system:write", "system:read"]
    system:write: ["system:read"]
```

## Available Capabilities

| Capability ID | Description | Required Scopes | AI Function |
|---------------|-------------|----------------|-------------|
| `file_read` | Read file contents | `files:read` | ✅ |
| `file_write` | Write content to files | `files:write` | ✅ |
| `file_exists` | Check file/directory existence | `files:read` | ✅ |
| `file_info` | Get file metadata | `files:read` | ✅ |
| `file_hash` | Compute file hashes | `files:read` | ✅ |
| `list_directory` | List directory contents | `files:read` | ✅ |
| `create_directory` | Create directories | `files:write` | ✅ |
| `delete_file` | Delete files/directories | `files:admin` | ✅ |
| `system_info` | Get system information | `system:read` | ✅ |
| `working_directory` | Get current directory | `system:read` | ✅ |
| `execute_command` | Execute shell commands | `system:admin` | ✅ |

## Security Considerations

### Workspace Directory
- **Required**: You must configure a `workspace_dir` to restrict file operations to a specific directory
- All file paths are resolved relative to this workspace directory
- Absolute paths outside the workspace are rejected

### Command Execution
The plugin only allows execution of pre-approved safe commands:
- `ls`, `pwd`, `whoami`, `date`, `echo`
- `cat`, `head`, `tail`, `wc`, `grep`, `find`
- `which`, `env`, `printenv`, `uname`, `hostname`
- `id`, `groups`, `df`, `du`, `free`, `uptime`

### File Size Limits
- Default maximum file size: 10MB
- Configurable via `max_file_size` setting
- Prevents memory exhaustion from large files

## Usage Examples

### AI Function Calls
The plugin automatically registers AI functions that can be called by LLMs:

```python
# These are handled automatically by the AgentUp framework
"Get the SHA256 hash of config.yml"
"List all Python files in the src directory"
"Read the contents of README.md"
"Execute the hostname command"
"Get system information"
```

### Direct API Usage
```python
from agentup_systools.plugin import AgentupSystoolsPlugin

plugin = AgentupSystoolsPlugin()
plugin.configure({
    "workspace_dir": "/path/to/workspace",
    "max_file_size": 5242880,  # 5MB
    "debug": True
})

# Example usage (within AgentUp framework)
result = await plugin.file_hash(context)
```

### Key Implementation Notes

#### Parameter Extraction
The plugin uses a robust parameter extraction method that works with both AgentUp's capability context and AI function calls:

```python
def _get_parameters(self, context: CapabilityContext) -> dict[str, Any]:
    """Extract parameters from context, checking multiple locations for compatibility."""
    params = context.metadata.get("parameters", {})
    if not params:
        params = context.task.metadata if context.task and context.task.metadata else {}
    return params
```

#### Configuration Integration
The plugin properly integrates with AgentUp's configuration system:

```python
def configure(self, config: dict[str, Any]) -> None:
    """Configure the plugin with settings."""
    super().configure(config)
    
    workspace_dir = config.get("workspace_dir")
    max_file_size = config.get("max_file_size", 10 * 1024 * 1024)
    
    self.security = SecurityManager(
        workspace_dir=workspace_dir,
        max_file_size=max_file_size
    )
```

### Testing
```bash
# Run tests
pytest tests/

# Test with an AgentUp agent
cd /path/to/your/agent
agentup agent serve
```

## License

Apache License 2.0
