# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with this AgentUp plugin.

## Plugin Overview

This is an AgentUp plugin that provides comprehensive system tools functionality including file operations, directory management, system information, and secure command execution. It uses the AgentUp decorator-based plugin architecture for integration with the AgentUp runtime.

## Plugin Structure

```
agentup-systools/
├── src/
│   └── agentup_systools/
│       ├── __init__.py         # Package initialization
│       ├── plugin.py           # Main plugin implementation
│       ├── security.py         # Security validation and management
│       ├── utils.py            # Utility functions
│       └── hashing.py          # File hashing capabilities
├── tests/
│   └── test_agentup_systools.py
├── static/                     # Static assets for AgentUp registry
├── pyproject.toml              # Package configuration with AgentUp entry point
├── README.md                   # Plugin documentation
└── CLAUDE.md                   # This file
```

## Core Plugin Architecture

### Decorator System
The plugin uses the `@capability` decorator to define functionality. The main plugin class `AgentupSystoolsPlugin` provides comprehensive system tools capabilities:

```python
from agent.plugins.base import Plugin
from agent.plugins.decorators import capability
from agent.plugins.models import CapabilityContext

class AgentupSystoolsPlugin(Plugin):
    @capability(
        id="file_read",
        name="File Read",
        description="Read contents of files",
        scopes=["files:read"],
        ai_function=True,
        ai_parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the file to read"},
                "encoding": {"type": "string", "description": "Text encoding", "default": "utf-8"}
            },
            "required": ["path"]
        }
    )
    async def file_read(self, context: CapabilityContext) -> dict[str, Any]:
        # Implementation here
        return response_dict
```

### Available Capabilities
The plugin provides the following capabilities:
- **File Operations**: `file_read`, `file_write`, `file_exists`, `file_info`, `delete_file`, `file_hash`
- **Directory Operations**: `list_directory`, `create_directory`
- **System Operations**: `system_info`, `working_directory`, `execute_command`

### Entry Point
The plugin is registered via entry point in `pyproject.toml`:
```toml
[project.entry-points."agentup.plugins"]
agentup_systools = "agentup_systools.plugin:AgentupSystoolsPlugin"
```

### Security Features
The plugin includes comprehensive security features:
- Path validation and workspace restrictions
- File size limits
- Command validation for safe execution
- Content sanitization

## Development Guidelines

### Code Style
- Follow PEP 8 and Python best practices
- Use type hints throughout the codebase (following modern Python typing conventions)
- Use async/await for I/O operations
- Handle errors gracefully with proper A2A error responses

### Modern Typing Conventions (Python 3.9+)
- **Use built-in types**: `dict[str, Any]` instead of `typing.Dict[str, Any]`
- **Use built-in types**: `list[str]` instead of `typing.List[str]`
- **Use union syntax**: `str | None` instead of `Optional[str]` (Python 3.10+)
- **Import selectively**: Only import from `typing` what's not available as built-ins
  ```python
  # ✅ CORRECT - Modern imports
  from typing import Union, Literal, Any, TypeVar, Generic
  from pydantic import BaseModel, Field, field_validator, model_validator
  
  # ❌ AVOID - Don't import these from typing
  from typing import Dict, List, Optional, Tuple, Set
  ```

### Pydantic v2 Patterns
- **Field validators**: Use `@field_validator` instead of deprecated `@validator`
- **Model validators**: Use `@model_validator(mode='after')` instead of `@root_validator`
- **Always add @classmethod**: Required for field validators in Pydantic v2
  ```python
  @field_validator("field_name")
  @classmethod
  def validate_field(cls, v: str) -> str:
      if not v.strip():
          raise ValueError("Field cannot be empty")
      return v
  ```

### Plugin Implementation Patterns

#### 1. File Operations Pattern
```python
@capability(
    id="file_read",
    name="File Read",
    description="Read contents of files",
    scopes=["files:read"],
    ai_function=True,
    ai_parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Path to the file to read"},
            "encoding": {"type": "string", "description": "Text encoding", "default": "utf-8"}
        },
        "required": ["path"]
    }
)
async def file_read(self, context: CapabilityContext) -> dict[str, Any]:
    try:
        params = self._get_parameters(context)
        path = params.get("path", "")
        encoding = params.get("encoding", "utf-8")
        
        # Security validation
        file_path = self.security.validate_path(path)
        self.security.validate_file_size(file_path)
        
        # File operation logic
        content = safe_read_text(file_path, encoding, self.security.max_file_size)
        
        return create_success_response({
            "path": str(file_path),
            "content": content,
            "encoding": encoding,
            "size": len(content)
        }, "file_read")
        
    except Exception as e:
        return create_error_response(e, "file_read")
```

#### 2. Directory Operations Pattern  
```python
@capability(
    id="list_directory",
    name="List Directory",
    description="List contents of a directory",
    scopes=["files:read"],
    ai_function=True,
    ai_parameters={
        "type": "object",
        "properties": {
            "path": {"type": "string", "description": "Directory path", "default": "."},
            "pattern": {"type": "string", "description": "Glob pattern to filter results"},
            "recursive": {"type": "boolean", "description": "List recursively", "default": False}
        }
    }
)
async def list_directory(self, context: CapabilityContext) -> dict[str, Any]:
    # Implementation with security validation and structured response
    pass
```

#### 3. System Operations Pattern
```python
@capability(
    id="execute_command",
    name="Execute Command", 
    description="Execute a safe shell command",
    scopes=["system:admin"],
    ai_function=True,
    ai_parameters={
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Command to execute"},
            "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30}
        },
        "required": ["command"]
    }
)
async def execute_command(self, context: CapabilityContext) -> dict[str, Any]:
    # Command validation and secure execution
    args = self.security.validate_command(command)
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    return create_success_response(result_data, "execute_command")
```

### Error Handling
The plugin uses structured error responses:
```python
# Success response
return create_success_response(
    data={"path": str(file_path), "content": content},
    operation="file_read",
    message="Successfully read file"
)

# Error response  
return create_error_response(
    error=FileNotFoundError(f"File not found: {path}"),
    operation="file_read"
)
```

### Security Implementation
The plugin implements comprehensive security through the `SecurityManager` class:
- **Path Validation**: Ensures paths are within the workspace directory
- **File Size Limits**: Prevents processing of overly large files
- **Command Validation**: Whitelist of allowed shell commands
- **Content Sanitization**: Removes potentially dangerous content

### Configuration Schema
The plugin supports the following configuration options:
```python
{
    "workspace_dir": "string",              # Base directory for operations
    "max_file_size": "integer",             # Maximum file size in bytes
    "allowed_extensions": ["string"],       # Allowed file extensions
    "allowed_commands": ["string"],         # Allowed shell commands
    "enabled": "boolean",                   # Enable/disable plugin
    "debug": "boolean"                      # Debug logging
}
```

### Testing
- Write comprehensive tests for all plugin functionality
- Test both success and error cases
- Mock external dependencies  
- Use pytest and async test patterns

## Development Workflow

### Local Development
1. Install in development mode: `pip install -e .`
2. Create test agent: `agentup agent create test-agent --quick`
3. Configure plugin in agent's `agentup.yml`
4. Test with: `agentup agent serve`

### Testing
```bash
# Run tests
pytest tests/ -v

# Check plugin loading
agentup plugin list

# Validate plugin
agentup plugin validate agentup_systools
```

### External Dependencies
- Use AgentUp's service registry for HTTP clients, databases, etc.
- Declare all dependencies in pyproject.toml
- Use async libraries for better performance

## Plugin Capabilities

### File Operations
- **`file_read`**: Read file contents with encoding support
- **`file_write`**: Write content to files with parent directory creation
- **`file_exists`**: Check if files or directories exist
- **`file_info`**: Get detailed file/directory information (size, permissions, timestamps)
- **`delete_file`**: Delete files or directories (with recursive option)
- **`file_hash`**: Compute cryptographic hashes (MD5, SHA1, SHA256, SHA512)

### Directory Operations  
- **`list_directory`**: List directory contents with pattern filtering and recursive options
- **`create_directory`**: Create directories with parent creation support

### System Operations
- **`system_info`**: Get comprehensive system and platform information
- **`working_directory`**: Get current working directory
- **`execute_command`**: Execute safe shell commands with timeout and output capture

### Security Scopes
- **`files:read`**: Read access to files and directories
- **`files:write`**: Write access for file and directory creation/modification  
- **`files:admin`**: Administrative access for file deletion
- **`system:read`**: System information access
- **`system:admin`**: System command execution

### AI Function Integration
All capabilities are designed as AI-callable functions with:
- Structured parameter schemas
- Input/output validation
- Rich examples for AI understanding
- Standardized error handling

### Utility Modules
- **`security.py`**: SecurityManager for path validation and command filtering
- **`utils.py`**: Helper functions for file operations and response formatting
- **`hashing.py`**: FileHasher for cryptographic operations

## Resources

- [AgentUp Documentation](https://docs.agentup.dev)
- [Plugin Development Guide](https://docs.agentup.dev/plugins/development)
- [Testing Guide](https://docs.agentup.dev/plugins/testing)
- [AI Functions Guide](https://docs.agentup.dev/plugins/ai-functions)

## Usage Examples

### File Operations
```python
# Reading a configuration file
await plugin.file_read(context_with_params({"path": "config.json"}))

# Writing data to a file
await plugin.file_write(context_with_params({
    "path": "output.txt", 
    "content": "Hello World",
    "create_parents": True
}))

# Computing file hashes for integrity verification
await plugin.file_hash(context_with_params({
    "path": "document.pdf",
    "algorithms": ["sha256", "md5"]
}))
```

### Directory Operations
```python
# Listing Python files recursively
await plugin.list_directory(context_with_params({
    "path": "src",
    "pattern": "*.py", 
    "recursive": True
}))
```

### System Operations  
```python
# Getting system information
await plugin.system_info(context)

# Executing a safe command
await plugin.execute_command(context_with_params({
    "command": "ls -la",
    "timeout": 10
}))
```

---

Remember: This plugin provides comprehensive system tools functionality with security-first design. Always consider workspace restrictions and security policies when working with file operations and command execution.