"""
System Tools plugin for AgentUp.

Provides comprehensive file system operations, directory management,
system information, and secure command execution capabilities.
"""

import os
import platform
import shutil
import subprocess
from typing import Any

import structlog  # noqa: F401
from agent.plugins.base import Plugin
from agent.plugins.decorators import capability
from agent.plugins.models import CapabilityContext

from .hashing import FileHasher
from .security import SecurityManager
from .utils import (
    create_error_response,
    create_success_response,
    format_file_size,
    format_timestamp,
    get_file_permissions,
    get_file_type,
    safe_read_text,
    safe_write_text,
)


class AgentupSystoolsPlugin(Plugin):
    """System Tools plugin providing file operations, directory management, and system utilities."""

    def __init__(self):
        """Initialize the plugin."""
        super().__init__()
        self.name = "agentup_systools"
        self.version = "1.0.0"
        # Initialize with defaults - will be reconfigured when configure() is called
        self.security = SecurityManager()
        self.hasher = FileHasher(self.security)

    def configure(self, config: dict[str, Any]) -> None:
        """Configure the plugin with settings."""
        super().configure(config)

        # Reinitialize security manager with configuration
        workspace_dir = config.get("workspace_dir")
        max_file_size = config.get("max_file_size", 10 * 1024 * 1024)

        # Get allowed commands from config if provided
        allowed_commands_config = config.get("allowed_commands")
        allowed_commands = None
        if allowed_commands_config:
            allowed_commands = set(allowed_commands_config)

        self.security = SecurityManager(
            workspace_dir=workspace_dir,
            max_file_size=max_file_size,
            allowed_commands=allowed_commands,
        )
        self.hasher = FileHasher(self.security)

        if config.get("debug", False):
            command_info = (
                f", allowed_commands: {len(allowed_commands) if allowed_commands else 'default'}"
                if allowed_commands
                else ""
            )
            self.logger.info(
                f"Plugin configured with workspace_dir: {workspace_dir}, max_file_size: {max_file_size}{command_info}"
            )

    def _get_parameters(self, context: CapabilityContext) -> dict[str, Any]:
        """Extract parameters from context, checking multiple locations for compatibility."""
        params = context.metadata.get("parameters", {})
        if not params:
            params = context.task.metadata if context.task and context.task.metadata else {}
        return params

    # File Operations
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
                "encoding": {
                    "type": "string",
                    "description": "Text encoding (default: utf-8)",
                    "default": "utf-8",
                },
            },
            "required": ["path"],
        },
        # A2A AgentSkill metadata
        examples=[
            "Read the contents of config.json",
            "Show me what's in the README.md file",
            "Display the contents of /var/log/app.log",
            "Read the Python script at src/main.py",
        ],
        input_modes=["text/plain"],
        output_modes=["text/plain", "application/json"],
        security=[{"scopes": ["files:read"]}],
    )
    async def file_read(self, context: CapabilityContext) -> dict[str, Any]:
        """Read contents of a file."""
        try:
            params = self._get_parameters(context)
            path = params.get("path", "")
            encoding = params.get("encoding", "utf-8")

            file_path = self.security.validate_path(path)
            self.security.validate_file_size(file_path)

            if not file_path.exists():
                return create_error_response(
                    FileNotFoundError(f"File not found: {path}"), "file_read"
                )

            if not file_path.is_file():
                return create_error_response(ValueError(f"Path is not a file: {path}"), "file_read")

            content = safe_read_text(file_path, encoding, self.security.max_file_size)

            return create_success_response(
                {
                    "path": str(file_path),
                    "content": content,
                    "encoding": encoding,
                    "size": len(content),
                },
                "file_read",
                f"Successfully read {format_file_size(len(content.encode()))}",
            )

        except Exception as e:
            return create_error_response(e, "file_read")

    @capability(
        id="file_write",
        name="File Write",
        description="Write content to files",
        scopes=["files:write"],
        ai_function=True,
        ai_parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the file to write"},
                "content": {"type": "string", "description": "Content to write to the file"},
                "encoding": {
                    "type": "string",
                    "description": "Text encoding (default: utf-8)",
                    "default": "utf-8",
                },
                "create_parents": {
                    "type": "boolean",
                    "description": "Create parent directories if needed",
                    "default": True,
                },
            },
            "required": ["path", "content"],
        },
        # A2A AgentSkill metadata
        examples=[
            "Write 'Hello World' to output.txt",
            "Save this JSON configuration to settings.json",
            "Create a new Python script at src/helper.py",
            "Update the README.md with new documentation",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["files:write"]}],
    )
    async def file_write(self, context: CapabilityContext) -> dict[str, Any]:
        """Write content to a file."""
        try:
            params = self._get_parameters(context)
            path = params.get("path", "")
            content = params.get("content", "")
            encoding = params.get("encoding", "utf-8")
            create_parents = params.get("create_parents", True)

            file_path = self.security.validate_path(path)
            content = self.security.sanitize_content(content)

            # Check if we're overwriting
            exists = file_path.exists()

            safe_write_text(file_path, content, encoding, create_parents)

            return create_success_response(
                {
                    "path": str(file_path),
                    "size": len(content.encode()),
                    "encoding": encoding,
                    "overwritten": exists,
                },
                "file_write",
                f"Successfully {'updated' if exists else 'created'} file",
            )

        except Exception as e:
            return create_error_response(e, "file_write")

    @capability(
        id="file_exists",
        name="File Exists",
        description="Check if a file or directory exists",
        scopes=["files:read"],
        ai_function=True,
        ai_parameters={
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Path to check"}},
            "required": ["path"],
        },
        # A2A AgentSkill metadata
        examples=[
            "Check if config.json exists",
            "Does the directory /home/user/projects exist?",
            "Verify if the file backup.tar.gz is present",
            "Is there a .env file in the current directory?",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["files:read"]}],
    )
    async def file_exists(self, context: CapabilityContext) -> dict[str, Any]:
        """Check if a file exists."""
        try:
            params = self._get_parameters(context)
            path = params.get("path", "")

            file_path = self.security.validate_path(path)
            exists = file_path.exists()

            return create_success_response(
                {
                    "path": str(file_path),
                    "exists": exists,
                    "is_file": file_path.is_file() if exists else None,
                    "is_directory": file_path.is_dir() if exists else None,
                },
                "file_exists",
            )

        except Exception as e:
            return create_error_response(e, "file_exists")

    @capability(
        id="file_info",
        name="File Info",
        description="Get detailed information about a file or directory",
        scopes=["files:read"],
        ai_function=True,
        ai_parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the file or directory"}
            },
            "required": ["path"],
        },
        # A2A AgentSkill metadata
        examples=[
            "Get information about the file document.pdf",
            "Show me the details of the logs directory",
            "What are the permissions on script.sh?",
            "When was config.yml last modified?",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["files:read"]}],
    )
    async def file_info(self, context: CapabilityContext) -> dict[str, Any]:
        """Get detailed information about a file."""
        try:
            params = self._get_parameters(context)
            path = params.get("path", "")

            file_path = self.security.validate_path(path)

            if not file_path.exists():
                return create_error_response(
                    FileNotFoundError(f"Path not found: {path}"), "file_info"
                )

            stat = file_path.stat()

            info = {
                "path": str(file_path),
                "name": file_path.name,
                "type": get_file_type(file_path),
                "size": stat.st_size,
                "size_human": format_file_size(stat.st_size),
                "permissions": get_file_permissions(file_path),
                "created": format_timestamp(stat.st_ctime),
                "modified": format_timestamp(stat.st_mtime),
                "accessed": format_timestamp(stat.st_atime),
                "is_file": file_path.is_file(),
                "is_directory": file_path.is_dir(),
                "is_symlink": file_path.is_symlink(),
            }

            if file_path.is_symlink():
                info["symlink_target"] = str(file_path.readlink())

            return create_success_response(info, "file_info")

        except Exception as e:
            return create_error_response(e, "file_info")

    @capability(
        id="delete_file",
        name="Delete File",
        description="Delete a file or directory",
        scopes=["files:admin"],
        ai_function=True,
        ai_parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to delete"},
                "recursive": {
                    "type": "boolean",
                    "description": "Delete directories recursively",
                    "default": False,
                },
            },
            "required": ["path"],
        },
        # A2A AgentSkill metadata
        examples=[
            "Delete the file temp.txt",
            "Remove the empty directory old_backup",
            "Delete the logs folder and all its contents",
            "Remove all .tmp files from the cache directory",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["files:admin"]}],
    )
    async def delete_file(self, context: CapabilityContext) -> dict[str, Any]:
        """Delete a file or directory."""
        try:
            params = self._get_parameters(context)
            path = params.get("path", "")
            recursive = params.get("recursive", False)

            file_path = self.security.validate_path(path)

            if not file_path.exists():
                return create_error_response(
                    FileNotFoundError(f"Path not found: {path}"), "delete_file"
                )

            if file_path.is_dir():
                if recursive:
                    shutil.rmtree(file_path)
                else:
                    file_path.rmdir()  # Only works for empty directories
            else:
                file_path.unlink()

            return create_success_response(
                {"path": str(file_path), "deleted": True},
                "delete_file",
                f"Successfully deleted: {path}",
            )

        except Exception as e:
            return create_error_response(e, "delete_file")

    # Directory Operations
    @capability(
        id="list_directory",
        name="List Directory",
        description="List contents of a directory",
        scopes=["files:read"],
        ai_function=True,
        ai_parameters={
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Directory path (default: current directory)",
                    "default": ".",
                },
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern to filter results (e.g., '*.txt')",
                },
                "recursive": {
                    "type": "boolean",
                    "description": "List recursively",
                    "default": False,
                },
            },
        },
        # A2A AgentSkill metadata
        examples=[
            "List all files in the current directory",
            "Show me all Python files in the src folder",
            "List all .json files recursively in the config directory",
            "What's in the /var/log directory?",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["files:read"]}],
    )
    async def list_directory(self, context: CapabilityContext) -> dict[str, Any]:
        """List contents of a directory."""
        try:
            params = context.metadata.get("parameters", {})
            path = params.get("path", ".")
            pattern = params.get("pattern")
            recursive = params.get("recursive", False)

            dir_path = self.security.validate_path(path)

            if not dir_path.exists():
                return create_error_response(
                    FileNotFoundError(f"Directory not found: {path}"), "list_directory"
                )

            if not dir_path.is_dir():
                return create_error_response(
                    ValueError(f"Path is not a directory: {path}"), "list_directory"
                )

            entries = []

            if recursive:
                # Use rglob for recursive listing
                paths = dir_path.rglob(pattern or "*")
            else:
                # Use glob for non-recursive listing
                paths = dir_path.glob(pattern or "*")

            for entry in sorted(paths):
                try:
                    stat = entry.stat()
                    entries.append(
                        {
                            "name": entry.name,
                            "path": str(entry.relative_to(dir_path)),
                            "type": "directory" if entry.is_dir() else "file",
                            "size": stat.st_size if entry.is_file() else None,
                            "modified": format_timestamp(stat.st_mtime),
                        }
                    )
                except Exception:
                    # Skip entries we can't stat
                    continue

            return create_success_response(
                {"path": str(dir_path), "count": len(entries), "entries": entries},
                "list_directory",
            )

        except Exception as e:
            return create_error_response(e, "list_directory")

    @capability(
        id="create_directory",
        name="Create Directory",
        description="Create a new directory",
        scopes=["files:write"],
        ai_function=True,
        ai_parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path of directory to create"},
                "parents": {
                    "type": "boolean",
                    "description": "Create parent directories if needed",
                    "default": True,
                },
                "exist_ok": {
                    "type": "boolean",
                    "description": "Don't raise error if directory exists",
                    "default": True,
                },
            },
            "required": ["path"],
        },
        # A2A AgentSkill metadata
        examples=[
            "Create a new directory called 'output'",
            "Make a folder structure 'data/processed/2024'",
            "Create directories for the project: src, tests, docs",
            "Set up a backup directory at /tmp/backups",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["files:write"]}],
    )
    async def create_directory(self, context: CapabilityContext) -> dict[str, Any]:
        """Create a directory."""
        try:
            params = self._get_parameters(context)
            path = params.get("path", "")
            parents = params.get("parents", True)
            exist_ok = params.get("exist_ok", True)

            dir_path = self.security.validate_path(path)

            if dir_path.exists() and not exist_ok:
                return create_error_response(
                    FileExistsError(f"Directory already exists: {path}"),
                    "create_directory",
                )

            dir_path.mkdir(parents=parents, exist_ok=exist_ok)

            return create_success_response(
                {"path": str(dir_path), "created": True},
                "create_directory",
                f"Directory created: {path}",
            )

        except Exception as e:
            return create_error_response(e, "create_directory")

    # System Operations
    @capability(
        id="system_info",
        name="System Info",
        description="Get system and platform information",
        scopes=["system:read"],
        ai_function=True,
        ai_parameters={"type": "object", "properties": {}},
        # A2A AgentSkill metadata
        examples=[
            "What operating system is this running on?",
            "Show me the system information",
            "Get the platform details and Python version",
            "What's the hostname and architecture?",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["system:read"]}],
    )
    async def system_info(self, context: CapabilityContext) -> dict[str, Any]:
        """Get system information."""
        try:
            info = {
                "platform": platform.system(),
                "platform_release": platform.release(),
                "platform_version": platform.version(),
                "architecture": platform.machine(),
                "processor": platform.processor(),
                "hostname": platform.node(),
                "python_version": platform.python_version(),
                "working_directory": os.getcwd(),
            }

            # Add OS-specific info
            if platform.system() != "Windows":
                info["user"] = os.environ.get("USER", "unknown")
            else:
                info["user"] = os.environ.get("USERNAME", "unknown")

            return create_success_response(info, "system_info")

        except Exception as e:
            return create_error_response(e, "system_info")

    @capability(
        id="working_directory",
        name="Working Directory",
        description="Get the current working directory",
        scopes=["system:read"],
        ai_function=True,
        ai_parameters={"type": "object", "properties": {}},
        # A2A AgentSkill metadata
        examples=[
            "What's the current working directory?",
            "Show me where I am in the filesystem",
            "Get the present working directory",
            "What directory am I currently in?",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["system:read"]}],
    )
    async def working_directory(self, context: CapabilityContext) -> dict[str, Any]:
        """Get current working directory."""
        try:
            cwd = os.getcwd()
            return create_success_response(
                {"path": cwd, "absolute": os.path.abspath(cwd)}, "working_directory"
            )
        except Exception as e:
            return create_error_response(e, "working_directory")

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
                "timeout": {"type": "integer", "description": "Timeout in seconds", "default": 30},
            },
            "required": ["command"],
        },
        # A2A AgentSkill metadata
        examples=[
            "Run 'ls -la' to list all files",
            "Execute 'git status' to check repository status",
            "Run the Python script: python analyze.py",
            "Execute 'df -h' to check disk usage",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["system:admin"]}],
    )
    async def execute_command(self, context: CapabilityContext) -> dict[str, Any]:
        """Execute a safe shell command."""
        params: dict[str, Any] = {}
        try:
            params = self._get_parameters(context)
            command = params.get("command", "")
            timeout = params.get("timeout", 30)

            # Validate command
            args = self.security.validate_command(command)

            # Execute command
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=str(self.security.workspace_dir),
            )

            return create_success_response(
                {
                    "command": command,
                    "args": args,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                    "returncode": result.returncode,
                    "success": result.returncode == 0,
                },
                "execute_command",
            )

        except subprocess.TimeoutExpired:
            return create_error_response(
                TimeoutError(f"Command timed out after {params.get('timeout', 30)} seconds"),
                "execute_command",
            )
        except Exception as e:
            return create_error_response(e, "execute_command")

    # File Hashing
    @capability(
        id="file_hash",
        name="File Hash",
        description="Compute cryptographic hash(es) for a file",
        scopes=["files:read"],
        ai_function=True,
        ai_parameters={
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Path to the file"},
                "algorithms": {
                    "type": "array",
                    "items": {"type": "string", "enum": ["md5", "sha1", "sha256", "sha512"]},
                    "description": "Hash algorithms to use",
                    "default": ["sha256"],
                },
                "output_format": {
                    "type": "string",
                    "enum": ["hex", "base64"],
                    "description": "Output format for hash",
                    "default": "hex",
                },
                "include_file_info": {
                    "type": "boolean",
                    "description": "Include file information in response",
                    "default": True,
                },
            },
            "required": ["path"],
        },
        # A2A AgentSkill metadata
        examples=[
            "Calculate the SHA256 hash of document.pdf",
            "Get MD5 and SHA1 checksums for archive.zip",
            "Verify the integrity of download.iso with SHA512",
            "Compute all hashes for the executable file",
        ],
        input_modes=["text/plain"],
        output_modes=["application/json"],
        security=[{"scopes": ["files:read"]}],
    )
    async def file_hash(self, context: CapabilityContext) -> dict[str, Any]:
        """Compute cryptographic hash(es) for a file."""
        try:
            params = self._get_parameters(context)

            path = params.get("path", "")
            algorithms = params.get("algorithms", ["sha256"])
            output_format = params.get("output_format", "hex")
            include_file_info = params.get("include_file_info", True)

            # Use the hasher to compute file hash(es)
            result = self.hasher.hash_file_with_info(
                path, algorithms, output_format, include_file_info
            )
            return result
        except Exception as e:
            return create_error_response(e, "file_hash")

    def get_config_schema(self) -> dict[str, Any]:
        """Define configuration schema for system tools plugin."""
        return {
            "type": "object",
            "properties": {
                "workspace_dir": {
                    "type": "string",
                    "description": "Base directory for file operations (for security)",
                },
                "max_file_size": {
                    "type": "integer",
                    "description": "Maximum file size in bytes",
                    "default": 10485760,
                },
                "allowed_extensions": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Allowed file extensions",
                },
                "allowed_commands": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of allowed shell commands for execution (if not specified, uses default safe commands)",
                },
                "enabled": {
                    "type": "boolean",
                    "default": True,
                    "description": "Enable/disable the plugin",
                },
                "debug": {
                    "type": "boolean",
                    "default": False,
                    "description": "Enable debug logging",
                },
            },
            "additionalProperties": False,
        }

    def validate_config(self, config: dict[str, Any]) -> dict[str, Any]:
        """Validate system tools plugin configuration."""
        errors = []
        warnings = []

        # Validate workspace directory
        if "workspace_dir" in config:
            workspace = config["workspace_dir"]
            if not os.path.exists(workspace):
                errors.append(f"Workspace directory does not exist: {workspace}")
            elif not os.path.isdir(workspace):
                errors.append(f"Workspace path is not a directory: {workspace}")

        # Validate max file size
        if "max_file_size" in config:
            max_size = config["max_file_size"]
            if not isinstance(max_size, int) or max_size <= 0:
                errors.append("max_file_size must be a positive integer")
            elif max_size < 1024:
                warnings.append("max_file_size is very small (< 1KB)")

        # Validate allowed commands
        if "allowed_commands" in config:
            allowed_commands = config["allowed_commands"]
            if not isinstance(allowed_commands, list):
                errors.append("allowed_commands must be a list of strings")
            else:
                # Check if all commands are strings
                non_strings = [cmd for cmd in allowed_commands if not isinstance(cmd, str)]
                if non_strings:
                    errors.append(f"allowed_commands contains non-string values: {non_strings}")

                # Check for potentially dangerous commands
                dangerous_commands = {
                    "rm",
                    "rmdir",
                    "dd",
                    "mkfs",
                    "fdisk",
                    "sudo",
                    "su",
                    "chmod",
                    "chown",
                }
                dangerous_found = [cmd for cmd in allowed_commands if cmd in dangerous_commands]
                if dangerous_found:
                    warnings.append(
                        f"Potentially dangerous commands in allowed_commands: {dangerous_found}"
                    )

        return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings}

    def _extract_user_input(self, context: CapabilityContext) -> str:
        """Extract user input from the task context (A2A message structure)."""
        if hasattr(context.task, "history") and context.task.history:
            # Get the first user message (not the last, as that might be agent response)
            for msg in context.task.history:
                if hasattr(msg, "role") and msg.role.value == "user":
                    if hasattr(msg, "parts") and msg.parts:
                        for part in msg.parts:
                            # Check for text content with proper type checking
                            if hasattr(part, "root") and hasattr(part.root, "text"):
                                text_content = getattr(part.root, "text", None)
                                if text_content:
                                    return str(text_content)
                            # Direct text attribute access with safe getattr
                            text_content = getattr(part, "text", None)
                            if text_content:
                                return str(text_content)
        return ""

    async def cleanup(self):
        """Cleanup resources when plugin is destroyed."""
        # Basic cleanup
        pass
