"""Security management for safe file and system operations."""

import os
import re
from pathlib import Path


class SecurityError(Exception):
    """Raised when a security check fails."""

    pass


class SecurityManager:
    """Manages security policies and validations."""

    def __init__(
        self, workspace_dir: str | None = None, max_file_size: int = 10 * 1024 * 1024
    ):
        """
        Initialize security manager.

        Args:
            workspace_dir: Directory to restrict operations to (defaults to cwd)
            max_file_size: Maximum file size in bytes (default 10MB)
        """
        self.workspace_dir = Path(workspace_dir or os.getcwd()).resolve()
        self.max_file_size = max_file_size

        # Command whitelist for safe execution
        self.allowed_commands = {
            "ls",
            "pwd",
            "whoami",
            "date",
            "echo",
            "cat",
            "head",
            "tail",
            "wc",
            "grep",
            "find",
            "which",
            "env",
            "printenv",
            "uname",
            "hostname",
            "id",
            "groups",
            "df",
            "du",
            "free",
            "uptime",
            "kubectl",
            "sed",
        }

        # Dangerous path patterns
        self.dangerous_patterns = [
            r"\.\./",  # Directory traversal
            r"^\/",  # Absolute paths (when not allowed)
            r"~/",  # Home directory expansion
            r"\$\{",  # Variable expansion
            r"\$\(",  # Command substitution
        ]

    def validate_path(self, path: str | Path, allow_absolute: bool = False) -> Path:
        """
        Validate and normalize a path.

        Args:
            path: Path to validate
            allow_absolute: Whether to allow absolute paths

        Returns:
            Validated and normalized Path object

        Raises:
            SecurityError: If path validation fails
        """
        # Convert to string for pattern matching
        path_str = str(path)

        # Check for dangerous patterns
        for pattern in self.dangerous_patterns:
            if re.search(pattern, path_str):
                raise SecurityError(f"Dangerous path pattern detected: {pattern}")

        # Convert to Path object
        path_obj = Path(path)

        # Handle absolute paths
        if path_obj.is_absolute():
            if not allow_absolute:
                raise SecurityError("Absolute paths are not allowed")
            resolved_path = path_obj.resolve()
        else:
            # Resolve relative to workspace
            resolved_path = (self.workspace_dir / path_obj).resolve()

        # Ensure path is within workspace
        try:
            resolved_path.relative_to(self.workspace_dir)
        except ValueError:
            raise SecurityError(
                f"Path '{path}' is outside workspace directory '{self.workspace_dir}'"
            ) from None

        return resolved_path

    def validate_file_size(self, path: Path) -> None:
        """
        Check if file size is within limits.

        Args:
            path: Path to file

        Raises:
            SecurityError: If file is too large
        """
        if path.exists() and path.is_file():
            size = path.stat().st_size
            if size > self.max_file_size:
                raise SecurityError(
                    f"File size ({size} bytes) exceeds maximum allowed "
                    f"({self.max_file_size} bytes)"
                )

    def validate_command(self, command: str) -> list[str]:
        """
        Validate and parse a shell command.

        Args:
            command: Command string to validate

        Returns:
            Parsed command as list of arguments

        Raises:
            SecurityError: If command is not allowed
        """
        # Basic command parsing (splits on spaces, respects quotes)
        import shlex

        try:
            args = shlex.split(command)
        except ValueError as e:
            raise SecurityError(f"Invalid command syntax: {e}")

        if not args:
            raise SecurityError("Empty command")

        # Check if base command is allowed
        base_command = args[0]
        if base_command not in self.allowed_commands:
            raise SecurityError(
                f"Command '{base_command}' is not in allowed list. "
                f"Allowed commands: {', '.join(sorted(self.allowed_commands))}"
            )

        # Additional validation for specific commands
        if base_command in ["cat", "head", "tail"]:
            # Ensure they're only reading files within workspace
            for arg in args[1:]:
                if not arg.startswith("-"):  # Skip flags
                    try:
                        self.validate_path(arg)
                    except SecurityError:
                        # Allow reading system files for these commands
                        if not Path(arg).is_absolute():
                            raise

        return args

    def sanitize_content(self, content: str, max_length: int = 1000000) -> str:
        """
        Sanitize content for safe handling.

        Args:
            content: Content to sanitize
            max_length: Maximum allowed length

        Returns:
            Sanitized content

        Raises:
            SecurityError: If content violates security policies
        """
        if len(content) > max_length:
            raise SecurityError(
                f"Content length ({len(content)}) exceeds maximum "
                f"allowed ({max_length})"
            )

        # Remove null bytes
        content = content.replace("\0", "")

        return content