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
        self,
        workspace_dir: str | None = None,
        max_file_size: int = 10 * 1024 * 1024,
        unbanned_commands: set[str] | None = None,
    ):
        """
        Initialize security manager.

        Args:
            workspace_dir: Directory to restrict operations to (defaults to cwd)
            max_file_size: Maximum file size in bytes (default 10MB)
            unbanned_commands: Commands to remove from the banned list (allow execution)
        """
        self.workspace_dir = Path(workspace_dir or os.getcwd()).resolve()
        self.max_file_size = max_file_size

        # Default banned commands list for security
        self.banned_commands = {
            # System Destruction
            "dd",
            "mkfs",
            "fdisk",
            "shred",
            "wipefs",
            # Network & Remote Access
            "nc",
            "netcat",
            "ssh",
            "scp",
            "telnet",
            "ftp",
            # System Control & Privilege Escalation
            "su",
            "sudo",
            "passwd",
            "chmod",
            "mount",
            "umount",
            "systemctl",
            "service",
            # Dangerous Interpreters & Compilers
            "eval",
            "exec",
            # File System Manipulation
            "cpio",
            "rsync",
            # Environment & Shell Control
            "history",
            # macOS Specific Commands
            "diskutil",  # Disk utility - format, partition, erase disks
            "hdiutil",  # Disk image utility - mount/create disk images
            "installer",  # Install packages (.pkg files)
            "softwareupdate",  # System software updates
            "spctl",  # System policy control (Gatekeeper)
            "csrutil",  # System Integrity Protection control
            "nvram",  # Non-volatile RAM manipulation
            "pmset",  # Power management settings
            "launchctl",  # Launch daemon/agent control
            "dscl",  # Directory service command line
            "dseditgroup",  # Edit group membership
            "pwpolicy",  # Password policy administration
            "sysadminctl",  # System administrator utility
            "systemsetup",  # System setup utility
            "scutil",  # System configuration utility
            "networksetup",  # Network configuration
            "security",  # Keychain and security framework
            "codesign",  # Code signing utility
            "xattr",  # Extended file attributes
            "mdutil",  # Spotlight metadata utility
            "tmutil",  # Time Machine utility
            "caffeinate",  # Prevent system sleep (potential DoS)
            "purge",  # Force memory cleanup
            "reboot",  # System restart
            "shutdown",  # System shutdown
            "halt",  # System halt
        }

        # Remove unbanned commands from the banned list if provided
        if unbanned_commands:
            self.banned_commands = self.banned_commands - unbanned_commands

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
            raise SecurityError(f"Path '{path}' is outside workspace directory '{self.workspace_dir}'") from None

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
                raise SecurityError(f"File size ({size} bytes) exceeds maximum allowed ({self.max_file_size} bytes)")

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
            raise SecurityError(f"Command parsing error: {e}") from None

        if not args:
            raise SecurityError("Empty command")

        # Check if base command is banned
        base_command = args[0]
        if base_command in self.banned_commands:
            raise SecurityError(
                f"Command '{base_command}' is banned for security reasons. "
                f"Contact your administrator to unban this command if needed."
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
            raise SecurityError(f"Content length ({len(content)}) exceeds maximum allowed ({max_length})")

        # Remove null bytes
        content = content.replace("\0", "")

        return content
