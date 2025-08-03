"""Utility functions for file operations and formatting."""

import mimetypes
from datetime import datetime
from pathlib import Path
from typing import Any


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Human-readable size string
    """
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size_bytes < 1024.0:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.2f} PB"


def format_timestamp(timestamp: float) -> str:
    """
    Format Unix timestamp to readable datetime string.

    Args:
        timestamp: Unix timestamp

    Returns:
        Formatted datetime string
    """
    dt = datetime.fromtimestamp(timestamp)
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def get_file_type(path: Path) -> str:
    """
    Determine file type from path.

    Args:
        path: Path to file

    Returns:
        File type description
    """
    if path.is_dir():
        return "directory"
    elif path.is_symlink():
        return "symbolic link"
    elif path.is_file():
        # Try to determine MIME type
        mime_type, _ = mimetypes.guess_type(str(path))
        if mime_type:
            return mime_type

        # Check for common text files without extensions
        try:
            with open(path, encoding="utf-8") as f:
                f.read(512)  # Try reading first 512 bytes
            return "text/plain"
        except (OSError, UnicodeDecodeError):
            return "application/octet-stream"
    else:
        return "unknown"


def safe_read_text(
    path: Path, encoding: str = "utf-8", max_size: int | None = None
) -> str:
    """
    Safely read text from a file.

    Args:
        path: Path to file
        encoding: Text encoding
        max_size: Maximum bytes to read (None for all)

    Returns:
        File contents as string

    Raises:
        IOError: If file cannot be read
        UnicodeDecodeError: If file is not valid text
    """
    # Check file size first if max_size is specified
    if max_size is not None:
        size = path.stat().st_size
        if size > max_size:
            # Read only up to max_size
            with open(path, encoding=encoding) as f:
                content = f.read(max_size)
                return (
                    content
                    + f"\n\n[Truncated - file size {format_file_size(size)} exceeds limit]"
                )

    with open(path, encoding=encoding) as f:
        return f.read()


def safe_write_text(
    path: Path, content: str, encoding: str = "utf-8", create_parents: bool = True
) -> None:
    """
    Safely write text to a file.

    Args:
        path: Path to file
        content: Content to write
        encoding: Text encoding
        create_parents: Whether to create parent directories

    Raises:
        IOError: If file cannot be written
    """
    if create_parents and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)

    # Write to temporary file first, then move (atomic write)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        with open(temp_path, "w", encoding=encoding) as f:
            f.write(content)
        temp_path.replace(path)
    except Exception:
        # Clean up temp file on error
        if temp_path.exists():
            temp_path.unlink()
        raise


def get_file_permissions(path: Path) -> str:
    """
    Get file permissions in human-readable format.

    Args:
        path: Path to file

    Returns:
        Permission string (e.g., "rw-r--r--")
    """
    mode = path.stat().st_mode
    perms = ["r" if mode & 0o400 else "-", "w" if mode & 0o200 else "-", "x" if mode & 0o100 else "-",
             "r" if mode & 0o040 else "-", "w" if mode & 0o020 else "-", "x" if mode & 0o010 else "-",
             "r" if mode & 0o004 else "-", "w" if mode & 0o002 else "-", "x" if mode & 0o001 else "-"]

    # Owner permissions

    # Group permissions

    # Other permissions

    return "".join(perms)


def normalize_line_endings(content: str, style: str = "unix") -> str:
    """
    Normalize line endings in text content.

    Args:
        content: Text content
        style: Line ending style ('unix', 'windows', 'mac')

    Returns:
        Content with normalized line endings
    """
    # First normalize to \n
    content = content.replace("\r\n", "\n").replace("\r", "\n")

    # Then convert to requested style
    if style == "windows":
        content = content.replace("\n", "\r\n")
    elif style == "mac":
        content = content.replace("\n", "\r")

    return content


def create_error_response(error: Exception, operation: str) -> dict[str, Any]:
    """
    Create a standardized error response.

    Args:
        error: The exception that occurred
        operation: The operation that failed

    Returns:
        Error response dictionary
    """
    error_type = type(error).__name__
    return {
        "success": False,
        "error": str(error),
        "error_type": error_type,
        "operation": operation,
        "message": f"{operation} failed: {error}",
    }


def create_success_response(
    data: Any, operation: str, message: str | None = None
) -> dict[str, Any]:
    """
    Create a standardized success response.

    Args:
        data: Response data
        operation: The operation performed
        message: Optional success message

    Returns:
        Success response dictionary
    """
    response = {"success": True, "data": data, "operation": operation}

    if message:
        response["message"] = message

    return response
