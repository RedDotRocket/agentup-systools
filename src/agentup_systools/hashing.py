"""Secure file hashing utility with support for multiple algorithms."""

import base64
import hashlib
from pathlib import Path
from typing import Any

from .security import SecurityManager
from .utils import create_error_response, create_success_response, format_file_size


class FileHasher:
    """Secure file hashing utility with support for multiple algorithms."""

    SUPPORTED_ALGORITHMS = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
        "sha512": hashlib.sha512,
    }

    def __init__(self, security_manager: SecurityManager):
        """
        Initialize the file hasher.

        Args:
            security_manager: Security manager for path validation
        """
        self.security = security_manager

    def get_supported_algorithms(self) -> list[str]:
        """
        Get list of supported hash algorithms.

        Returns:
            List of supported algorithm names
        """
        return list(self.SUPPORTED_ALGORITHMS.keys())

    def compute_file_hash(
        self,
        file_path: Path,
        algorithm: str = "sha256",
        output_format: str = "hex",
        chunk_size: int = 8192,
    ) -> dict[str, str]:
        """
        Compute hash for a single file.

        Args:
            file_path: Path to the file
            algorithm: Hash algorithm to use
            output_format: Output format ('hex' or 'base64')
            chunk_size: Size of chunks to read (bytes)

        Returns:
            Dictionary containing hash information

        Raises:
            ValueError: If algorithm or format is not supported
            IOError: If file cannot be read
        """
        # Validate algorithm
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(
                f"Unsupported algorithm '{algorithm}'. "
                f"Supported: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}"
            )

        # Validate output format
        if output_format not in ["hex", "base64"]:
            raise ValueError(
                f"Unsupported output format '{output_format}'. Supported: 'hex', 'base64'"
            )

        # Create hash object
        hasher = self.SUPPORTED_ALGORITHMS[algorithm]()

        # Read file in chunks to handle large files efficiently
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                hasher.update(chunk)

        # Get hash digest
        if output_format == "hex":
            digest = hasher.hexdigest()
        else:  # base64
            digest = base64.b64encode(hasher.digest()).decode("utf-8")

        return {
            "algorithm": algorithm,
            "digest": digest,
            "format": output_format,
        }

    def compute_multiple_hashes(
        self,
        file_path: Path,
        algorithms: list[str] | None = None,
        output_format: str = "hex",
        chunk_size: int = 8192,
    ) -> dict[str, dict[str, str]]:
        """
        Compute multiple hashes for a file in a single pass.

        Args:
            file_path: Path to the file
            algorithms: List of algorithms to use (default: all supported)
            output_format: Output format ('hex' or 'base64')
            chunk_size: Size of chunks to read (bytes)

        Returns:
            Dictionary mapping algorithm names to hash information

        Raises:
            ValueError: If any algorithm or format is not supported
            IOError: If file cannot be read
        """
        # Use all supported algorithms if none specified
        if algorithms is None:
            algorithms = list(self.SUPPORTED_ALGORITHMS.keys())

        # Validate algorithms
        for algorithm in algorithms:
            if algorithm not in self.SUPPORTED_ALGORITHMS:
                raise ValueError(
                    f"Unsupported algorithm '{algorithm}'. "
                    f"Supported: {', '.join(self.SUPPORTED_ALGORITHMS.keys())}"
                )

        # Validate output format
        if output_format not in ["hex", "base64"]:
            raise ValueError(
                f"Unsupported output format '{output_format}'. Supported: 'hex', 'base64'"
            )

        # Create hash objects for all algorithms
        hashers = {algorithm: self.SUPPORTED_ALGORITHMS[algorithm]() for algorithm in algorithms}

        # Read file once and update all hashers
        with open(file_path, "rb") as f:
            while chunk := f.read(chunk_size):
                for hasher in hashers.values():
                    hasher.update(chunk)

        # Get all digests
        results = {}
        for algorithm, hasher in hashers.items():
            if output_format == "hex":
                digest = hasher.hexdigest()
            else:  # base64
                digest = base64.b64encode(hasher.digest()).decode("utf-8")

            results[algorithm] = {
                "algorithm": algorithm,
                "digest": digest,
                "format": output_format,
            }

        return results

    def hash_file_with_info(
        self,
        path: str,
        algorithms: list[str] | None = None,
        output_format: str = "hex",
        include_file_info: bool = True,
    ) -> dict[str, Any]:
        """
        Compute hash(es) for a file with optional file information.

        Args:
            path: Path to the file
            algorithms: List of algorithms to use (None for all)
            output_format: Output format ('hex' or 'base64')
            include_file_info: Whether to include file information

        Returns:
            Dictionary containing hash results and optional file info

        Raises:
            Exception: Various exceptions for validation and I/O errors
        """
        try:
            # Validate and resolve path
            # Allow absolute paths when workspace is configured as absolute
            allow_absolute = self.security.workspace_dir.is_absolute()
            file_path = self.security.validate_path(path, allow_absolute=allow_absolute)

            # Check if file exists
            if not file_path.exists():
                raise FileNotFoundError(f"File not found: {path}")

            if not file_path.is_file():
                raise ValueError(f"Path is not a file: {path}")

            # Validate file size
            self.security.validate_file_size(file_path)

            # Compute hashes
            if algorithms is None or len(algorithms) == 1:
                # Single algorithm (use default sha256 if none specified)
                algorithm = algorithms[0] if algorithms else "sha256"
                hash_result = self.compute_file_hash(file_path, algorithm, output_format)
                hashes = {algorithm: hash_result}
            else:
                # Multiple algorithms
                hashes = self.compute_multiple_hashes(file_path, algorithms, output_format)

            # Prepare response
            response_data = {
                "path": str(file_path),
                "hashes": hashes,
                "algorithms_used": list(hashes.keys()),
                "output_format": output_format,
            }

            # Add file information if requested
            if include_file_info:
                stat = file_path.stat()
                response_data["file_info"] = {
                    "name": file_path.name,
                    "size": stat.st_size,
                    "size_human": format_file_size(stat.st_size),
                    "modified": stat.st_mtime,
                }

            return create_success_response(
                response_data,
                "hash_file",
                f"Successfully computed {len(hashes)} hash(es) for file",
            )

        except Exception as e:
            return create_error_response(e, "hash_file")
