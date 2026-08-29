"""
KernelGuard policy engine.

Loads a JSON policy and evaluates whether network destinations
and filesystem paths are allowed.
"""

import ipaddress
import json
from pathlib import Path
from typing import Any


class PolicyError(Exception):
    """Base exception for policy-related failures."""


class PolicyLoadError(PolicyError):
    """Raised when a policy file cannot be loaded or parsed."""


class PolicyValidationError(PolicyError):
    """Raised when a policy has an invalid structure."""


class Policy:
    """Loads and evaluates KernelGuard allow-list policies."""

    def __init__(self, policy_path: str | Path):
        self.policy_path = Path(policy_path)
        self.network_allowed_ips: set[str] = set()
        self.filesystem_allowed_paths: set[str] = set()

        self._load()

    def _load(self) -> None:
        """Load and validate the JSON policy."""
        if not self.policy_path.exists():
            raise PolicyLoadError(
                f"Policy file not found: {self.policy_path}"
            )

        try:
            with self.policy_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
        except json.JSONDecodeError as exc:
            raise PolicyLoadError(
                f"Invalid JSON in policy file: {exc}"
            ) from exc
        except OSError as exc:
            raise PolicyLoadError(
                f"Unable to read policy file: {exc}"
            ) from exc

        self._validate_and_load(data)

    def _validate_and_load(self, data: Any) -> None:
        """Validate policy structure and populate allow lists."""
        if not isinstance(data, dict):
            raise PolicyValidationError(
                "Policy root must be a JSON object."
            )

        network = data.get("network", {})
        filesystem = data.get("filesystem", {})

        if not isinstance(network, dict):
            raise PolicyValidationError(
                "'network' must be a JSON object."
            )

        if not isinstance(filesystem, dict):
            raise PolicyValidationError(
                "'filesystem' must be a JSON object."
            )

        allowed_ips = network.get("allowed_ips", [])
        allowed_paths = filesystem.get("allowed_paths", [])

        if not isinstance(allowed_ips, list):
            raise PolicyValidationError(
                "'network.allowed_ips' must be a JSON array."
            )

        if not isinstance(allowed_paths, list):
            raise PolicyValidationError(
                "'filesystem.allowed_paths' must be a JSON array."
            )

        for ip in allowed_ips:
            if not isinstance(ip, str):
                raise PolicyValidationError(
                    "Every value in 'network.allowed_ips' must be a string."
                )
            try:
                addr = ipaddress.ip_address(ip)
                if addr.version != 4:
                    raise PolicyValidationError(
                        f"Only IPv4 policy entries are supported: {ip}"
                    )
            except ValueError:
                raise PolicyValidationError(
                    f"Invalid IP address format: {ip}"
                )

        if not all(isinstance(path, str) for path in allowed_paths):
            raise PolicyValidationError(
                "Every value in 'filesystem.allowed_paths' must be a string."
            )

        self.network_allowed_ips = set(allowed_ips)
        self.filesystem_allowed_paths = {
            self._normalize_path(path) for path in allowed_paths
        }

    @staticmethod
    def _normalize_path(path: str) -> str:
        """Normalize a filesystem path for consistent comparisons."""
        return str(Path(path).expanduser().resolve(strict=False))

    def is_ip_allowed(self, ip_address: str) -> bool:
        """Return True when the IP address is explicitly allowed."""
        return ip_address in self.network_allowed_ips

    def is_path_allowed(self, file_path: str) -> bool:
        """Return True when the filesystem path is explicitly allowed."""
        return self._normalize_path(file_path) in self.filesystem_allowed_paths

    def check_network(self, ip_address: str) -> bool:
        """Evaluate a network destination against the policy."""
        return self.is_ip_allowed(ip_address)

    def check_filesystem(self, file_path: str) -> bool:
        """Evaluate a filesystem path against the policy."""
        return self.is_path_allowed(file_path)

    def __repr__(self) -> str:
        return (
            f"Policy("
            f"network_allowed_ips={self.network_allowed_ips!r}, "
            f"filesystem_allowed_paths={self.filesystem_allowed_paths!r}"
            f")"
        )
