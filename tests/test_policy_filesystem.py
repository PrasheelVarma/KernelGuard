"""
Unit tests for KernelGuard policy filesystem path matching and filename hashing.
"""

import tempfile
import unittest
from pathlib import Path

from kernelguard.controller import ExecveController
from kernelguard.policy import Policy


class TestPolicyFilesystem(unittest.TestCase):
    """Test suite for filesystem policy path evaluation and filename hashing."""

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.allowed_file_1 = Path(self.temp_dir.name) / "allowed_one.txt"
        self.allowed_file_2 = Path(self.temp_dir.name) / "allowed_two.txt"
        self.allowed_dir = Path(self.temp_dir.name) / "allowed_dir"
        self.denied_file = Path(self.temp_dir.name) / "unauthorized.txt"

        self.allowed_dir.mkdir(parents=True, exist_ok=True)

        self.policy_file = Path(self.temp_dir.name) / "test_policy.json"
        self.policy_file.write_text(
            f"""{{
  "network": {{ "allowed_ips": ["1.1.1.1"] }},
  "filesystem": {{
    "allowed_paths": [
      "{self.allowed_file_1}",
      "{self.allowed_file_2}",
      "{self.allowed_dir}"
    ]
  }}
}}""",
            encoding="utf-8",
        )

        self.policy = Policy(self.policy_file)

    def test_exact_path_match(self) -> None:
        """Verify exact allowed file path evaluates to True."""
        self.assertTrue(self.policy.is_path_allowed(str(self.allowed_file_1)))
        self.assertTrue(self.policy.is_path_allowed(str(self.allowed_file_2)))

    def test_non_existent_allowed_file_path_match(self) -> None:
        """Verify policy allows file paths that do not exist yet on disk."""
        future_file = Path(self.temp_dir.name) / "allowed_one.txt"
        self.assertFalse(future_file.exists())
        self.assertTrue(self.policy.is_path_allowed(str(future_file)))

    def test_denied_file_path(self) -> None:
        """Verify unauthorized file path evaluates to False."""
        self.assertFalse(self.policy.is_path_allowed(str(self.denied_file)))

    def test_directory_prefix_match(self) -> None:
        """Verify files inside an allowed directory evaluate to True."""
        subfile = self.allowed_dir / "sub_output.log"
        self.assertTrue(self.policy.is_path_allowed(str(subfile)))

    def test_trace_fragment_basename_match(self) -> None:
        """Verify relative trace path fragments (e.g. 'allowed_one.txt') match policy."""
        self.assertTrue(self.policy.is_path_allowed("allowed_one.txt"))
        self.assertTrue(self.policy.is_path_allowed("allowed_two.txt"))
        self.assertFalse(self.policy.is_path_allowed("unauthorized.txt"))

    def test_filename_hash_equivalence(self) -> None:
        """Verify Controller._hash_filename produces deterministic djb2 hashes."""
        h1 = ExecveController._hash_filename("kernelguard-test.txt")
        h2 = ExecveController._hash_filename("kernelguard-test.txt")
        h3 = ExecveController._hash_filename("other.txt")

        self.assertEqual(h1, h2)
        self.assertNotEqual(h1, h3)
        self.assertIsInstance(h1, int)
        self.assertTrue(0 <= h1 <= 0xFFFFFFFFFFFFFFFF)


if __name__ == "__main__":
    unittest.main()
