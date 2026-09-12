"""
Unit tests for KernelGuard CLI 'run' subcommand and execution launcher.
"""

import os
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from kernelguard.cli import build_parser
from kernelguard.controller import ExecveController, ControllerError


class TestCLIRunSubcommand(unittest.TestCase):
    """Test suite for CLI argument parsing for 'run' and 'attach'."""

    def setUp(self) -> None:
        self.parser = build_parser()

    def test_run_subcommand_arguments(self) -> None:
        """Verify parser correctly parses 'run' subcommand arguments."""
        args = self.parser.parse_args(["run", "test_script.py", "arg1", "--flag"])
        self.assertEqual(args.command, "run")
        self.assertEqual(args.script, Path("test_script.py"))
        self.assertEqual(args.script_args, ["arg1", "--flag"])
        self.assertTrue(args.enforce)

    def test_run_subcommand_no_enforce_flag(self) -> None:
        """Verify '--no-enforce' flag disables active enforcement."""
        args = self.parser.parse_args(["run", "--no-enforce", "test_script.py"])
        self.assertEqual(args.command, "run")
        self.assertFalse(args.enforce)

    def test_attach_subcommand_arguments(self) -> None:
        """Verify parser correctly parses 'attach' subcommand arguments."""
        args = self.parser.parse_args(["attach", "--pid", "1234", "--enforce"])
        self.assertEqual(args.command, "attach")
        self.assertEqual(args.pid, 1234)
        self.assertTrue(args.enforce)

    def test_legacy_top_level_arguments(self) -> None:
        """Verify legacy root arguments still work for backward compatibility."""
        args = self.parser.parse_args(["--pid", "5678", "--enforce"])
        self.assertIsNone(args.command)
        self.assertEqual(args.pid, 5678)
        self.assertTrue(args.enforce)


class TestControllerRunScript(unittest.TestCase):
    """Test suite for controller execution launcher logic."""

    def setUp(self) -> None:
        self.mock_logger = MagicMock()
        self.controller = ExecveController(enforce=True, logger=self.mock_logger)

    def test_run_script_nonexistent_file_raises_error(self) -> None:
        """Verify run_script raises ControllerError if script does not exist."""
        nonexistent = Path("/nonexistent/path/script.py")
        with self.assertRaises(ControllerError):
            self.controller.run_script(nonexistent)

    @patch("os.environ", {"SUDO_UID": "1000", "SUDO_GID": "1000", "SUDO_USER": "testuser"})
    @patch("os.setuid")
    @patch("os.setgid")
    @patch("os.setgroups")
    @patch("os.getgrouplist", return_value=[1000, 998])
    def test_drop_privileges(self, mock_getgrouplist, mock_setgroups, mock_setgid, mock_setuid) -> None:
        """Verify _drop_privileges drops to SUDO_UID and SUDO_GID."""
        ExecveController._drop_privileges()
        mock_setgroups.assert_called_once_with([1000, 998])
        mock_setgid.assert_called_once_with(1000)
        mock_setuid.assert_called_once_with(1000)


if __name__ == "__main__":
    unittest.main()
