"""
Unit tests for KernelGuard controller signal handling and graceful cleanup.
"""

import signal
import unittest
from unittest.mock import MagicMock, patch

from kernelguard.controller import ExecveController, BPFLoadError


class TestControllerCleanup(unittest.TestCase):
    """Test suite for controller signal handling and eBPF cleanup mechanism."""

    def setUp(self) -> None:
        self.mock_logger = MagicMock()
        self.controller = ExecveController(logger=self.mock_logger)

    def test_initial_state(self) -> None:
        """Verify initial controller cleanup attributes."""
        self.assertIsNone(self.controller.bpf)
        self.assertEqual(self.controller.attached_kprobes, [])
        self.assertFalse(self.controller.running)

    def test_cleanup_with_no_bpf(self) -> None:
        """Verify cleanup execution when BPF is not loaded does not raise error."""
        self.controller.cleanup()
        self.assertIsNone(self.controller.bpf)
        self.assertEqual(self.controller.attached_kprobes, [])

    def test_cleanup_detaches_kprobes_and_calls_bpf_cleanup(self) -> None:
        """Verify cleanup detaches all registered kprobes and frees BPF resources."""
        mock_bpf = MagicMock()
        self.controller.bpf = mock_bpf
        self.controller.attached_kprobes = ["sys_execve", "tcp_connect", "vfs_write"]

        self.controller.cleanup()

        self.assertEqual(mock_bpf.detach_kprobe.call_count, 3)
        mock_bpf.detach_kprobe.assert_any_call(event="sys_execve")
        mock_bpf.detach_kprobe.assert_any_call(event="tcp_connect")
        mock_bpf.detach_kprobe.assert_any_call(event="vfs_write")
        mock_bpf.cleanup.assert_called_once()
        self.assertIsNone(self.controller.bpf)
        self.assertEqual(self.controller.attached_kprobes, [])

    def test_cleanup_handles_detach_exceptions_gracefully(self) -> None:
        """Verify individual kprobe detachment failures do not prevent full cleanup."""
        mock_bpf = MagicMock()
        mock_bpf.detach_kprobe.side_effect = Exception("Detach error")
        self.controller.bpf = mock_bpf
        self.controller.attached_kprobes = ["sys_execve"]

        self.controller.cleanup()

        mock_bpf.cleanup.assert_called_once()
        self.assertIsNone(self.controller.bpf)
        self.assertEqual(self.controller.attached_kprobes, [])

    def test_setup_signal_handlers(self) -> None:
        """Verify signal handlers are set up for SIGINT and SIGTERM."""
        with patch("signal.signal") as mock_signal:
            self.controller.setup_signal_handlers()

            calls = [call[0][0] for call in mock_signal.call_args_list]
            self.assertIn(signal.SIGINT, calls)
            self.assertIn(signal.SIGTERM, calls)

    def test_context_manager_protocol(self) -> None:
        """Verify context manager enters and exits cleanly."""
        with patch.object(self.controller, "load") as mock_load, \
             patch.object(self.controller, "cleanup") as mock_cleanup:

            with self.controller as ctrl:
                self.assertEqual(ctrl, self.controller)
                mock_load.assert_called_once()

            mock_cleanup.assert_called_once()


if __name__ == "__main__":
    unittest.main()
