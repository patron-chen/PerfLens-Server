"""Unit tests for activation_server.setup."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest

from activation_server.setup import (
    apply_mirror,
    normalize_arch,
    verify_sha256,
    is_python_313,
    main as setup_main,
)


class SetupTests(unittest.TestCase):
    def test_normalize_arch(self):
        self.assertEqual(normalize_arch("AMD64"), "x86_64")
        self.assertEqual(normalize_arch("x86_64"), "x86_64")
        self.assertEqual(normalize_arch("x64"), "x86_64")
        self.assertEqual(normalize_arch("aarch64"), "aarch64")

    def test_apply_mirror(self):
        base_url = "https://github.com/astral-sh/python-build-standalone/releases/download/test.tar.gz"
        # No mirror
        self.assertEqual(apply_mirror(base_url, None), base_url)
        self.assertEqual(apply_mirror(base_url, ""), base_url)

        # Prefix mirror with trailing slash
        mirror_prefix = "https://ghproxy.net/"
        self.assertEqual(apply_mirror(base_url, mirror_prefix), f"{mirror_prefix}{base_url}")

        # Prefix mirror without trailing slash (detected via 'proxy')
        mirror_prefix_no_slash = "https://ghproxy.net"
        self.assertEqual(apply_mirror(base_url, mirror_prefix_no_slash), f"{mirror_prefix_no_slash}/{base_url}")

        # Domain replace mirror
        mirror_domain = "https://hub.fastgit.xyz"
        expected = base_url.replace("https://github.com", mirror_domain)
        self.assertEqual(apply_mirror(base_url, mirror_domain), expected)

    def test_verify_sha256(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            temp_path = Path(handle.name)
            content = b"PerfLens activation server setup test data\n"
            handle.write(content)
        try:
            expected_hash = hashlib.sha256(content).hexdigest()
            self.assertTrue(verify_sha256(temp_path, expected_hash))
            self.assertTrue(verify_sha256(temp_path, expected_hash.upper()))
            self.assertFalse(verify_sha256(temp_path, "0" * 64))
            self.assertFalse(verify_sha256(temp_path / "nonexistent", expected_hash))
        finally:
            temp_path.unlink(missing_ok=True)

    def test_is_python_313_handles_invalid_interpreters(self):
        self.assertFalse(is_python_313("non_existent_python_binary_xyz_123"))
        self.assertFalse(is_python_313(Path("C:/non/existent/path/python.exe")))

    def test_setup_help_exits_cleanly(self):
        with self.assertRaises(SystemExit) as exit_check:
            setup_main(["--help"])
        self.assertEqual(exit_check.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
