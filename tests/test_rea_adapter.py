"""REA integration tests: no external CLI, binaries or network required."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

from reverselab.rea_adapter import analyze, status, REAError


class REATests(unittest.TestCase):
    def test_unavailable(self):
        with patch("reverselab.rea_adapter.shutil.which", return_value=None):
            self.assertFalse(status()["available"])
            with tempfile.TemporaryDirectory() as d:
                with self.assertRaises(REAError):
                    analyze(d)

    def test_validates_mode(self):
        with self.assertRaises(ValueError):
            analyze("/anything", mode="execute")

    def test_calls_static_cli_without_shell(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Mock(returncode=0, stdout=json.dumps({"evidence": []}), stderr="")
            with patch("reverselab.rea_adapter.shutil.which", return_value="/bin/rea"), patch("reverselab.rea_adapter.subprocess.run", return_value=fake) as run:
                result = analyze(d)
            self.assertEqual(result["engine"], "rea")
            args, kwargs = run.call_args
            self.assertEqual(args[0][1], "analyze-javascript-application")
            self.assertEqual(kwargs["shell"], False)
            self.assertEqual(kwargs["timeout"], 120)

    def test_bad_json(self):
        with tempfile.TemporaryDirectory() as d:
            fake = Mock(returncode=0, stdout="bad", stderr="")
            with patch("reverselab.rea_adapter.shutil.which", return_value="/bin/rea"), patch("reverselab.rea_adapter.subprocess.run", return_value=fake):
                with self.assertRaises(REAError):
                    analyze(d)

    def test_timeout_limit(self):
        with self.assertRaises(ValueError):
            analyze("/anything", timeout=900)


if __name__ == "__main__":
    unittest.main()
