import os
import tempfile
import unittest
from pathlib import Path

from config.settings import Settings, load_settings, save_settings, validate_settings


class SettingsTests(unittest.TestCase):
    def test_defaults_are_valid(self):
        _, errors = validate_settings(Settings().to_dict())
        self.assertEqual(errors, [])

    def test_limits_enforced(self):
        for key, bad in (("timeout", 0), ("timeout", 999), ("max_body_kb", 10**7), ("max_requests", 10**6),
                         ("request_delay", 0.0), ("request_delay", "abc")):
            with self.subTest(key=key, bad=bad):
                s, errors = validate_settings({**Settings().to_dict(), key: bad})
                self.assertTrue(errors)
                self.assertEqual(getattr(s, key), getattr(Settings(), key))   # falls back to the safe default

    def test_user_agent_and_theme_and_dir(self):
        _, e = validate_settings({**Settings().to_dict(), "user_agent": "bad\r\nX-Injected: 1"})
        self.assertTrue(e)
        _, e = validate_settings({**Settings().to_dict(), "theme": "neon"})
        self.assertTrue(e)
        _, e = validate_settings({**Settings().to_dict(), "export_dir": "/definitely/not/here"})
        self.assertTrue(e)

    def test_save_and_load_roundtrip_and_corrupt_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "settings.json"
            save_settings(Settings(timeout=5.0, theme="dark"), p)
            self.assertEqual((load_settings(p).timeout, load_settings(p).theme), (5.0, "dark"))
            p.write_text("{not json")
            self.assertEqual(load_settings(p), Settings())


if __name__ == "__main__":
    unittest.main()
