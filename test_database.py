import os
import tempfile
import unittest

from database.database_manager import DatabaseError, DatabaseManager
from tests.helpers import resp, run_scan


class DatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tmp.name, "scans.db")
        self.db = DatabaseManager(self.path)
        self.result, _ = run_scan({"https://example.test/": resp("https://example.test/")})

    def tearDown(self):
        self.tmp.cleanup()

    def test_save_and_load_scan(self):
        self.db.save_scan(self.result)
        scan = self.db.get_scan(self.result.scan_id)
        self.assertEqual(scan["hostname"], "example.test")
        self.assertEqual(len(scan["findings"]), len(self.result.findings))
        self.assertEqual(self.db.list_scans()[0]["scan_id"], self.result.scan_id)

    def test_update_validation_state_and_note(self):
        self.db.save_scan(self.result)
        fid = self.result.findings[0].finding_id
        self.db.update_validation(self.result.scan_id, fid, "False Positive", "internal test host")
        f = self.db.get_findings(self.result.scan_id)[0]
        self.assertEqual((f["validation_status"], f["user_note"]), ("False Positive", "internal test host"))
        with self.assertRaises(DatabaseError):
            self.db.update_validation(self.result.scan_id, fid, "Exploitable!", "")

    def test_note_secrets_are_redacted(self):
        self.db.save_scan(self.result)
        fid = self.result.findings[0].finding_id
        self.db.update_validation(self.result.scan_id, fid, "Observed", "token=abc123supersecret")
        self.assertNotIn("abc123supersecret", self.db.get_findings(self.result.scan_id)[0]["user_note"])

    def test_stats_delete_and_clear(self):
        self.db.save_scan(self.result)
        stats = self.db.stats()
        self.assertEqual(stats["total_scans"], 1)
        self.assertEqual(stats["total_findings"], len(self.result.findings))
        self.db.delete_scan(self.result.scan_id)
        self.assertIsNone(self.db.get_scan(self.result.scan_id))
        self.db.save_scan(self.result)
        self.db.clear_history()
        self.assertEqual(self.db.stats()["total_scans"], 0)
        self.assertEqual(self.db.stats()["total_findings"], 0)

    def test_allowlist_persistence(self):
        self.db.add_allowlist("example.test")
        self.db.add_allowlist("example.test")
        self.assertEqual(DatabaseManager(self.path).list_allowlist(), ["example.test"])
        self.db.remove_allowlist("example.test")
        self.assertEqual(self.db.list_allowlist(), [])

    def test_corrupted_database_is_recovered(self):
        with open(self.path, "wb") as fh:
            fh.write(b"this is definitely not an sqlite database" * 50)
        db = DatabaseManager(self.path)
        self.assertIsNotNone(db.recovered_from)
        self.assertTrue(os.path.exists(db.recovered_from))
        self.assertEqual(db.stats()["total_scans"], 0)

    def test_missing_database_is_created(self):
        p = os.path.join(self.tmp.name, "sub", "new.db")
        DatabaseManager(p)
        self.assertTrue(os.path.exists(p))


if __name__ == "__main__":
    unittest.main()
