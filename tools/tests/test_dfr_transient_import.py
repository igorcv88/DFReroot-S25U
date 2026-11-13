#!/usr/bin/env python3
"""Regression for the transient importer's positive build-ID binding."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from import_dfr_transient_owo import require_build_ids


class BuildIdContractTest(unittest.TestCase):
    def setUp(self):
        self.provenance = {
            "ksud_build_id": "a" * 40,
            "module_build_id": "b" * 40,
        }
        self.contract = dict(self.provenance)

    def test_valid_pair(self):
        require_build_ids(self.provenance, self.contract)

    def test_missing_on_both_sides_does_not_pass_none_equals_none(self):
        for field in ("ksud_build_id", "module_build_id"):
            with self.subTest(field=field):
                prov, contract = dict(self.provenance), dict(self.contract)
                del prov[field]
                del contract[field]
                with self.assertRaisesRegex(RuntimeError, "absent or malformed"):
                    require_build_ids(prov, contract)

    def test_bad_or_empty_build_id(self):
        for bad in ("", "0" * 39, "0" * 41, "G" * 40, None):
            with self.subTest(value=bad):
                prov, contract = dict(self.provenance), dict(self.contract)
                prov["ksud_build_id"] = bad
                contract["ksud_build_id"] = bad
                with self.assertRaisesRegex(RuntimeError, "absent or malformed"):
                    require_build_ids(prov, contract)

    def test_mismatched_valid_build_ids(self):
        for field in ("ksud_build_id", "module_build_id"):
            with self.subTest(field=field):
                contract = dict(self.contract)
                contract[field] = "c" * 40
                with self.assertRaisesRegex(RuntimeError, "does not match"):
                    require_build_ids(self.provenance, contract)


if __name__ == "__main__":
    unittest.main()
