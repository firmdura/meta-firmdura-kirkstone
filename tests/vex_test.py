#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Unit tests for OpenVEX v0.2.0 schema validation and Grype positive/negative control verification."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "vex"))
import generate_openvex as gov


def _sample_manifest(name: str, sha: str) -> dict:
    return {
        "output": {
            "root_source_package": {
                "name": name,
                "rootfs_sha256": sha,
                "grype_openvex_product_purl": f"pkg:generic/{name}@1.0-sha256.{sha}",
            }
        }
    }


def _sample_grype(active_target: bool, ignored_target: bool, db_from: str = "aux") -> dict:
    pkgs = ["libwebsockets18", "libwebsockets-evlib-uv", "libwebsockets-testapps"]
    matches = [{"vulnerability": {"id": "CVE-2025-1866"}, "artifact": {"name": "libwebsockets18"}}]
    ignored = []
    if active_target:
        for p in pkgs:
            matches.append({"vulnerability": {"id": "CVE-2026-19773"}, "artifact": {"name": p}})
    if ignored_target:
        for p in pkgs:
            ignored.append({
                "vulnerability": {"id": "CVE-2026-19773"},
                "artifact": {"name": p},
                "appliedIgnoreRules": [{"namespace": "vex", "vex-status": "fixed"}],
            })
    return {
        "descriptor": {"version": "0.122.0", "db": {"status": {"from": db_from, "built": "2026-11-18T06:21:08Z"}}},
        "matches": matches,
        "ignoredMatches": ignored,
    }


class OpenVexTests(unittest.TestCase):
    def test_generate_and_schema_guards(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            bm = base / "b.json"
            pm = base / "p.json"
            bm.write_text(json.dumps(_sample_manifest("img-base", "a" * 64)))
            pm.write_text(json.dumps(_sample_manifest("img-patch", "b" * 64)))
            doc = gov.build_openvex_document(
                baseline_manifest_path=bm,
                patched_manifest_path=pm,
                document_id="https://github.com/firmdura/meta-firmdura-kirkstone/vex/test-v1",
                timestamp="2026-11-18T14:50:00Z",
                evidence_url="https://example.invalid/run.json",
            )
            self.assertTrue(gov.validate_openvex_v020(doc))

            # Missing action_statement on affected must fail
            bad = json.loads(json.dumps(doc))
            del bad["statements"][1]["action_statement"]
            with self.assertRaises(gov.OpenVexError):
                gov.validate_openvex_v020(bad)

            # Identical baseline and patched PURLs must fail
            with self.assertRaises(gov.OpenVexError):
                gov.build_openvex_document(
                    baseline_manifest_path=bm,
                    patched_manifest_path=bm,
                    document_id="https://github.com/firmdura/meta-firmdura-kirkstone/vex/test-v1",
                    timestamp="2026-11-18T14:50:00Z",
                    evidence_url="https://example.invalid/run.json",
                )

    def test_verify_control_matrix_enforces_negative_control(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            abu = base / "abu.json"; abu.write_text(json.dumps(_sample_grype(True, False)))
            apu = base / "apu.json"; apu.write_text(json.dumps(_sample_grype(True, False)))
            apv = base / "apv.json"; apv.write_text(json.dumps(_sample_grype(False, True)))
            abv_ok = base / "abv_ok.json"; abv_ok.write_text(json.dumps(_sample_grype(True, False)))
            abv_bad = base / "abv_bad.json"; abv_bad.write_text(json.dumps(_sample_grype(False, True)))
            st = base / "stock.json"; st.write_text(json.dumps(_sample_grype(False, False, "stock")))

            res = gov.verify_control_matrix(
                patched_purl="pkg:generic/img-patch@1.0-sha256." + "b" * 64,
                aux_base_unfiltered=abu, aux_patch_unfiltered=apu,
                aux_patch_vex=apv, aux_base_vex=abv_ok,
                stock_base_unfiltered=st, stock_patch_unfiltered=st,
                stock_patch_vex=st, stock_base_vex=st,
            )
            self.assertEqual(res["status"], "verified")

            with self.assertRaises(gov.OpenVexError):
                gov.verify_control_matrix(
                    patched_purl="pkg:generic/img-patch@1.0-sha256." + "b" * 64,
                    aux_base_unfiltered=abu, aux_patch_unfiltered=apu,
                    aux_patch_vex=apv, aux_base_vex=abv_bad,
                    stock_base_unfiltered=st, stock_patch_unfiltered=st,
                    stock_patch_vex=st, stock_base_vex=st,
                )


if __name__ == "__main__":
    unittest.main()
