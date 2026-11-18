#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Focused unit tests for deterministic QEMU bundle and source redistribution packaging."""

import hashlib
import io
import json
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts" / "bundle"))
import package_bundles as pb


class BundlePackagingTests(unittest.TestCase):
    def test_deterministic_tar_gz_reproducible_and_rejects_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = Path(td) / "a.tar.gz"
            p2 = Path(td) / "b.tar.gz"
            for p in (p1, p2):
                w = pb.DeterministicTarGz(p)
                w.add_bytes("dir/LICENSE.txt", b"upper\n", 0o644)
                w.add_bytes("dir/License.txt", b"mixed\n", 0o644)
                w.close()
            self.assertEqual(p1.read_bytes(), p2.read_bytes())
            with tarfile.open(p1, "r:gz") as tf:
                names = [m.name for m in tf.getmembers()]
            self.assertEqual(names, ["dir/LICENSE.txt", "dir/License.txt"])

            p3 = Path(td) / "bad.tar.gz"
            w = pb.DeterministicTarGz(p3)
            try:
                with self.assertRaises(pb.BundleError):
                    w.add_bytes("../escape.txt", b"no")
            finally:
                w.close()

    def test_host_path_and_secret_guards_fail_closed(self):
        with self.assertRaises(pb.BundleError):
            pb.check_no_host_or_secrets("path-leak", b"cwd=/Users/alice/work")
        with self.assertRaises(pb.BundleError):
            pb.check_no_host_or_secrets("token-leak", b"token=ghp_1234567890abcdefghijklmnop")
        pb.check_no_host_or_secrets("clean", b"portable=1\n")

    def test_launch_script_enforces_nic_none_and_hash_guards(self):
        script = pb.render_launch_sh(
            "bundle", "baseline", "images/Image.bin", "images/rootfs.ext4",
            "a" * 64, "b" * 64,
        ).decode("utf-8")
        self.assertIn("-nic none", script)
        self.assertIn("INTENTIONALLY VULNERABLE BASELINE", script)
        self.assertIn("mktemp -d", script)
        self.assertEqual(script.count("verify_frozen"), 3)

    def test_extract_deploy_members_resolves_tar_hardlinks(self):
        with tempfile.TemporaryDirectory() as td:
            tpath = Path(td) / "sample.tar"
            with tarfile.open(tpath, "w:") as tf:
                first = tarfile.TarInfo("deploy/licenses/pkgA/MIT")
                raw = b"MIT license text\n"
                first.size = len(raw)
                tf.addfile(first, io.BytesIO(raw))
                hard = tarfile.TarInfo("deploy/licenses/pkgB/MIT")
                hard.type = tarfile.LNKTYPE
                hard.linkname = "deploy/licenses/pkgA/MIT"
                tf.addfile(hard)
            out = pb.extract_deploy_members(tpath, lambda n: "pkgB" in n)
            self.assertEqual(out["deploy/licenses/pkgB/MIT"], raw)


if __name__ == "__main__":
    unittest.main()
