#!/usr/bin/env python3
"""Local contract/orchestration tests. Mocked Cosign calls are NOT OIDC evidence."""

import copy
import json
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import warnings
import zipfile


TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent / "scripts" / "release"))
import approval
import verify


FIXTURE = TESTS / "release-fixtures" / "unsigned"


class ReleaseTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="release-tests-", dir=TESTS)
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self.root = self.base / "candidate"
        shutil.copytree(FIXTURE, self.root)
        self.expected = {
            "manifest_sha256": verify.file_digest(self.root / verify.MANIFEST),
            "kind": "fixture", "release_id": "sti111-keyless-fixture",
            "source_commit": "44210974feddea19687ea2d7466f99f45d43588b",
        }

    def check(self, signed=False):
        return verify.check_assets(self.root, signed=signed, **self.expected)

    def rewrite_manifest(self, change):
        path = self.root / verify.MANIFEST
        document = json.loads(path.read_bytes())
        change(document)
        path.write_text(json.dumps(document))
        self.expected["manifest_sha256"] = verify.file_digest(path)

    def fake_bundle(self):
        (self.root / verify.BUNDLE).write_text('{"test_only":"NOT A SIGSTORE SIGNATURE"}\n')

    def archive(self, extra=()):
        path = self.base / "candidate.zip"
        with zipfile.ZipFile(path, "w") as output:
            for source in sorted(self.root.rglob("*")):
                if source.is_file():
                    output.write(source, source.relative_to(self.root).as_posix())
            for name, data in extra:
                output.writestr(name, data)
        return path

    def test_labelled_fixture_bytes_and_manifest_are_valid_without_authenticity_claim(self):
        self.assertEqual(self.check()["release"]["kind"], "fixture")

    def test_changed_manifest_bytes_fail_even_if_json_meaning_is_unchanged(self):
        with (self.root / verify.MANIFEST).open("ab") as stream:
            stream.write(b"\n")
        with self.assertRaisesRegex(verify.InvalidRelease, "approved manifest SHA-256 mismatch"):
            self.check()

    def test_changed_payload_same_size_fails_digest(self):
        path = self.root / "payloads" / "fixture.txt"
        path.write_bytes(b"X" * path.stat().st_size)
        with self.assertRaisesRegex(verify.InvalidRelease, "payload SHA-256 mismatch"):
            self.check()

    def test_changed_payload_size_fails(self):
        (self.root / "payloads" / "fixture.txt").write_bytes(b"truncated")
        with self.assertRaisesRegex(verify.InvalidRelease, "payload size mismatch"):
            self.check()

    def test_missing_payload_fails(self):
        (self.root / "payloads" / "fixture.txt").unlink()
        with self.assertRaisesRegex(verify.InvalidRelease, "asset set mismatch: missing="):
            self.check()

    def test_unsigned_file_and_empty_directory_each_fail(self):
        path = self.root / "extra.txt"
        path.write_text("unsigned")
        with self.assertRaisesRegex(verify.InvalidRelease, "asset set mismatch"):
            self.check()
        path.unlink()
        (self.root / "empty").mkdir()
        with self.assertRaisesRegex(verify.InvalidRelease, "unsigned or missing asset directories"):
            self.check()

    def test_extra_manifest_entry_fails(self):
        self.rewrite_manifest(lambda doc: doc["artifacts"].append({
            **doc["artifacts"][0], "path": "missing.txt",
        }))
        with self.assertRaisesRegex(verify.InvalidRelease, "asset set mismatch"):
            self.check()

    def test_manifest_and_bundle_cannot_be_payloads(self):
        for name in (verify.MANIFEST, verify.BUNDLE):
            with self.subTest(path=name):
                self.rewrite_manifest(lambda doc: doc["artifacts"][0].update(path=name))
                with self.assertRaisesRegex(verify.InvalidRelease, "cannot list itself"):
                    self.check()

    def test_duplicate_keys_and_paths_fail(self):
        path = self.root / verify.MANIFEST
        raw = path.read_bytes()
        path.write_bytes(raw.replace(b'"schema_version": 1', b'"schema_version": 1, "schema_version": 1'))
        self.expected["manifest_sha256"] = verify.file_digest(path)
        with self.assertRaisesRegex(verify.InvalidRelease, "duplicate JSON key"):
            self.check()
        path.write_bytes(raw)
        self.rewrite_manifest(lambda doc: doc["artifacts"].append(copy.deepcopy(doc["artifacts"][0])))
        with self.assertRaisesRegex(verify.InvalidRelease, "duplicate asset path"):
            self.check()

    def test_ambiguous_paths_are_rejected_before_filesystem_access(self):
        for path in ("../x", "/absolute", "a/../x", "a//b", "./x", "a\\b", "a/",
                     "a/./b", ".hidden", "a\nb", "A:b", "x.", "con.txt", "café"):
            with self.subTest(path=path), self.assertRaises(verify.InvalidRelease):
                verify.normalized_path(path)
        for names in (["Payloads/a", "payloads/b"], ["x", "X"], ["a", "a/b"]):
            with self.subTest(paths=names), self.assertRaises(verify.InvalidRelease):
                verify.path_set(names)

    def test_file_and_directory_symlinks_fail(self):
        payload = self.root / "payloads" / "fixture.txt"
        payload.unlink()
        payload.symlink_to(FIXTURE / "payloads" / "fixture.txt")
        with self.assertRaisesRegex(verify.InvalidRelease, "non-regular asset"):
            self.check()
        payload.unlink()
        payload.parent.rmdir()
        payload.parent.symlink_to(FIXTURE / "payloads", target_is_directory=True)
        with self.assertRaisesRegex(verify.InvalidRelease, "non-regular asset"):
            self.check()

    def test_fixture_cannot_be_verified_as_release_or_another_source(self):
        for key, value in (("kind", "release"), ("release_id", "v1.0.0"),
                           ("source_commit", "a" * 40)):
            with self.subTest(key=key):
                expected = {**self.expected, key: value}
                with self.assertRaises(verify.InvalidRelease):
                    verify.check_assets(self.root, signed=False, **expected)

    def test_strict_schema_types_and_unknown_fields(self):
        original = (self.root / verify.MANIFEST).read_bytes()
        changes = (
            lambda doc: doc.update(schema_version=True),
            lambda doc: doc.update(unsigned_extension="not allowed"),
            lambda doc: doc["source"].update(repository="https://github.com/another/repo"),
            lambda doc: doc["artifacts"][0].update(size=True),
            lambda doc: doc["artifacts"][0].update(size=-1),
            lambda doc: doc["artifacts"][0].update(sha256="A" * 64),
            lambda doc: doc["artifacts"][0].update(variant="unreviewed"),
            lambda doc: doc["artifacts"][0].update(role=""),
            lambda doc: doc.update(artifacts=[]),
        )
        for change in changes:
            with self.subTest(change=change):
                (self.root / verify.MANIFEST).write_bytes(original)
                self.rewrite_manifest(change)
                with self.assertRaises(verify.InvalidRelease):
                    self.check()

    def test_signed_and_unsigned_asset_sets_are_distinct(self):
        with self.assertRaisesRegex(verify.InvalidRelease, "asset set mismatch"):
            self.check(signed=True)
        self.fake_bundle()
        with self.assertRaisesRegex(verify.InvalidRelease, "asset set mismatch"):
            self.check()

    def test_cosign_orchestration_pins_exact_identity_and_issuer(self):
        self.fake_bundle()
        version = subprocess.CompletedProcess([], 0, '{"gitVersion":"v3.1.4"}')
        with patch.object(verify.subprocess, "run", side_effect=[
            version, subprocess.CompletedProcess([], 0),
        ]) as run:
            verify.verify_assets(self.root, **self.expected)
        self.assertEqual(run.call_args.args[0], [
            "cosign", "verify-blob", "--bundle", str(self.root / verify.BUNDLE),
            "--certificate-identity",
            "https://github.com/firmdura/meta-firmdura-kirkstone/.github/workflows/release.yml@refs/heads/main",
            "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
            str(self.root / verify.MANIFEST),
        ])
        self.assertIs(run.call_args.kwargs["check"], True)

    def test_cosign_identity_and_issuer_failures_are_not_swallowed(self):
        self.fake_bundle()
        for reason in ("wrong certificate identity", "wrong certificate issuer"):
            with self.subTest(reason=reason), patch.object(verify.subprocess, "run", side_effect=[
                subprocess.CompletedProcess([], 0, '{"gitVersion":"v3.1.4"}'),
                subprocess.CalledProcessError(1, ["cosign", "verify-blob"], stderr=reason),
            ]):
                with self.assertRaises(subprocess.CalledProcessError):
                    verify.verify_assets(self.root, **self.expected)

    def test_cosign_missing_and_wrong_version_fail(self):
        self.fake_bundle()
        with self.assertRaises(FileNotFoundError):
            verify.verify_assets(self.root, str(self.base / "nonexistent-cosign"), **self.expected)
        with patch.object(verify.subprocess, "run", return_value=subprocess.CompletedProcess(
                [], 0, '{"gitVersion":"v0.0.0"}')):
            with self.assertRaisesRegex(verify.InvalidRelease, "Cosign v3.1.4 is required"):
                verify.verify_assets(self.root, **self.expected)

    def test_mutation_during_cosign_is_detected(self):
        self.fake_bundle()

        def cosign(command, **kwargs):
            if command[1] == "version":
                return subprocess.CompletedProcess(command, 0, '{"gitVersion":"v3.1.4"}')
            (self.root / "extra.txt").write_text("changed while verifying")
            return subprocess.CompletedProcess(command, 0)

        with patch.object(verify.subprocess, "run", side_effect=cosign):
            with self.assertRaisesRegex(verify.InvalidRelease, "asset set mismatch"):
                verify.verify_assets(self.root, **self.expected)

    def test_zip_preserves_frozen_manifest_and_payload(self):
        destination = self.base / "unpacked"
        verify.unpack(self.archive(), destination, **self.expected)
        for source in (self.root / verify.MANIFEST, self.root / "payloads" / "fixture.txt"):
            self.assertEqual(source.read_bytes(), (destination / source.relative_to(self.root)).read_bytes())

    def test_zip_rejects_unsafe_extra_duplicate_and_symlink_members_before_writing(self):
        symlink = zipfile.ZipInfo("link")
        symlink.create_system = 3
        symlink.external_attr = (stat.S_IFLNK | 0o777) << 16
        for extra in (
            [("../outside", b"bad")], [("/absolute", b"bad")],
            [("unsigned", b"extra")], [(verify.MANIFEST, b"duplicate")],
            [(symlink, b"payloads/fixture.txt")],
        ):
            with self.subTest(extra=extra), warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                destination = self.base / "unpacked"
                with self.assertRaises(verify.InvalidRelease):
                    verify.unpack(self.archive(extra), destination, **self.expected)
                self.assertFalse(destination.exists())
                self.assertFalse((self.base / "outside").exists())

    def test_zip_rejects_preexisting_destination_and_signed_input(self):
        with self.assertRaisesRegex(verify.InvalidRelease, "must not already exist"):
            verify.unpack(self.archive(), self.root, **self.expected)
        self.fake_bundle()
        with self.assertRaisesRegex(verify.InvalidRelease, "ZIP asset set mismatch"):
            verify.unpack(self.archive(), self.base / "unpacked", **self.expected)

    def github_candidate(self):
        (self.root / "payloads" / "fixture.txt").rename(self.root / "fixture.txt")
        (self.root / "payloads").rmdir()
        self.expected.update(kind="release", release_id="v0.0.0-test")

        def flat_manifest(document):
            document["artifacts"][0]["path"] = "fixture.txt"
            document["release"] = {"kind": "release", "id": "v0.0.0-test"}

        self.rewrite_manifest(flat_manifest)
        self.fake_bundle()
        return {
            "release_id": 123,
            "assets": {path.name: {"id": index, "size": path.stat().st_size}
                       for index, path in enumerate(sorted(self.root.iterdir()))},
        }

    def test_github_requires_complete_download_not_a_filtered_subset(self):
        snapshot = self.github_candidate()
        destination = self.base / "download"

        def incomplete_download(*args, **kwargs):
            shutil.copytree(self.root, destination)
            (destination / "fixture.txt").unlink()

        with patch.object(verify, "release_snapshot", return_value=snapshot):
            with patch.object(verify.subprocess, "run", side_effect=incomplete_download):
                with self.assertRaisesRegex(verify.InvalidRelease, "complete GitHub asset set"):
                    verify.verify_github_release(destination, **self.expected)

    def test_github_rejects_unsigned_remote_asset_before_cosign(self):
        snapshot = self.github_candidate()
        (self.root / "unsigned.txt").write_text("not in manifest")
        snapshot["assets"]["unsigned.txt"] = {"id": 99, "size": 15}
        destination = self.base / "download"
        with patch.object(verify, "release_snapshot", return_value=snapshot):
            with patch.object(verify.subprocess, "run", side_effect=lambda *a, **k:
                              shutil.copytree(self.root, destination)) as run:
                with self.assertRaisesRegex(verify.InvalidRelease, "asset set mismatch"):
                    verify.verify_github_release(destination, **self.expected)
                self.assertEqual(run.call_count, 1)

    def test_github_detects_remote_asset_changes_during_verification(self):
        snapshot = self.github_candidate()
        changed = copy.deepcopy(snapshot)
        changed["assets"]["fixture.txt"]["id"] = 999
        destination = self.base / "download"
        with patch.object(verify, "release_snapshot", side_effect=[snapshot, changed]):
            with patch.object(verify.subprocess, "run", side_effect=lambda *a, **k:
                              shutil.copytree(self.root, destination)):
                with patch.object(verify, "verify_assets", return_value={}):
                    with self.assertRaisesRegex(verify.InvalidRelease, "changed during verification"):
                        verify.verify_github_release(destination, **self.expected)

    def test_github_snapshot_reads_all_asset_pages(self):
        release = {"id": 123, "tag_name": "v0.0.0-test", "draft": False}
        pages = [[{"id": 1, "name": "manifest.json"}], [{"id": 2, "name": "extra.txt"}]]
        with patch.object(verify.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0, json.dumps(release)),
            subprocess.CompletedProcess([], 0, json.dumps(pages)),
        ]) as run:
            snapshot = verify.release_snapshot("v0.0.0-test")
        self.assertEqual(set(snapshot["assets"]), {"manifest.json", "extra.txt"})
        self.assertIn("--paginate", run.call_args.args[0])
        self.assertIn("--slurp", run.call_args.args[0])

    def test_draft_stage_download_accepts_single_unsigned_draft_and_rejects_signed_or_published(self):
        snapshot = self.github_candidate()
        (self.root / verify.BUNDLE).unlink()
        del snapshot["assets"][verify.BUNDLE]
        dest = self.base / "staged"
        with patch.object(verify, "draft_release_snapshot", return_value=snapshot):
            with patch.object(verify.subprocess, "run", side_effect=lambda *a, **k:
                              shutil.copytree(self.root, dest)):
                doc = verify.stage_download(dest, **self.expected)
        self.assertEqual(doc["release"]["id"], "v0.0.0-test")

        signed_snapshot = copy.deepcopy(snapshot)
        signed_snapshot["assets"][verify.BUNDLE] = {"id": 77, "size": 12}
        with patch.object(verify, "draft_release_snapshot", return_value=signed_snapshot):
            with self.assertRaisesRegex(verify.InvalidRelease, "must not already contain a signature bundle"):
                verify.stage_download(self.base / "staged-signed", **self.expected)

        published_pages = [[{"id": 123, "tag_name": "v0.0.0-test", "draft": False}]]
        with patch.object(verify.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, json.dumps(published_pages),
        )):
            with self.assertRaisesRegex(verify.InvalidRelease, "unpublished draft release"):
                verify.draft_release_snapshot("v0.0.0-test")

    def test_verify_draft_release_verifies_complete_signed_draft_before_publication(self):
        snapshot = self.github_candidate()
        dest = self.base / "draft-verified"
        with patch.object(verify, "draft_release_snapshot", return_value=snapshot):
            with patch.object(verify.subprocess, "run", side_effect=lambda *a, **k:
                              shutil.copytree(self.root, dest)):
                with patch.object(verify, "verify_assets", return_value={"release": {"id": "v0.0.0-test"}}) as va:
                    doc = verify.verify_draft_release(dest, **self.expected)
        self.assertEqual(doc["release"]["id"], "v0.0.0-test")
        va.assert_called_once()


class ApprovalTests(unittest.TestCase):
    def policy(self):
        return {
            "name": "release-signing",
            "protection_rules": [{
                "type": "required_reviewers", "prevent_self_review": True,
                "reviewers": [{"type": "User", "reviewer": {"type": "User", "login": "human"}}],
            }],
            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
        }, {"total_count": 1, "branch_policies": [{"type": "branch", "name": "main"}]}

    def test_human_review_main_only_policy_is_accepted(self):
        for prevent_self_review in (True, False):
            with self.subTest(prevent_self_review=prevent_self_review):
                environment, branches = self.policy()
                environment["protection_rules"][0]["prevent_self_review"] = prevent_self_review
                approval.check_policy(environment, branches)

    def test_missing_bot_or_unrestricted_policies_fail(self):
        changes = (
            lambda env, branches: env.update(protection_rules=[]),
            lambda env, branches: env["protection_rules"][0].update(reviewers=[]),
            lambda env, branches: env["protection_rules"][0]["reviewers"][0]["reviewer"].update(type="Bot"),
            lambda env, branches: env.update(deployment_branch_policy=None),
            lambda env, branches: branches["branch_policies"][0].update(name="*"),
            lambda env, branches: branches["branch_policies"][0].update(type="tag"),
            lambda env, branches: branches.update(total_count=2),
        )
        for change in changes:
            with self.subTest(change=change):
                environment, branches = self.policy()
                change(environment, branches)
                with self.assertRaises(verify.InvalidRelease):
                    approval.check_policy(environment, branches)

    def test_untrusted_workflow_context_fails_before_api_access(self):
        for key, value in (("GITHUB_REPOSITORY", "fork/repo"),
                           ("GITHUB_REF", "refs/pull/1/merge"),
                           ("GITHUB_EVENT_NAME", "pull_request")):
            environment = {
                "GITHUB_REPOSITORY": verify.REPOSITORY, "GITHUB_REF": "refs/heads/main",
                "GITHUB_EVENT_NAME": "workflow_dispatch", key: value,
            }
            with self.subTest(key=key), patch.dict(approval.os.environ, environment, clear=True):
                with patch.object(approval, "github_json") as api:
                    self.assertEqual(approval.main(), 1)
                    api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
