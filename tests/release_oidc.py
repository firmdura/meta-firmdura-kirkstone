#!/usr/bin/env python3
"""Real signed-fixture controls; missing Cosign/bundle is failure, never a skip."""

import argparse
import base64
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent / "scripts" / "release"))
import verify


def command(root, cosign, expected):
    result = [sys.executable, str(Path(verify.__file__)), "verify", "--assets", str(root),
              "--cosign", cosign]
    for key, value in expected.items():
        result.extend([f"--{key.replace('_', '-')}", value])
    return result


def reject(label, argv, reason):
    result = subprocess.run(argv, capture_output=True, text=True, check=False)
    output = result.stdout + result.stderr
    print(f"{label}: exit={result.returncode}\n{output}", flush=True)
    verify.require(result.returncode != 0 and reason in output,
                   f"negative control did not fail for the expected reason: {label}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument("--cosign", default="cosign")
    verify.expectation_arguments(parser)
    args = parser.parse_args()
    expected = verify.expected_from(args)
    verify.require(args.kind == "fixture", "this harness must never claim release validation")
    verify.verify_assets(args.assets, args.cosign, **expected)
    bundle = json.loads((args.assets / verify.BUNDLE).read_bytes())
    certificate = base64.b64decode(
        bundle["verificationMaterial"]["certificate"]["rawBytes"], validate=True)
    san = subprocess.run(
        ["openssl", "x509", "-inform", "DER", "-noout", "-ext", "subjectAltName"],
        input=certificate, capture_output=True, check=True).stdout.decode("utf-8").strip()
    verify.require(f"URI:{verify.IDENTITY}" in san, "unexpected actual certificate SAN")
    print(json.dumps({
        "evidence_kind": "fixture-only-not-a-release",
        "actual_certificate_subject_alt_name": san, "verified_issuer": verify.ISSUER,
        "certificate_der_sha256": verify.digest(certificate),
        "manifest_sha256": expected["manifest_sha256"],
        "bundle_sha256": verify.file_digest(args.assets / verify.BUNDLE),
    }, sort_keys=True), flush=True)
    for flag, wrong in (
        ("--certificate-identity", "https://github.com/invalid/repo/.github/workflows/release.yml@refs/heads/main"),
        ("--certificate-oidc-issuer", "https://invalid.example/issuer"),
    ):
        argv = verify.verification_command(args.cosign, args.assets)
        argv[argv.index(flag) + 1] = wrong
        reject(flag, argv, wrong)
    with tempfile.TemporaryDirectory(prefix="release-oidc-", dir=TESTS) as directory:
        parent = Path(directory)
        for label in ("changed-manifest", "changed-payload", "missing-payload", "unsigned-extra",
                      "mismatched-asset-set"):
            root = parent / label
            shutil.copytree(args.assets, root)
            manifest = root / verify.MANIFEST
            document = json.loads(manifest.read_bytes())
            payload = root / document["artifacts"][0]["path"]
            case_expected = dict(expected)
            if label == "changed-manifest":
                with manifest.open("ab") as stream:
                    stream.write(b"\n")
                # Let Cosign, not only the externally pinned digest, reject these changed bytes.
                case_expected["manifest_sha256"] = verify.file_digest(manifest)
                reason = "failed to verify signature"
            elif label == "changed-payload":
                raw = payload.read_bytes()
                verify.require(bool(raw), "fixture control requires nonempty payload")
                payload.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
                reason = "payload SHA-256 mismatch"
            elif label == "missing-payload":
                payload.unlink()
                reason = "asset set mismatch"
            elif label == "unsigned-extra":
                (root / "unsigned.txt").write_text("not signed")
                reason = "asset set mismatch"
            else:
                payload.rename(payload.with_name("renamed.txt"))
                reason = "asset set mismatch"
            reject(label, command(root, args.cosign, case_expected), reason)
    verify.verify_assets(args.assets, args.cosign, **expected)
    print("PASS: real signed-fixture controls; NOT production release evidence.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
