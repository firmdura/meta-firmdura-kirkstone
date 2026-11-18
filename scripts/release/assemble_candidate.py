#!/usr/bin/env python3
"""Deterministically assemble and verify the frozen release candidate asset set."""

import argparse
import gzip
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import verify  # noqa: E402


PAIRED_BUILD_COMMIT = "a8a2adb0a299221d6f246f7c95e0912e4babd419"
FROZEN_TEST_COMMIT = "6e3e70b94281c8f75f52f90e77152deba7372c83"
BUILD_INPUT_PATHS = (
    "conf",
    "kas",
    "recipes-connectivity",
    "meta-firmdura-tests",
    "tests/run-cve-2026-19773.py",
)

FROZEN_STORE_ARTIFACTS = (
    {
        "store_rel": "artifacts/20261118-sti112-bundles/bundles/firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz",
        "filename": "firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz",
        "role": "qemu-bundle",
        "variant": "baseline",
        "expected_sha256": "ca423ae7d57f411c44916651413b6d6f3ad45d39aac4abb70498800ecd8891b0",
    },
    {
        "store_rel": "artifacts/20261118-sti112-bundles/bundles/firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz",
        "filename": "firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz",
        "role": "qemu-bundle",
        "variant": "patched",
        "expected_sha256": "aa04251544a1ff48e690620591255f029ca361871acc48af63ee785b462c8678",
    },
    {
        "store_rel": "artifacts/20261118-sti112-bundles/bundles/firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz",
        "filename": "firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz",
        "role": "corresponding-source",
        "expected_sha256": "ad8bded335da769b16cf66a4b3279e93e9667e6839c1dd82cce3f8a24c86c3ef",
    },
    {
        "store_rel": "artifacts/20261118-sti112-bundles/bundles/firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz",
        "filename": "firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz",
        "role": "licenses",
        "expected_sha256": "351d071eae6de20bd95af40356ba98c353953e7fcfaa4129c4bb5a06c5f15a76",
    },
    {
        "store_rel": "artifacts/20261118-sti112-bundles/bundles/firmdura-kirkstone-qemuarm64-redistribution-inventory.json",
        "filename": "firmdura-kirkstone-qemuarm64-redistribution-inventory.json",
        "role": "redistribution-inventory",
        "expected_sha256": "e66a37683054d0c70963e6f171e271d2530fdcc0f793687fb4959d9e7d635427",
    },
    {
        "store_rel": "artifacts/20261118-sti110-patched/sbom/baseline-41pkg-consolidated.spdx.json",
        "filename": "firmdura-kirkstone-qemuarm64-baseline.spdx.json",
        "role": "sbom",
        "variant": "baseline",
        "expected_sha256": "050eb32b37945ded03465de1f1f178cb433d7a37c408ee1a0fc83327292e3765",
    },
    {
        "store_rel": "artifacts/20261118-sti110-patched/sbom/patched-41pkg-consolidated.spdx.json",
        "filename": "firmdura-kirkstone-qemuarm64-patched.spdx.json",
        "role": "sbom",
        "variant": "patched",
        "expected_sha256": "f050a6e085b2c61afa3507cd35e977252f3fcf9836f91148c099189e20009110",
    },
)

FROZEN_VEX = {
    "repo_rel": "vex/firmdura-kirkstone-cve-2026-19773.openvex.json",
    "filename": "firmdura-kirkstone-cve-2026-19773.openvex.json",
    "role": "vex",
    "expected_sha256": "68850d630989bd25002f495c43b9cd4090cefde299774274f0d1b80e348b906e",
}

SECRET_RE = re.compile(
    r"(ghp_[A-Za-z0-9]+|gho_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|lin_api_[A-Za-z0-9]+|"
    r"LINEAR_API_KEY\s*=|Authorization:\s*Bearer)",
    re.I,
)


def deterministic_tar_gz(dest: Path, members: list[tuple[str, bytes]]) -> None:
    with dest.open("xb") as raw_out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_out, mtime=0) as gz:
            with tarfile.open(mode="w", fileobj=gz, format=tarfile.PAX_FORMAT) as tf:
                for arcname, payload in sorted(members, key=lambda item: item[0]):
                    verify.normalized_path(arcname)
                    info = tarfile.TarInfo(name=arcname)
                    info.size = len(payload)
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    info.mode = 0o644
                    tf.addfile(info, io.BytesIO(payload))


def verify_frozen_build_tree(repo: Path, source_commit: str) -> None:
    verify.require(re.fullmatch(r"[0-9a-f]{40}", source_commit) is not None,
                   "source_commit must be 40 lowercase hex characters")
    resolved = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--verify", f"{source_commit}^{{commit}}"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    verify.require(resolved == source_commit, "source_commit does not resolve cleanly")
    diff = subprocess.run(
        ["git", "-C", str(repo), "diff", "--exit-code",
         f"{PAIRED_BUILD_COMMIT}..{source_commit}", "--", *BUILD_INPUT_PATHS],
        capture_output=True, text=True,
    )
    verify.require(diff.returncode == 0,
                   "tested layer, build configuration, or target test inputs changed since paired build")


def build_source_archive(repo: Path, source_commit: str, release_id: str, dest: Path) -> None:
    raw_tar = subprocess.run(
        ["git", "-C", str(repo), "archive", "--format=tar",
         f"--prefix=meta-firmdura-kirkstone-{release_id}/", source_commit],
        check=True, capture_output=True,
    ).stdout
    with dest.open("xb") as raw_out:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw_out, mtime=0) as gz:
            gz.write(raw_tar)


def build_raw_logs_archive(repo: Path, source_commit: str, store: Path, release_id: str, dest: Path) -> dict:
    ls_tree = subprocess.run(
        ["git", "-C", str(repo), "ls-tree", "-r", "--name-only", source_commit, "evidence"],
        check=True, capture_output=True, text=True,
    ).stdout.splitlines()
    run_files = sorted(p for p in ls_tree if p.endswith("/run.json"))
    referenced: dict[str, set[str]] = {}
    expected_digests: dict[str, str] = {}
    for rf in run_files:
        content = subprocess.run(
            ["git", "-C", str(repo), "show", f"{source_commit}:{rf}"],
            check=True, capture_output=True, text=True,
        ).stdout
        doc = json.loads(content)
        for cmd in doc.get("commands", []):
            loc = cmd.get("log", "")
            if loc.startswith("local://firmdura-kirkstone/logs/") and loc.endswith(".log"):
                rel = loc.removeprefix("local://firmdura-kirkstone/")
                referenced.setdefault(rel, set()).add(rf)
                if cmd.get("log_sha256"):
                    prev = expected_digests.setdefault(rel, cmd["log_sha256"])
                    verify.require(prev == cmd["log_sha256"], f"conflicting log_sha256 for {rel}")
        for match in re.finditer(r"local://firmdura-kirkstone/(logs/[A-Za-z0-9._/-]+\.log)", content):
            referenced.setdefault(match.group(1), set()).add(rf)

    members: list[tuple[str, bytes]] = []
    included_index = []
    omitted_local_path_logs = []
    prefix = f"firmdura-kirkstone-{release_id}-raw-logs"
    for rel in sorted(referenced):
        path = store / rel
        verify.require(path.is_file(), f"missing referenced raw log in store: {rel}")
        data = path.read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        if rel in expected_digests:
            verify.require(sha == expected_digests[rel], f"raw log SHA-256 mismatch for {rel}")
        text = data.decode("utf-8", errors="replace")
        verify.require(SECRET_RE.search(text) is None, f"secret pattern detected in raw log: {rel}")
        if "/Users/" in text:
            omitted_local_path_logs.append({
                "store_locator": f"local://firmdura-kirkstone/{rel}",
                "sha256": sha,
                "size": len(data),
                "reason": "contains control-host filesystem path string; retained unmodified in local durable store",
                "referenced_by": sorted(referenced[rel]),
            })
            continue
        arcname = f"{prefix}/{rel}"
        members.append((arcname, data))
        included_index.append({
            "archive_path": arcname,
            "store_locator": f"local://firmdura-kirkstone/{rel}",
            "sha256": sha,
            "size": len(data),
            "referenced_by": sorted(referenced[rel]),
        })

    index_doc = {
        "schema_version": 1,
        "release_id": release_id,
        "source_commit": source_commit,
        "included_log_count": len(included_index),
        "omitted_host_path_log_count": len(omitted_local_path_logs),
        "included_logs": included_index,
        "omitted_host_path_logs": omitted_local_path_logs,
    }
    members.append((f"{prefix}/INDEX.json", (json.dumps(index_doc, indent=2, sort_keys=True) + "\n").encode()))
    deterministic_tar_gz(dest, members)
    return {"included_log_count": len(included_index), "omitted_host_path_log_count": len(omitted_local_path_logs)}


def render_release_notes(release_id: str, source_commit: str) -> bytes:
    text = f"""# Firmdura Kirkstone reference release `{release_id}`

Scoped Yocto Kirkstone (`4.0.35`, `qemuarm64`) security maintenance reference
sample for `libwebsockets` `4.2.2` addressing
[`CVE-2026-19773`](https://www.zerodayinitiative.com/advisories/ZDI-26-590/).

## Source and build provenance

| Identity | Revision / digest |
|---|---|
| Release repository | `https://github.com/firmdura/meta-firmdura-kirkstone` |
| Release source & evidence commit | `{source_commit}` |
| Paired image build commit (`baseline` & `patched`) | `{PAIRED_BUILD_COMMIT}` |
| Frozen target test harness commit | `{FROZEN_TEST_COMMIT}` |
| Poky (`yocto-4.0.35`) | `93431249a6260da7bd29ee3ca32145d89e5b8259` |
| `meta-openembedded` (`kirkstone`) | `ce8539c941f6fcbecaca4d16640ac105c0595589` |
| `garmin/meta-lts-collab` (`kirkstone`) | `e127ed67e74ca6b7e0fdc6cbda572302886c00a0` |
| Pinned ARM64 kas 4.8 builder | `ghcr.io/siemens/kas/kas@sha256:718b8f0dbf8174645ddb18c7979e7a635a4ed7bd55e750d75c1c8091454b8ce7` |
| Upstream `libwebsockets` `4.2.2` `SRCREV` | `8d605f0649ed1ab6d27a443c7688598ea21fdb75` |
| Backported upstream repair commits | `824151862f37bc72f46d9a3e01d5b9408d313a0b`, `0c6cef0922c531f2662e87e74e17c191fa18162b` |
| Upstream community contribution | [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283) |

Zero BitBake layer, recipe, patch, or target-test files changed between paired
build commit `{PAIRED_BUILD_COMMIT}` and release commit `{source_commit}`;
intermediate commits added packaging, OpenVEX, signing, and independent replay
verification tooling and records.

## Before / after target runtime and scanner results

- **Target runtime (`qemuarm64`, `-nic none`, disposable rootfs copies)**:
  - `baseline` (`/usr/lib/libwebsockets.so.18` `77809db0...`, `.rootfs.ext4`
    `6f18018f...`): passes normal HTTP/2 controls (`exit 0`) and reproduces all
    `7/7` targeted `CVE-2026-19773` HPACK `:path` out-of-bounds heap/guard-page
    write subchecks in `lws_frag_append` (`exit 1`).
  - `patched` (`/usr/lib/libwebsockets.so.18` `4aac4463...`, `.rootfs.ext4`
    `92a3d9f9...`, `PR = "r0.firmdura1"`, `PV = "4.2.2"`): passes normal HTTP/2
    controls (`exit 0`), cleanly rejects all `7/7` oversized `:path` inputs
    while continuing to serve HTTP/2 `200` responses (`exit 0`), and passes
    `ptest-runner firmdura-lws-h2-tests` (`TOTAL: 1 FAIL: 0`).
  - Independent clean-volume source rebuilds reproduced byte-identical
    `libwebsockets.so.18`, test harness binaries, kernel `Image`, and 41-package
    manifests with matching QEMU runtime behavior.
- **SBOM, OpenVEX v0.2.0, and pinned Grype `0.122.0` verification**:
  - Consolidated 41-package SPDX 2.2 SBOMs bind distinct `.rootfs.ext4`
    SHA-256 product PURLs for `baseline` (`sha256.6f18018f...`, `affected`) and
    `patched` (`sha256.92a3d9f9...`, `fixed`).
  - Under the isolated test-only CPE fixture database (`xxh64:da9d32d12ca5d406`),
    offline Grype `0.122.0` suppresses all `3` `CVE-2026-19773` package matches
    on `patched` (`ignoredMatches` `vex-status: fixed`, preserving all `151`
    unrelated matches) and retains all `3` active `CVE-2026-19773` matches on
    `baseline` when given the same OpenVEX file (mandatory negative control).
  - Stock Anchore Grype DB `v6.1.10` (`2026-11-18T06:21:08Z`) currently has `0`
    CPE rows for `CVE-2026-19773` while NIST NVD lists the CVE as
    `Awaiting Analysis`; companion offline OSV Git/source provenance reports
    `affected` on `baseline` vs `fixed_by_verified_backport` on `patched`.

## Signature verification and quick QEMU evaluation

Verify the complete published GitHub Release with Cosign `v3.1.4`, Python 3.11+,
and GitHub CLI before extracting any bundle:

```sh
python3 scripts/release/verify.py github-release \\
  --assets ./downloaded-{release_id} \\
  --manifest-sha256 "<MANIFEST_SHA256>" \\
  --release-id "{release_id}" \\
  --source-commit "{source_commit}"
```

Extract both QEMU evaluation bundles into clean directories and run the
offline comparison (`qemu-system-aarch64` required; never extract on shared or
bridged networks):

```sh
mkdir -p eval-baseline eval-patched
tar -xzf downloaded-{release_id}/firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz -C eval-baseline
tar -xzf downloaded-{release_id}/firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz -C eval-patched
python3 eval-baseline/firmdura-kirkstone-qemuarm64-baseline-eval/run-evaluation.py --mode full
python3 eval-patched/firmdura-kirkstone-qemuarm64-patched-eval/run-evaluation.py --mode full
```

Expected outcome: `baseline` exits `1` (`vulnerable-oob-write-reproduced`);
`patched` exits `0` (`bounds-enforced-secure`).

## Scope boundaries and licensing

- **Experimental evaluation sample only**: Validated solely on this pinned
  `qemuarm64` Poky `4.0.35` image (`debug-tweaks` enabled for local root test
  execution). Not production firmware and not a claim of universal Kirkstone
  BSP, hardware, or CVE coverage.
- **Complete corresponding source and licences**: Distributed alongside the
  evaluation bundles in `firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz`,
  `firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz`, and
  `firmdura-kirkstone-qemuarm64-redistribution-inventory.json`. Original
  Firmdura files are MIT-licensed; third-party components retain their upstream
  licences and notices.
"""
    return text.encode("utf-8")


def assemble_candidate(*, repo: Path, store: Path, output: Path, release_id: str, source_commit: str) -> dict:
    verify.require(not output.exists() and not output.is_symlink(),
                   "candidate output directory must not already exist")
    verify_frozen_build_tree(repo, source_commit)
    output.mkdir(parents=True)

    artifact_entries = []

    def register(path: Path, role: str, variant: str | None = None, expected_sha256: str | None = None):
        sha = verify.file_digest(path)
        if expected_sha256 is not None:
            verify.require(sha == expected_sha256, f"unexpected frozen SHA-256 for {path.name}: {sha}")
        entry = {
            "path": path.name,
            "role": role,
            "size": path.stat().st_size,
            "sha256": sha,
        }
        if variant is not None:
            entry["variant"] = variant
        artifact_entries.append(entry)

    for item in FROZEN_STORE_ARTIFACTS:
        src = store / item["store_rel"]
        verify.require(src.is_file(), f"missing frozen store artifact: {src}")
        dst = output / item["filename"]
        shutil.copyfile(src, dst)
        register(dst, item["role"], item.get("variant"), item["expected_sha256"])

    vex_bytes = subprocess.run(
        ["git", "-C", str(repo), "show", f"{source_commit}:{FROZEN_VEX['repo_rel']}"],
        check=True, capture_output=True,
    ).stdout
    vex_dst = output / FROZEN_VEX["filename"]
    vex_dst.write_bytes(vex_bytes)
    register(vex_dst, FROZEN_VEX["role"], None, FROZEN_VEX["expected_sha256"])

    src_dst = output / f"firmdura-kirkstone-{release_id}-source-and-evidence.tar.gz"
    build_source_archive(repo, source_commit, release_id, src_dst)
    register(src_dst, "source-layer")

    logs_dst = output / f"firmdura-kirkstone-{release_id}-raw-evidence-logs.tar.gz"
    log_stats = build_raw_logs_archive(repo, source_commit, store, release_id, logs_dst)
    register(logs_dst, "evidence-logs")

    notes_dst = output / f"firmdura-kirkstone-{release_id}-release-notes.md"
    notes_bytes = render_release_notes(release_id, source_commit)
    verify.require(b"/Users/" not in notes_bytes and re.search(rb"\bSTI-\d+\b", notes_bytes) is None,
                   "unsanitized content in release notes")
    notes_dst.write_bytes(notes_bytes)
    register(notes_dst, "release-notes")

    artifact_entries.sort(key=lambda e: e["path"])
    manifest_doc = {
        "schema_version": 1,
        "release": {"kind": "release", "id": release_id},
        "source": {"repository": verify.SOURCE_REPOSITORY, "commit": source_commit},
        "artifacts": artifact_entries,
    }
    manifest_bytes = (json.dumps(manifest_doc, indent=2) + "\n").encode("utf-8")
    manifest_sha256 = verify.digest(manifest_bytes)
    (output / verify.MANIFEST).write_bytes(manifest_bytes)

    verify.check_assets(
        output, signed=False,
        manifest_sha256=manifest_sha256,
        kind="release",
        release_id=release_id,
        source_commit=source_commit,
    )
    return {
        "status": "candidate-assembled-and-checked",
        "release_id": release_id,
        "source_commit": source_commit,
        "paired_build_commit": PAIRED_BUILD_COMMIT,
        "manifest_sha256": manifest_sha256,
        "manifest_size": len(manifest_bytes),
        "payload_count": len(artifact_entries),
        "total_payload_bytes": sum(e["size"] for e in artifact_entries),
        "log_archive_stats": log_stats,
        "artifacts": artifact_entries,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--store", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()

    summary = assemble_candidate(
        repo=args.repo,
        store=args.store,
        output=args.output,
        release_id=args.release_id,
        source_commit=args.source_commit,
    )
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
