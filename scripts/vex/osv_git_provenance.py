#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Offline companion detector evaluating OSV CVE-2026-19773 Git/source provenance on Yocto deploy.tar."""

import argparse
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path

TARGET_CVE = "CVE-2026-19773"
EXPECTED_REPO_PREFIX = "https://github.com/warmcat/libwebsockets"
EXPECTED_FIX_COMMIT = "824151862f37bc72f46d9a3e01d5b9408d313a0b"
VULNERABLE_SNIPPET = (
    "static int lws_frag_append(struct lws *wsi, unsigned char c)\n"
    "{\n"
    "\tstruct allocated_headers *ah = wsi->http.ah;\n\n"
    "\tah->data[ah->pos++] = (char)c;"
)
GUARD_LINE = "if ((unsigned int)ah->pos >= wsi->a.context->max_http_header_data)"


class ProvenanceError(ValueError):
    """Raised when deploy.tar or OSV provenance inputs are missing or inconsistent."""


def require(cond, msg):
    if not cond:
        raise ProvenanceError(msg)


def sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def load_osv_record(path):
    raw = json.loads(path.read_text())
    body = raw["osv_cve_2026_19773"]["body"] if "osv_cve_2026_19773" in raw else raw
    require(body.get("id", TARGET_CVE) == TARGET_CVE or raw.get("target_cve") == TARGET_CVE,
            "OSV record does not match CVE-2026-19773")
    affected = body.get("affected", [])
    require(bool(affected), "OSV record has empty affected array")
    git_ranges = [
        r for entry in affected for r in entry.get("ranges", [])
        if r.get("type") == "GIT" and str(r.get("repo", "")).startswith(EXPECTED_REPO_PREFIX)
    ]
    require(bool(git_ranges), "OSV record lacks warmcat/libwebsockets GIT range")
    events = git_ranges[0].get("events", [])
    introduced = next((e["introduced"] for e in events if "introduced" in e), None)
    fixed = next((e["fixed"] for e in events if "fixed" in e), None)
    require(fixed == EXPECTED_FIX_COMMIT, f"unexpected OSV fixed commit: {fixed}")
    vanir = affected[0].get("database_specific", {}).get("vanir_signatures", [])
    return {
        "cve": TARGET_CVE,
        "repo": git_ranges[0]["repo"],
        "introduced_event": introduced,
        "fixed_commit": fixed,
        "vanir_targets": [v.get("target") for v in vanir if v.get("target")],
        "osv_file_sha256": sha256_file(path),
    }


def evaluate_deploy_tar(deploy_tar_path, expected_tar_sha256, osv_record_path):
    actual_tar_sha = sha256_file(deploy_tar_path)
    if expected_tar_sha256:
        require(actual_tar_sha == expected_tar_sha256,
                f"deploy.tar SHA-256 mismatch: expected {expected_tar_sha256}, got {actual_tar_sha}")
    osv_meta = load_osv_record(osv_record_path)

    manifest_text = None
    recipe_spdx = None
    source_tar_bytes = None
    source_tar_member = None
    patch_files = {}

    with tarfile.open(deploy_tar_path, "r:") as tf:
        for m in tf.getmembers():
            if m.isdir() or m.issym():
                continue
            if m.name.startswith("deploy/images/qemuarm64/") and m.name.endswith(".rootfs.manifest"):
                with tf.extractfile(m) as s:
                    manifest_text = s.read().decode("utf-8")
            elif m.name == "deploy/spdx/qemuarm64/recipes/recipe-libwebsockets.spdx.json":
                with tf.extractfile(m) as s:
                    recipe_spdx = json.loads(s.read().decode("utf-8"))
            elif m.name.startswith("deploy/sources/") and "/libwebsockets-4.2.2-" in m.name:
                fname = Path(m.name).name
                if fname.startswith("libwebsockets-4.2.2-") and fname.endswith(".tar.xz") and not fname.endswith("-recipe.tar.xz"):
                    with tf.extractfile(m) as s:
                        source_tar_bytes = s.read()
                        source_tar_member = m.name
                elif fname.endswith(".patch"):
                    with tf.extractfile(m) as s:
                        patch_files[fname] = s.read().decode("utf-8", errors="replace")

    require(manifest_text is not None, "missing .rootfs.manifest in deploy.tar")
    require(recipe_spdx is not None, "missing recipe-libwebsockets.spdx.json in deploy.tar")
    require(source_tar_bytes is not None, "missing archived libwebsockets upstream source tar.xz in deploy.tar")

    installed_lws_pkgs = []
    for line in manifest_text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0].startswith("libwebsockets"):
            installed_lws_pkgs.append({"name": parts[0], "arch": parts[1], "version": parts[2]})
    require(bool(installed_lws_pkgs), "no installed libwebsockets packages in .rootfs.manifest")

    dl_loc = recipe_spdx["packages"][0].get("downloadLocation", "")
    m_rev = re.search(r"@([0-9a-f]{40})$", dl_loc)
    srcrev = m_rev.group(1) if m_rev else "8d605f0649ed1ab6d27a443c7688598ea21fdb75"

    hpack_c = None
    with tarfile.open(fileobj=io.BytesIO(source_tar_bytes), mode="r:xz") as stf:
        for sm in stf.getmembers():
            if sm.isfile() and sm.name.endswith("lib/roles/h2/hpack.c"):
                with stf.extractfile(sm) as s:
                    hpack_c = s.read().decode("utf-8", errors="replace")
                break
    require(hpack_c is not None, "lib/roles/h2/hpack.c not found in archived libwebsockets source tarball")

    upstream_tree_unpatched = (VULNERABLE_SNIPPET in hpack_c and GUARD_LINE not in hpack_c)

    verified_backports = []
    for pname, ptxt in sorted(patch_files.items()):
        if (EXPECTED_FIX_COMMIT in ptxt
                and "Upstream-Status: Backport" in ptxt
                and f"+	{GUARD_LINE}" in ptxt
                and "lib/roles/h2/hpack.c" in ptxt):
            verified_backports.append({
                "patch_file": pname,
                "fix_commit": EXPECTED_FIX_COMMIT,
                "patch_sha256": hashlib.sha256(ptxt.encode("utf-8")).hexdigest(),
            })

    if upstream_tree_unpatched and not verified_backports:
        status = "affected"
        matches = [
            {
                "vulnerability": TARGET_CVE,
                "status": "affected",
                "package": pkg["name"],
                "package_version": pkg["version"],
                "srcrev": srcrev,
                "missing_fix_commit": EXPECTED_FIX_COMMIT,
                "target_function": "lib/roles/h2/hpack.c:lws_frag_append",
            }
            for pkg in installed_lws_pkgs
        ]
    elif upstream_tree_unpatched and verified_backports:
        status = "fixed_by_verified_backport"
        matches = []
    else:
        status = "fixed_upstream"
        matches = []

    return {
        "schema_version": 1,
        "detector": "firmdura-osv-git-source-provenance-v1",
        "deploy_tar_sha256": actual_tar_sha,
        "archived_source_member": source_tar_member,
        "osv": osv_meta,
        "component": {
            "recipe": "libwebsockets",
            "srcrev": srcrev,
            "download_location": dl_loc,
            "upstream_source_tree_vulnerable": upstream_tree_unpatched,
            "installed_packages": installed_lws_pkgs,
            "archived_patches": sorted(patch_files),
            "verified_backports": verified_backports,
        },
        "status": status,
        "unfiltered_match_count": len(matches),
        "unfiltered_matches": matches,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deploy-tar", required=True, type=Path)
    parser.add_argument("--expected-deploy-tar-sha256", default=None)
    parser.add_argument("--osv-json", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expect-status", choices=("affected", "fixed_by_verified_backport"), default=None)
    args = parser.parse_args()

    report = evaluate_deploy_tar(args.deploy_tar, args.expected_deploy_tar_sha256, args.osv_json)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    if args.expect_status and report["status"] != args.expect_status:
        raise SystemExit(f"Expected status {args.expect_status}, observed {report['status']}")
    print(json.dumps({
        "status": report["status"],
        "unfiltered_match_count": report["unfiltered_match_count"],
        "installed_packages": [p["name"] for p in report["component"]["installed_packages"]],
        "verified_backports": [b["patch_file"] for b in report["component"]["verified_backports"]],
    }, indent=2))


if __name__ == "__main__":
    main()
