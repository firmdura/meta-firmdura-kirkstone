#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Package frozen baseline/patched QEMU evaluation bundles and complete corresponding source."""

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import tarfile
from pathlib import Path

BASELINE_BINS = {
    "kernel_sha256": "4866e9a8df7c5be803372af05fc187b35792ef170fd2d8745053f18f6af6d36c",
    "rootfs_sha256": "6f18018f84e0799faeb30a892f827500e209f7831305748eeb64f41813e197a2",
    "library_sha256": "77809db0b9f6a1f97917292a5976e332de130bed90c21eb219e8032cfe3ae05a",
    "harness_sha256": "774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795",
}
PATCHED_BINS = {
    "kernel_sha256": "4866e9a8df7c5be803372af05fc187b35792ef170fd2d8745053f18f6af6d36c",
    "rootfs_sha256": "92a3d9f9aaf40de580590bff13774d39b51aab8b3494b1e14bea1963e344598d",
    "library_sha256": "4aac446382e44af454bed760127683a16faf98a8abb1c257d7564da798a717c5",
    "harness_sha256": "774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795",
}
SECRET_RE = re.compile(
    r"github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]+|lin_api_[A-Za-z0-9]+|BEGIN [A-Z ]*PRIVATE KEY"
)


class BundleError(ValueError):
    """Raised when bundle inputs or redistribution obligations fail verification."""


def require(cond, msg):
    if not cond:
        raise BundleError(msg)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class DeterministicTarGz:
    """Write deterministic gzip-compressed POSIX ustar/pax archives (mtime=0, uid/gid=0)."""

    def __init__(self, path):
        self.path = path
        self._raw = path.open("xb")
        self._gz = gzip.GzipFile(filename="", mode="wb", fileobj=self._raw, compresslevel=6, mtime=0)
        self._tar = tarfile.open(mode="w", fileobj=self._gz, format=tarfile.PAX_FORMAT)
        self.members = []

    def add_bytes(self, arcname, data, mode=0o644):
        require(not arcname.startswith("/") and ".." not in arcname.split("/"),
                f"unsafe archive path: {arcname}")
        info = tarfile.TarInfo(name=arcname)
        info.size = len(data)
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.uname = ""
        info.gname = ""
        info.mode = mode
        info.type = tarfile.REGTYPE
        self._tar.addfile(info, io.BytesIO(data))
        digest = sha256_bytes(data)
        self.members.append({"path": arcname, "size": len(data), "sha256": digest, "mode": oct(mode)})
        return digest

    def close(self):
        self._tar.close()
        self._gz.close()
        self._raw.close()


def render_launch_sh(prefix_dir, variant, kernel_rel, rootfs_rel, kernel_sha, rootfs_sha):
    banner = (
        "WARNING: INTENTIONALLY VULNERABLE BASELINE (CVE-2026-19773) - ISOLATED EVALUATION ONLY, NEVER PRODUCTION FIRMWARE"
        if variant == "baseline"
        else "NOTICE: ISOLATED EVALUATION REFERENCE (CVE-2026-19773 REPAIRED) - NOT PRODUCTION FIRMWARE"
    )
    return f"""#!/bin/sh
# SPDX-License-Identifier: MIT
set -eu

BUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
QEMU_BIN=${{QEMU_SYSTEM_AARCH64:-qemu-system-aarch64}}
KERNEL="$BUNDLE_DIR/{kernel_rel}"
ROOTFS="$BUNDLE_DIR/{rootfs_rel}"
EXPECTED_KERNEL_SHA="{kernel_sha}"
EXPECTED_ROOTFS_SHA="{rootfs_sha}"

hash_file() {{
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{{print $1}}'
    else
        shasum -a 256 "$1" | awk '{{print $1}}'
    fi
}}

verify_frozen() {{
    [ "$(hash_file "$KERNEL")" = "$EXPECTED_KERNEL_SHA" ] || {{ echo "Kernel SHA-256 mismatch" >&2; exit 1; }}
    [ "$(hash_file "$ROOTFS")" = "$EXPECTED_ROOTFS_SHA" ] || {{ echo "Rootfs SHA-256 mismatch" >&2; exit 1; }}
}}

printf '%s\\n' "{banner}" >&2
verify_frozen

TMP_DIR=$(mktemp -d "${{TMPDIR:-/tmp}}/firmdura-{variant}-eval.XXXXXX")
cleanup() {{
    rm -rf "$TMP_DIR"
    verify_frozen
}}
trap cleanup EXIT INT TERM

RUN_ROOTFS="$TMP_DIR/rootfs.ext4"
cp "$ROOTFS" "$RUN_ROOTFS"
[ "$(hash_file "$RUN_ROOTFS")" = "$EXPECTED_ROOTFS_SHA" ] || {{ echo "Disposable copy mismatch" >&2; exit 1; }}

"$QEMU_BIN" -machine virt -cpu cortex-a57 -smp 2 -m 512 \\
  -nographic -nic none -kernel "$KERNEL" \\
  -drive "id=disk0,file=$RUN_ROOTFS,if=none,format=raw" \\
  -device virtio-blk-pci,drive=disk0 \\
  -object rng-random,filename=/dev/urandom,id=rng0 \\
  -device virtio-rng-pci,rng=rng0 \\
  -device virtio-serial-pci -chardev null,id=virtcon \\
  -device virtconsole,chardev=virtcon \\
  -append 'console=ttyAMA0 root=/dev/vda rw'
""".encode("utf-8")


def render_run_evaluation_py(variant, kernel_rel, rootfs_rel, expected):
    outcome = "vulnerable" if variant == "baseline" else "repaired"
    return f"""#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
\"\"\"Self-contained isolated QEMU evaluation runner for the {variant} reference bundle.\"\"\"

import argparse
import hashlib
import json
import re
import shutil
import sys
import tempfile
import time
from pathlib import Path

import pexpect

VARIANT = {variant!r}
EXPECTED_OUTCOME = {outcome!r}
KERNEL_REL = {kernel_rel!r}
ROOTFS_REL = {rootfs_rel!r}
EXPECTED_KERNEL_SHA256 = {expected["kernel_sha256"]!r}
EXPECTED_ROOTFS_SHA256 = {expected["rootfs_sha256"]!r}
EXPECTED_LIBRARY_SHA256 = {expected["library_sha256"]!r}
EXPECTED_HARNESS_SHA256 = {expected["harness_sha256"]!r}
EXPECTED_LIBRARY_VERSION = "4.2.1-v4.2.2"


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def verify_frozen(kernel, rootfs):
    if sha256(kernel) != EXPECTED_KERNEL_SHA256:
        raise RuntimeError("Frozen kernel SHA-256 mismatch")
    if sha256(rootfs) != EXPECTED_ROOTFS_SHA256:
        raise RuntimeError("Frozen rootfs SHA-256 mismatch")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default="qemu-system-aarch64")
    args = parser.parse_args()

    bundle_dir = Path(__file__).resolve().parent
    kernel = bundle_dir / KERNEL_REL
    rootfs = bundle_dir / ROOTFS_REL
    verify_frozen(kernel, rootfs)
    started = time.monotonic()
    observations = {{"variant": VARIANT, "expected_security_outcome": EXPECTED_OUTCOME}}

    with tempfile.TemporaryDirectory(prefix=f"firmdura-{{VARIANT}}-") as directory:
        copy = Path(directory) / "rootfs.ext4"
        shutil.copyfile(rootfs, copy)
        if sha256(copy) != EXPECTED_ROOTFS_SHA256:
            raise RuntimeError("Disposable rootfs copy mismatch")
        command = [
            "-machine", "virt", "-cpu", "cortex-a57", "-smp", "2", "-m", "512",
            "-nographic", "-nic", "none", "-kernel", str(kernel),
            "-drive", f"id=disk0,file={{copy}},if=none,format=raw",
            "-device", "virtio-blk-pci,drive=disk0",
            "-object", "rng-random,filename=/dev/urandom,id=rng0",
            "-device", "virtio-rng-pci,rng=rng0",
            "-device", "virtio-serial-pci", "-chardev", "null,id=virtcon",
            "-device", "virtconsole,chardev=virtcon",
            "-append", "console=ttyAMA0 root=/dev/vda rw",
        ]
        child = pexpect.spawn(args.qemu, command, encoding="utf-8", timeout=120)
        child.logfile = sys.stdout
        seq = 0

        def guest_raw(cmd, timeout=60):
            nonlocal seq
            seq += 1
            marker = f"__FIRMDURA_EVAL_RC_{{seq}}__="
            child.sendline(cmd + f"; rc=$?; printf '\\\\n{{marker}}%s\\\\n' \\"$rc\\"")
            child.expect(re.escape(marker) + r"([0-9]+)\\r*\\n", timeout=timeout)
            raw = child.before.replace("\\r", "")
            nl = raw.find("\\n")
            out = raw[nl + 1:] if nl >= 0 else raw
            rc = int(child.match.group(1))
            child.expect_exact("__FIRMDURA_EVAL__ ", timeout=30)
            return rc, out.strip()

        def guest(cmd, timeout=60):
            rc, out = guest_raw(cmd, timeout=timeout)
            if rc != 0:
                raise RuntimeError(f"Guest command exited {{rc}}: {{cmd}}")
            return out

        def guest_json(path):
            out = guest(f"printf '__JSON_START__\\\\n'; cat {{path}}; printf '\\\\n__JSON_END__\\\\n'")
            m = re.search(r"__JSON_START__\\n(.*)\\n__JSON_END__", out, re.S)
            if m is None:
                raise RuntimeError(f"Missing JSON markers for {{path}}")
            return json.loads(m.group(1))

        try:
            child.expect("qemuarm64 login:")
            child.sendline("root")
            child.expect(r"root@qemuarm64:[^\\r\\n]*# ")
            child.sendline("export PS1='__FIRMDURA_EVAL__ '")
            child.expect(r"\\r*\\n__FIRMDURA_EVAL__ ")

            guest("ifconfig lo 127.0.0.1 up || ip link set lo up")
            if "aarch64" not in guest("uname -m"):
                raise RuntimeError("Guest is not aarch64")
            if "Poky (Yocto Project Reference Distro) 4.0.35" not in guest("cat /etc/issue"):
                raise RuntimeError("Unexpected guest distro banner")
            if EXPECTED_LIBRARY_SHA256 not in guest("sha256sum /usr/lib/libwebsockets.so.18"):
                raise RuntimeError("Guest libwebsockets.so.18 SHA-256 mismatch")
            if EXPECTED_HARNESS_SHA256 not in guest("sha256sum /usr/bin/firmdura-h2-cve-2026-19773"):
                raise RuntimeError("Guest test harness SHA-256 mismatch")

            norm_rc, _ = guest_raw("/usr/bin/firmdura-h2-cve-2026-19773 --mode normal-only >/tmp/norm.json")
            if norm_rc != 0:
                raise RuntimeError(f"Normal HTTP/2 control failed: {{norm_rc}}")
            observations["normal_control"] = guest_json("/tmp/norm.json")

            full_rc, _ = guest_raw("/usr/bin/firmdura-h2-cve-2026-19773 --mode full >/tmp/full.json", timeout=90)
            full_rep = guest_json("/tmp/full.json")
            observations["full_security_exit_code"] = full_rc
            observations["full_security_suite"] = full_rep

            ptest_rc, ptest_out = guest_raw("ptest-runner firmdura-lws-h2-tests", timeout=90)
            observations["ptest_exit_code"] = ptest_rc

            if EXPECTED_OUTCOME == "vulnerable":
                if full_rc != 1 or full_rep.get("verdict") != "vulnerable-oob-write-reproduced":
                    raise RuntimeError(f"Baseline did not reproduce vulnerable OOB write: rc={{full_rc}}")
                if ptest_rc == 0 or "FAIL: firmdura-cve-2026-19773-bounds-enforced" not in ptest_out:
                    raise RuntimeError("Baseline ptest did not fail bounds check")
            else:
                if full_rc != 0 or full_rep.get("verdict") != "bounds-enforced-secure":
                    raise RuntimeError(f"Patched did not enforce bounds: rc={{full_rc}}")
                if ptest_rc != 0 or "PASS: firmdura-cve-2026-19773-bounds-enforced" not in ptest_out:
                    raise RuntimeError("Patched ptest did not pass bounds check")

            child.sendline("poweroff")
            child.expect(pexpect.EOF, timeout=90)
            child.close()
            if child.exitstatus != 0:
                raise RuntimeError(f"QEMU exit={{child.exitstatus}}")
        finally:
            child.close(force=True)
            verify_frozen(kernel, rootfs)

    print(json.dumps({{
        "status": "passed",
        "variant": VARIANT,
        "expected_security_outcome": EXPECTED_OUTCOME,
        "elapsed_seconds": time.monotonic() - started,
        "originals_unchanged": True,
        "observations": observations,
    }}, indent=2), flush=True)


if __name__ == "__main__":
    main()
""".encode("utf-8")


def render_notice_txt(variant):
    if variant == "baseline":
        return (
            "WARNING: INTENTIONALLY VULNERABLE EVALUATION REFERENCE (CVE-2026-19773)\n"
            "========================================================================\n"
            "This baseline qemuarm64 image builds unpatched libwebsockets 4.2.2-r0\n"
            "(commit 8d605f0649ed1ab6d27a443c7688598ea21fdb75) to demonstrate\n"
            "CVE-2026-19773 (ZDI-26-590) HTTP/2 HPACK :path out-of-bounds heap write\n"
            "reproduction in isolated QEMU (-nic none) environments.\n\n"
            "- DO NOT deploy on production or physical hardware.\n"
            "- DO NOT attach bridged or external networking.\n"
            "- Boot only disposable copies via ./launch-qemu.sh or ./run-evaluation.py.\n"
            "- Third-party components retain their original licences; see\n"
            "  firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz and\n"
            "  firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz.\n"
        ).encode("utf-8")
    return (
        "NOTICE: ISOLATED EVALUATION REFERENCE ONLY (CVE-2026-19773 REPAIRED)\n"
        "====================================================================\n"
        "This patched qemuarm64 image applies the scoped libwebsockets 4.2.2\n"
        "CVE-2026-19773 backport layer (4.2.2-r0.firmdura1) on Poky 4.0.35.\n\n"
        "- Reference evaluation image only (debug-tweaks enabled); NOT production firmware.\n"
        "- Boot only disposable copies with -nic none via ./launch-qemu.sh or\n"
        "  ./run-evaluation.py.\n"
        "- Third-party components retain their original licences; see\n"
        "  firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz and\n"
        "  firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz.\n"
    ).encode("utf-8")


def check_no_host_or_secrets(label, raw_bytes):
    text = raw_bytes.decode("utf-8", errors="ignore")
    require("/Users/" not in text and "/home/azhovan" not in text,
            f"host-specific path leaked into {label}")
    require(SECRET_RE.search(text) is None, f"secret-like token detected in {label}")


def extract_deploy_members(deploy_tar_path, predicate):
    out = {}
    with tarfile.open(deploy_tar_path, "r:") as tf:
        for member in tf.getmembers():
            if member.isdir() or not predicate(member.name):
                continue
            if member.issym():
                continue
            require(member.isfile() or member.islnk(),
                    f"unexpected special member in {deploy_tar_path}: {member.name}")
            with tf.extractfile(member) as stream:
                out[member.name] = stream.read()
    return out


def build_eval_bundle(output_path, variant, deploy_tar_path, spdx_path, expected):
    root_dir = f"firmdura-kirkstone-qemuarm64-{variant}-eval"
    img_members = extract_deploy_members(
        deploy_tar_path,
        lambda n: n.startswith("deploy/images/qemuarm64/") and (
            n.endswith(".bin") or f"firmdura-reference-{variant}-qemuarm64-" in n
        ) and any(n.endswith(ext) for ext in (".bin", ".rootfs.ext4", ".rootfs.manifest", ".qemuboot.conf")),
    )
    kernel_key = next((k for k in sorted(img_members) if k.endswith(".bin")), None)
    rootfs_key = next((k for k in sorted(img_members) if k.endswith(".rootfs.ext4")), None)
    manifest_key = next((k for k in sorted(img_members) if k.endswith(".rootfs.manifest")), None)
    qemuboot_key = next((k for k in sorted(img_members) if k.endswith(".qemuboot.conf")), None)
    require(all([kernel_key, rootfs_key, manifest_key, qemuboot_key]),
            f"missing required kernel/rootfs/manifest/qemuboot in {variant} deploy.tar")

    kernel_bytes = img_members[kernel_key]
    rootfs_bytes = img_members[rootfs_key]
    require(sha256_bytes(kernel_bytes) == expected["kernel_sha256"], f"{variant} kernel SHA-256 mismatch")
    require(sha256_bytes(rootfs_bytes) == expected["rootfs_sha256"], f"{variant} rootfs SHA-256 mismatch")

    kernel_name = Path(kernel_key).name
    rootfs_name = Path(rootfs_key).name
    manifest_name = Path(manifest_key).name
    qemuboot_name = Path(qemuboot_key).name
    spdx_bytes = spdx_path.read_bytes()

    notice_name = (
        "WARNING-VULNERABLE-REFERENCE-ONLY.txt"
        if variant == "baseline"
        else "NOTICE-REFERENCE-ONLY.txt"
    )
    notice_bytes = render_notice_txt(variant)
    launch_bytes = render_launch_sh(
        root_dir, variant, f"images/{kernel_name}", f"images/{rootfs_name}",
        expected["kernel_sha256"], expected["rootfs_sha256"],
    )
    eval_py_bytes = render_run_evaluation_py(
        variant, f"images/{kernel_name}", f"images/{rootfs_name}", expected,
    )
    for lbl, b in [("notice", notice_bytes), ("launch-qemu.sh", launch_bytes), ("run-evaluation.py", eval_py_bytes)]:
        check_no_host_or_secrets(f"{variant}:{lbl}", b)

    # Sanitize qemuboot.conf build paths so zero /work/ host/build paths mislead evaluators
    qb_sanitized = "\n".join(
        line for line in img_members[qemuboot_key].decode("utf-8").splitlines()
        if not line.startswith(("deploy_dir_image =", "staging_bindir_native =", "staging_dir_host =", "staging_dir_native ="))
    ).encode("utf-8") + b"\n"
    check_no_host_or_secrets(f"{variant}:qemuboot.conf", qb_sanitized)

    writer = DeterministicTarGz(output_path)
    try:
        writer.add_bytes(f"{root_dir}/{notice_name}", notice_bytes, 0o644)
        writer.add_bytes(f"{root_dir}/launch-qemu.sh", launch_bytes, 0o755)
        writer.add_bytes(f"{root_dir}/run-evaluation.py", eval_py_bytes, 0o755)
        writer.add_bytes(f"{root_dir}/images/{kernel_name}", kernel_bytes, 0o644)
        writer.add_bytes(f"{root_dir}/images/{rootfs_name}", rootfs_bytes, 0o644)
        writer.add_bytes(f"{root_dir}/images/{manifest_name}", img_members[manifest_key], 0o644)
        writer.add_bytes(f"{root_dir}/images/{qemuboot_name}", qb_sanitized, 0o644)
        writer.add_bytes(f"{root_dir}/sbom/{spdx_path.name}", spdx_bytes, 0o644)

        inner_inv = {
            "schema_version": 1,
            "variant": variant,
            "reference_only": True,
            "intentionally_vulnerable": variant == "baseline",
            "default_network": "none (-nic none)",
            "frozen_payloads": {
                "kernel": {"path": f"images/{kernel_name}", "size": len(kernel_bytes), "sha256": expected["kernel_sha256"]},
                "rootfs_ext4": {"path": f"images/{rootfs_name}", "size": len(rootfs_bytes), "sha256": expected["rootfs_sha256"]},
                "target_library_sha256": expected["library_sha256"],
                "target_harness_sha256": expected["harness_sha256"],
            },
            "members": list(writer.members),
        }
        inv_bytes = (json.dumps(inner_inv, indent=2, sort_keys=True) + "\n").encode("utf-8")
        check_no_host_or_secrets(f"{variant}:bundle-inventory.json", inv_bytes)
        writer.add_bytes(f"{root_dir}/bundle-inventory.json", inv_bytes, 0o644)
    finally:
        writer.close()

    return {
        "filename": output_path.name,
        "variant": variant,
        "size": output_path.stat().st_size,
        "sha256": sha256_file(output_path),
        "inner_kernel_sha256": expected["kernel_sha256"],
        "inner_rootfs_sha256": expected["rootfs_sha256"],
        "member_count": len(writer.members),
    }


def package_all(*, repo_root, baseline_tar, baseline_tar_sha, patched_tar, patched_tar_sha,
                baseline_spdx, baseline_manifest_json, patched_spdx, patched_manifest_json,
                glibc_git_tar, glibc_git_tar_sha, pkggrp_bb, pkggrp_bb_sha,
                producer_commit, output_dir):
    require(not output_dir.exists(), f"output directory must not already exist: {output_dir}")
    require(sha256_file(baseline_tar) == baseline_tar_sha, "baseline deploy.tar SHA-256 mismatch before packaging")
    require(sha256_file(patched_tar) == patched_tar_sha, "patched deploy.tar SHA-256 mismatch before packaging")
    require(sha256_file(glibc_git_tar) == glibc_git_tar_sha, "glibc git archive SHA-256 mismatch")
    require(sha256_file(pkggrp_bb) == pkggrp_bb_sha, "packagegroup-core-boot.bb SHA-256 mismatch")

    b_man = json.loads(baseline_manifest_json.read_text())
    p_man = json.loads(patched_manifest_json.read_text())
    require(len(b_man["installed_packages"]) == 41 and len(p_man["installed_packages"]) == 41,
            "expected 41 installed target binary packages in both variants")

    output_dir.mkdir(parents=True)

    b_bundle = build_eval_bundle(
        output_dir / "firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz",
        "baseline", baseline_tar, baseline_spdx, BASELINE_BINS,
    )
    p_bundle = build_eval_bundle(
        output_dir / "firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz",
        "patched", patched_tar, patched_spdx, PATCHED_BINS,
    )

    target_recipes = sorted({
        pkg["recipe_name"]
        for pkg in b_man["installed_packages"] + p_man["installed_packages"]
    })
    required_source_recipes = sorted(set(target_recipes) | {
        "linux-yocto", "gcc-source-11.5.0", "linux-libc-headers", "util-linux-libuuid"
    })

    def wanted_src_member(name):
        if not name.startswith("deploy/sources/"):
            return False
        parts = name.split("/")
        if len(parts) < 5:
            return False
        pf = parts[3]
        return any(pf.startswith(r + "-") for r in required_source_recipes)

    p_sources = extract_deploy_members(patched_tar, wanted_src_member)
    b_lws_sources = extract_deploy_members(
        baseline_tar,
        lambda n: n.startswith("deploy/sources/") and "/libwebsockets-4.2.2-r0/" in n,
    )
    require(bool(b_lws_sources), "missing baseline libwebsockets-4.2.2-r0 sources in baseline deploy.tar")

    src_archive_path = output_dir / "firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz"
    src_writer = DeterministicTarGz(src_archive_path)
    recipe_to_src_members = {r: [] for r in target_recipes + ["linux-yocto"]}
    try:
        all_src = dict(p_sources)
        all_src.update(b_lws_sources)
        for member_name in sorted(all_src):
            rel = "yocto-sources/" + member_name[len("deploy/sources/"):]
            src_writer.add_bytes(rel, all_src[member_name], 0o644)
            pf = member_name.split("/")[3]
            for r in recipe_to_src_members:
                if pf.startswith(r + "-"):
                    recipe_to_src_members[r].append(rel)
            if pf.startswith("gcc-source-11.5.0-"):
                recipe_to_src_members["libgcc"].append(rel)
            if pf.startswith("linux-libc-headers-"):
                recipe_to_src_members["glibc"].append(rel)

        # Add complete upstream glibc-2.35 git source archive (bb59339d02faebac534a87eea50c83c948f35b77)
        glibc_arc = f"yocto-sources/aarch64-poky-linux/glibc-2.35-r0/{glibc_git_tar.name}"
        src_writer.add_bytes(glibc_arc, glibc_git_tar.read_bytes(), 0o644)
        recipe_to_src_members["glibc"].append(glibc_arc)

        # Add packagegroup-core-boot metadata recipe
        pkggrp_arc = "yocto-sources/qemuarm64-poky-linux/packagegroup-core-boot-1.0-r17/packagegroup-core-boot.bb"
        src_writer.add_bytes(pkggrp_arc, pkggrp_bb.read_bytes(), 0o644)
        recipe_to_src_members["packagegroup-core-boot"].append(pkggrp_arc)

        # Include sample repository build scripts, kas locks, repair layer, and test layer
        build_dirs = ("LICENSE", "conf", "kas", "recipes-connectivity", "meta-firmdura-tests", "tests/boot-reference.py", "tests/run-cve-2026-19773.py")
        build_files = []
        for entry in build_dirs:
            p = repo_root / entry
            if p.is_file():
                build_files.append(p)
            elif p.is_dir():
                build_files.extend(sorted(f for f in p.rglob("*") if f.is_file()))
        for fpath in sorted(set(build_files)):
            rel = "build-configuration/" + fpath.relative_to(repo_root).as_posix()
            raw = fpath.read_bytes()
            check_no_host_or_secrets(rel, raw)
            mode = 0o755 if os.access(fpath, os.X_OK) else 0o644
            src_writer.add_bytes(rel, raw, mode)
    finally:
        src_writer.close()

    # Package licences and notices as a POSIX tar.gz preserving case-sensitive filenames
    required_lic_dirs = set(target_recipes) | {"linux-yocto", "gcc", "gcc-runtime", "linux-libc-headers"}
    p_lics = extract_deploy_members(
        patched_tar,
        lambda n: n.startswith("deploy/licenses/") and (
            n.split("/")[2] in required_lic_dirs
            or n.split("/")[2].startswith("firmdura-reference-patched-qemuarm64-")
        ),
    )
    b_lics = extract_deploy_members(
        baseline_tar,
        lambda n: n.startswith("deploy/licenses/") and n.split("/")[2].startswith("firmdura-reference-baseline-qemuarm64-"),
    )
    lic_archive_path = output_dir / "firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz"
    lic_writer = DeterministicTarGz(lic_archive_path)
    recipe_to_lic_members = {r: [] for r in target_recipes + ["linux-yocto"]}
    try:
        lic_writer.add_bytes("firmdura-original-files/LICENSE.MIT", (repo_root / "LICENSE").read_bytes(), 0o644)
        combined_lics = dict(p_lics)
        combined_lics.update(b_lics)
        for member_name in sorted(combined_lics):
            rel = "yocto-licenses/" + member_name[len("deploy/licenses/"):]
            lic_writer.add_bytes(rel, combined_lics[member_name], 0o644)
            top = member_name.split("/")[2]
            if top in recipe_to_lic_members:
                recipe_to_lic_members[top].append(rel)
            if top in ("gcc", "gcc-runtime"):
                recipe_to_lic_members["libgcc"].append(rel)
    finally:
        lic_writer.close()

    # Fail-closed redistribution audit: EVERY distributed binary & package MUST have archived upstream/local source AND licence files
    src_member_Set = {m["path"] for m in src_writer.members}
    for r, members in sorted(recipe_to_src_members.items()):
        require(bool(members), f"redistribution gap: recipe {r} has zero archived source files")
        has_upstream_or_local_code = any(
            not m.endswith(("-recipe.tar.xz", ".patch", ".diff"))
            for m in members
        )
        require(has_upstream_or_local_code,
                f"redistribution gap: recipe {r} has only recipe metadata without source payload: {members}")
        for m in members:
            require(m in src_member_Set, f"missing promised source member {m}")

    for r, members in sorted(recipe_to_lic_members.items()):
        require(bool(members), f"redistribution gap: recipe {r} has zero licence files")

    # Reverify frozen producer deploy.tar archives were not mutated
    require(sha256_file(baseline_tar) == baseline_tar_sha, "baseline deploy.tar mutated during packaging")
    require(sha256_file(patched_tar) == patched_tar_sha, "patched deploy.tar mutated during packaging")

    inventory = {
        "schema_version": 1,
        "producer_source_commit": producer_commit,
        "bundles": {
            "baseline": b_bundle,
            "patched": p_bundle,
            "corresponding_source": {
                "filename": src_archive_path.name,
                "size": src_archive_path.stat().st_size,
                "sha256": sha256_file(src_archive_path),
                "member_count": len(src_writer.members),
            },
            "licenses_and_notices": {
                "filename": lic_archive_path.name,
                "size": lic_archive_path.stat().st_size,
                "sha256": sha256_file(lic_archive_path),
                "member_count": len(lic_writer.members),
            },
        },
        "distributed_kernel": {
            "binary": "Image--5.15.211+git0+73e7c4ea36_e3ab4c73da-r0-qemuarm64-20261117213416.bin",
            "sha256": PATCHED_BINS["kernel_sha256"],
            "recipe": "linux-yocto",
            "source_members": sorted(set(recipe_to_src_members["linux-yocto"])),
            "license_members": sorted(set(recipe_to_lic_members["linux-yocto"])),
        },
        "distributed_packages": {
            variant_name: [
                {
                    "package": pkg["name"],
                    "version": pkg["manifest_version"],
                    "architecture": pkg["manifest_architecture"],
                    "recipe": pkg["recipe_name"],
                    "packaged_file_count": pkg["file_count"],
                    "source_member_count": len(set(recipe_to_src_members[pkg["recipe_name"]])),
                    "source_members": sorted(set(recipe_to_src_members[pkg["recipe_name"]])),
                    "license_members": sorted(set(recipe_to_lic_members[pkg["recipe_name"]])),
                }
                for pkg in man["installed_packages"]
            ]
            for variant_name, man in (("baseline", b_man), ("patched", p_man))
        },
        "frozen_inputs_unchanged": True,
    }
    inv_path = output_dir / "firmdura-kirkstone-qemuarm64-redistribution-inventory.json"
    inv_raw = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode("utf-8")
    check_no_host_or_secrets("redistribution-inventory.json", inv_raw)
    inv_path.write_bytes(inv_raw)
    inventory["inventory_file"] = {
        "filename": inv_path.name,
        "size": inv_path.stat().st_size,
        "sha256": sha256_file(inv_path),
    }
    return inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--baseline-deploy-tar", required=True, type=Path)
    parser.add_argument("--baseline-deploy-tar-sha256", required=True)
    parser.add_argument("--patched-deploy-tar", required=True, type=Path)
    parser.add_argument("--patched-deploy-tar-sha256", required=True)
    parser.add_argument("--baseline-spdx", required=True, type=Path)
    parser.add_argument("--baseline-spdx-manifest", required=True, type=Path)
    parser.add_argument("--patched-spdx", required=True, type=Path)
    parser.add_argument("--patched-spdx-manifest", required=True, type=Path)
    parser.add_argument("--glibc-git-tar", required=True, type=Path)
    parser.add_argument("--glibc-git-tar-sha256", required=True)
    parser.add_argument("--pkggrp-bb", required=True, type=Path)
    parser.add_argument("--pkggrp-bb-sha256", required=True)
    parser.add_argument("--producer-commit", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    inv = package_all(
        repo_root=args.repo_root.resolve(),
        baseline_tar=args.baseline_deploy_tar,
        baseline_tar_sha=args.baseline_deploy_tar_sha256,
        patched_tar=args.patched_deploy_tar,
        patched_tar_sha=args.patched_deploy_tar_sha256,
        baseline_spdx=args.baseline_spdx,
        baseline_manifest_json=args.baseline_spdx_manifest,
        patched_spdx=args.patched_spdx,
        patched_manifest_json=args.patched_spdx_manifest,
        glibc_git_tar=args.glibc_git_tar,
        glibc_git_tar_sha=args.glibc_git_tar_sha256,
        pkggrp_bb=args.pkggrp_bb,
        pkggrp_bb_sha=args.pkggrp_bb_sha256,
        producer_commit=args.producer_commit,
        output_dir=args.output_dir,
    )
    print(json.dumps({
        "status": "packaged",
        "bundles": inv["bundles"],
        "inventory_file": inv["inventory_file"],
        "frozen_inputs_unchanged": inv["frozen_inputs_unchanged"],
    }, indent=2))


if __name__ == "__main__":
    main()

