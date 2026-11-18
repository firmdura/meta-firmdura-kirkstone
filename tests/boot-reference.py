#!/usr/bin/env python3
"""Boot and identify the reference image; this is not a vulnerability test."""

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


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", required=True)
    parser.add_argument("--kernel", required=True, type=Path)
    parser.add_argument("--rootfs", required=True, type=Path)
    parser.add_argument("--library-sha256", required=True)
    parser.add_argument("--library-version", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.library_sha256):
        parser.error("--library-sha256 must be a lowercase SHA-256 digest")

    originals = {"kernel": sha256(args.kernel), "rootfs": sha256(args.rootfs)}
    started = time.monotonic()
    observations = {}
    with tempfile.TemporaryDirectory(prefix="firmdura-boot-") as directory:
        copy = Path(directory) / "rootfs.ext4"
        shutil.copyfile(args.rootfs, copy)
        if sha256(copy) != originals["rootfs"]:
            raise RuntimeError("Disposable rootfs copy does not match its original")
        command = [
            "-machine", "virt", "-cpu", "cortex-a57", "-smp", "2", "-m", "512",
            "-nographic", "-nic", "none", "-kernel", str(args.kernel),
            "-drive", f"id=disk0,file={copy},if=none,format=raw",
            "-device", "virtio-blk-pci,drive=disk0",
            "-object", "rng-random,filename=/dev/urandom,id=rng0",
            "-device", "virtio-rng-pci,rng=rng0",
            "-device", "virtio-serial-pci",
            "-chardev", "null,id=virtcon",
            "-device", "virtconsole,chardev=virtcon",
            "-append", "console=ttyAMA0 root=/dev/vda rw",
        ]
        print(json.dumps({"qemu": args.qemu, "argv": command, "originals": originals}),
              flush=True)
        child = pexpect.spawn(args.qemu, command, encoding="utf-8", timeout=120)
        child.logfile = sys.stdout
        sequence = 0

        def guest(command):
            nonlocal sequence
            sequence += 1
            marker = f"__FIRMDURA_RC_{sequence}__="
            child.sendline(command + f"; rc=$?; printf '\\n{marker}%s\\n' \"$rc\"")
            # The numeric result cannot match the echoed printf format string.
            child.expect(re.escape(marker) + r"([0-9]+)\r*\n", timeout=30)
            output = child.before.replace("\r", "")
            status = int(child.match.group(1))
            child.expect_exact("__FIRMDURA_PROMPT__ ", timeout=30)
            if status != 0:
                raise RuntimeError(f"Guest command exited {status}: {command}")
            return output

        try:
            child.expect("qemuarm64 login:")
            child.sendline("root")
            child.expect(r"root@qemuarm64:[^\r\n]*# ")
            child.sendline("export PS1='__FIRMDURA_PROMPT__ '")
            child.expect(r"\r*\n__FIRMDURA_PROMPT__ ")

            architecture = guest("uname -m")
            if not re.search(r"(?m)^aarch64$", architecture):
                raise RuntimeError("Guest is not aarch64")
            observations["architecture"] = "aarch64"
            observations["kernel"] = guest("uname -r")
            distro = guest("cat /etc/issue")
            if "Poky (Yocto Project Reference Distro) 4.0.35" not in distro:
                raise RuntimeError("Guest distro differs from the pinned reference")
            observations["distro_banner"] = distro

            library = guest("sha256sum /usr/lib/libwebsockets.so.18")
            match = re.search(
                r"(?m)^([0-9a-f]{64})  /usr/lib/libwebsockets\.so\.18$", library
            )
            if match is None or match.group(1) != args.library_sha256:
                raise RuntimeError("Guest library differs from the built package/rootfs")
            observations["library_sha256"] = match.group(1)
            guest("test -x /usr/bin/ptest-runner")

            banner = guest(
                "libwebsockets-test-server -i lo -p 7681 -d 15 "
                ">/tmp/firmdura-library.log 2>&1 & lws_pid=$!; sleep 1; "
                "cat /tmp/firmdura-library.log && kill -0 \"$lws_pid\""
            )
            if f"LWS: {args.library_version}," not in banner:
                raise RuntimeError("Runtime library version differs from its build header")
            if "NET CLI SRV H1 H2 WS" not in banner:
                raise RuntimeError("Runtime client/server/HTTP/2 feature banner is missing")
            observations["library_version"] = args.library_version
            observations["runtime_features"] = "NET CLI SRV H1 H2 WS"
            observations["loaded_library"] = guest(
                "grep -F /usr/lib/libwebsockets.so.18 /proc/\"$lws_pid\"/maps"
            )
            guest("kill \"$lws_pid\"")
            child.sendline("poweroff")
            child.expect(pexpect.EOF, timeout=90)
            child.close()
            if child.exitstatus != 0:
                raise RuntimeError(
                    f"QEMU exit={child.exitstatus}, signal={child.signalstatus}"
                )
        finally:
            child.close(force=True)
            after = {"kernel": sha256(args.kernel), "rootfs": sha256(args.rootfs)}
            print(json.dumps({"originals_after": after}), flush=True)
            if originals != after:
                raise RuntimeError("Frozen kernel or rootfs changed during the boot test")

    print(json.dumps({
        "status": "passed",
        "scope": "boot-and-library-identity-only",
        "elapsed_seconds": time.monotonic() - started,
        "observations": observations,
        "originals_unchanged": True,
    }, indent=2), flush=True)


if __name__ == "__main__":
    main()
