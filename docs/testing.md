# Baseline checks and scanner preflight

The clean image build, boot/library checks and retained inventory are verified.
The [handoff review](../evidence/20261118-sti108-handoff/run.json) rechecked
their identities, logs and canonical archive contents. The historical
[run record](../evidence/20261117-sti108-baseline/run.json) remains unchanged:
its `blocked` status describes the original combined build/scanner gate.
Scanner interoperability is now separate from runtime reproduction and repair.
No vulnerability reproduction, repair, security regression result, paired-image
freeze, VEX statement or release is claimed.

## Boot and identify the actual library

Use the pinned builder, dedicated Docker context and source/storage rules in
[the build contract](build.md). The tested build volume is
`firmdura-kirkstone-baseline`; it started empty without download/sstate reuse.
The immutable build source was
`209222b2f7fbd6a30257b0e064d3f4df18e23692`.

From this checkout, the recorded boot check is:

```sh
docker --context colima-firmdura-kirkstone run --rm --init \
  --read-only --network none --user "$(id -u):$(id -g)" \
  --cpus 2 --memory 1g --pids-limit 256 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=128m \
  --mount type=volume,source=firmdura-kirkstone-baseline,target=/work,readonly \
  --mount "type=bind,source=$PWD,target=/repo,readonly" \
  --entrypoint python3 "$(cat kas/builder-image.txt)" \
  /repo/tests/boot-reference.py \
  --qemu /work/build-baseline/tmp/work/aarch64-linux/qemu-helper-native/1.0-r1/recipe-sysroot-native/usr/bin/qemu-system-aarch64 \
  --kernel /work/build-baseline/tmp/deploy/images/qemuarm64/Image--5.15.211+git0+73e7c4ea36_e3ab4c73da-r0-qemuarm64-20261117213416.bin \
  --rootfs /work/build-baseline/tmp/deploy/images/qemuarm64/firmdura-reference-baseline-qemuarm64-20261117213416.rootfs.ext4 \
  --library-sha256 77809db0b9f6a1f97917292a5976e332de130bed90c21eb219e8032cfe3ae05a \
  --library-version 4.2.1-v4.2.2
```

These are measured filenames for this run, not predictions for later builds.
Discover new outputs and verify their package/SBOM hashes before substituting
them. The pinned builder already provides Python 3.11 and pexpect 4.8.0;
the actual Yocto-native emulator reports QEMU 6.2.0.

The helper boots a disposable ext4 copy in tmpfs, with no guest NIC or
published service. It checks `aarch64`, the Poky 4.0.35 banner, the library
SHA-256, an executable ptest runner, the live server's `NET CLI SRV H1 H2 WS`
banner, and its `/proc/<pid>/maps` entry for the shared library. It powers
off the guest and verifies the original kernel/rootfs hashes again.
This does **not** run ptest suites, exercise an exploit, or establish a
functional HTTP/2/security regression contract.

The package is `libwebsockets18` **4.2.2-r0**, from upstream commit
`8d605f0649ed1ab6d27a443c7688598ea21fdb75`, with no local source patches.
That upstream tag's generated header and runtime banner say
**4.2.1-v4.2.2**. Both identities are retained; the display-version mismatch
was not "fixed" by changing the baseline. The IPK, rootfs archive, native
package SPDX file and running target agree on the library's SHA-256.
The minimal image has neither an opkg status database nor `/etc/os-release`;
provenance comes from the actual package/manifest/SBOM and matching bytes,
not a fabricated target package-manager report.

The committed-helper replay passed in 15.462019 seconds of command elapsed time.
Repeating it with a 64-zero `--library-sha256` deliberately exited 1 at the
identity guard, leaving the originals unchanged. Two early attempts failed
on serial CR/CRLF framing and an incorrect `/etc/os-release` assumption;
their logs remain retained. The helper now handles the observed serial
framing and uses the image's installed `/etc/issue` banner.

## Released scanner and frozen database

- Grype **0.122.0**, source
  `4419483072181b643c3efde0fd15b9113d88887f`, embedded Syft **1.57.2**.
- ARM64 image:
  `docker.io/anchore/grype@sha256:68205d0d11c88aec5999c3139b04ebc242f8b41c40322d2a56b7e880f1e641b4`.
- Database **v6.1.10**, built **2026-11-17T06:20:58Z**.
- Vendor archive SHA-256:
  `3f0cbdbc9d40fb69eaeacec1869b27a8c74f1894108804ace8b7468513e2df07`.
- Retained SQLite SHA-256:
  `303ba44739343769e0e15bd0d50af62e142491b256bb533a8cfaf13ab00ca1b7`.

Actual scans ran offline with the database mounted read-only, automatic
updates disabled, hash/age validation enabled, no VEX, no distro override,
no automatic CPE generation and no user exclusions. Grype injects four
built-in kernel-header ignore rules; they do not target libwebsockets.
The diagnostic scans additionally retained matcher suppressions. Complete
JSON/configuration/database identities are indexed, including all findings.
A later stale-database error is not a scan verdict: do not silently update
the frozen database or call an expired snapshot current.

## Why preflight is blocked

| Actual input | Findings | Required CVE-2026-19773 |
|---|---|---|
| Native image SPDX root document | Empty, invalid as a full inventory scan | Absent |
| Native libwebsockets recipe SPDX | Empty | Absent |
| Same recipe, only CPE reference-type spelling normalized | CVE-2025-1866 retained | Absent |
| Exact CPE emitted by the build, scanned directly | CVE-2025-1866 retained | Absent |

The native image document contains one image package and 78 external
document references, not a flattened inventory of its 39 installed packages.
The binary-package document references its recipe and does not carry the
recipe's CPE itself. Scanning only the root document does not traverse that
inventory.

The recipe carries
`cpe:2.3:a:*:libwebsockets:4.2.2:*:*:*:*:*:*:*`, with reference type
`http://spdx.org/rdf/references/cpe23Type`. The released
[Syft decoder](https://github.com/anchore/syft/blob/v1.57.2/syft/format/common/spdxhelpers/to_syft_model.go#L866)
does not recognize that full-URI spelling. A controlled diagnostic changed
only that JSON field to `cpe23Type`; package name, version and CPE were
unchanged. It then matched the real component. The original SBOM and all
referenced files remain intact. This is a component-only diagnosis, not a
completed full-image SBOM adapter or VEX integration.

Even after that correction, the frozen database has **zero NVD
affected-package records** for CVE-2026-19773. Its affected-package entries
are for Debian, Echo and Ubuntu, not this Yocto image. The
[NVD record](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-19773)
was **Awaiting Analysis**, with no applicability configurations, when
captured. No package identity or vulnerability mapping was injected.

CVE-2025-1866 is explicitly **Win32-only** in its advisory/database
description. Its version-only match is retained as unresolved scanner output,
not accepted as a replacement Linux case or removed through VEX.

The earlier scanner-only hold was superseded on 2026-11-18 by an approved
separation of the runtime and scanner work. The verified baseline can be used
for target reproduction and repair without waiting for a scanner match.
The selected case has not changed, and applicability still requires actual
target evidence; never remove an existing fix or weaken the test.

The scanner blocker remains open in STI-119. It prevents VEX acceptance and
publication, not runtime work. A new supported normalization or database check
must retain new inputs and results rather than overwrite this snapshot.
Signing preparation is independent. Human engineering/release review, genuine
scanner findings and the paired-artifact VEX controls remain mandatory.
