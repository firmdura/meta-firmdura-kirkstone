# Baseline checks, target reproduction, paired repair, and scanner preflight

The clean baseline build, boot/library checks, target `CVE-2026-19773`
reproduction, and paired `baseline`/`patched` candidate validation are
recorded in
[`evidence/20261118-sti110-paired-validation/run.json`](../evidence/20261118-sti110-paired-validation/run.json).
The [handoff review](../evidence/20261118-sti108-handoff/run.json) rechecked
the initial build/boot identities, and the
[target reproduction record](../evidence/20261118-sti109-reproduction/run.json)
froze the target security and normal-path HTTP/2 test contract. The
[baseline run](../evidence/20261117-sti108-baseline/run.json) recorded
`blocked` for the combined build and scanner checks. The image built and
booted, but scanner preflight was incomplete.
On November 18, 2026, engineering review confirmed the patch scope, expected
test outcomes, and limits of the evidence. The two images reviewed that day
were frozen for packaging.

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

On November 18, the stock Grype database still had no match for this CVE.
A separate test database was used to check how Grype applied the OpenVEX
statement. The [scanner guide](scanner.md) records both results. The stock
feed limitation was documented in the [v0.1.0 release](release.md).

## Target reproduction and frozen test contract (`CVE-2026-19773`)

### HTTP/2 HPACK `:path` boundary and upstream repair analysis

[ZDI-26-590](https://www.zerodayinitiative.com/advisories/ZDI-26-590/)
(`CVE-2026-19773`) affects server-side HTTP/2 HPACK `:path` header decoding in
`libwebsockets`. Each HTTP stream attaches a pooled `struct allocated_headers`
whose `ah->data` heap buffer has length `context->max_http_header_data`.
In `libwebsockets` 4.2.2 (`8d605f0649ed1ab6d27a443c7688598ea21fdb75`),
`lws_frag_append()` (`lib/roles/h2/hpack.c:273`) writes the incoming byte
**before** checking whether `ah->pos` has already reached or exceeded
`max_http_header_data`:

```c
static int lws_frag_append(struct lws *wsi, unsigned char c)
{
    struct allocated_headers *ah = wsi->http.ah;

    ah->data[ah->pos++] = (char)c;
    ah->frags[ah->nfrag].len++;

    return (unsigned int)ah->pos >= wsi->a.context->max_http_header_data;
}
```

During HPACK `:path` value decoding (`lws_hpack_interpret()`,
`lib/roles/h2/hpack.c:1148`), every decoded character first passes through
`lws_parse_urldecode()` (`lib/roles/http/parsers.c:774`). When `:path` contains
`'?'` (`parsers.c:942`) or unescaped `'&'` / `';'` (`parsers.c:842`),
`lws_parse_urldecode()` writes a terminating NUL via `issue_char(wsi, '\0')`
(allowed whenever `ah->pos < max_http_header_data`), then executes
`ah->frags[ah->nfrag].offset = ++ah->pos;` without a bounds check and returns
`LPUR_SWALLOW`:

- If `ah->pos == max_http_header_data - 2` before `'?'`, `issue_char()` writes
  `ah->data[max_http_header_data - 2] = '\0'` and `++ah->pos` advances
  `ah->pos` to **`max_http_header_data`** (`+0` past the buffer).
- If `ah->pos == max_http_header_data - 1` before `'?'` or `';'`, `issue_char()`
  writes `ah->data[max_http_header_data - 1] = '\0'` and `++ah->pos` advances
  `ah->pos` to **`max_http_header_data + 1`** (`+1` past the buffer).

On the next `:path` character (or the trailing NUL in `lws_frag_end()`),
`lws_frag_append()` writes attacker-controlled byte `c` out of bounds at
`ah->data[max_http_header_data]` or `ah->data[max_http_header_data + 1]`.

Upstream repair analysis across `v4.2.2` through `main`:

- **Primary fix**
  ([`824151862f37bc72f46d9a3e01d5b9408d313a0b`](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b)):
  guards `lws_frag_append()` prior to storing `c` with
  `if ((unsigned int)ah->pos >= wsi->a.context->max_http_header_data) return 1;`.
  `lws_frag_append()` in 4.2.2 matches the commit's parent without missing
  structural prerequisites.
- **Related URI-parser follow-ups**:
  [`0c6cef0922c531f2662e87e74e17c191fa18162b`](https://github.com/warmcat/libwebsockets/commit/0c6cef0922c531f2662e87e74e17c191fa18162b)
  checks `ah->pos >= max_http_header_data` right after `++ah->pos` on `'?'`, and
  [`523b6f2efdeb36e1e0a4f4004862a216624e9f8f`](https://github.com/warmcat/libwebsockets/commit/523b6f2efdeb36e1e0a4f4004862a216624e9f8f)
  bounds the parallel `'&'` / `';'` split so `ah->frags[ah->nfrag].offset` is
  never left pointing past `ah->data` before `lws_dynamic_token_insert()` or
  `lws_frag_end()`.

### Packaged C harness, normal controls, and incomplete-fix controls

The test-only recipe
[`firmdura-lws-h2-tests_1.0.bb`](../meta-firmdura-tests/recipes-connectivity/firmdura-lws-h2-tests/firmdura-lws-h2-tests_1.0.bb)
installs `/usr/bin/firmdura-h2-cve-2026-19773` and its `ptest-runner` wrapper
`/usr/lib/firmdura-lws-h2-tests/ptest/run-ptest` into
`firmdura-reference-image`. At startup the binary resolves `lws_create_context`
via `dladdr()` and `/proc/self/maps` to verify that
`/usr/lib/libwebsockets.so.18` is mapped in-process. Each scenario forks an
isolated `LWS_SERVER_OPTION_H2_PRIOR_KNOWLEDGE` server bound to loopback `lo`
with `max_http_header_data = 1048` (`0x418`, allocating a `0x420`-byte chunk
above glibc 2.35's `0x410` tcache ceiling):

1. **Normal-path HTTP/2 controls (`--mode normal-only`)**: Exchanges valid
   HTTP/2 client preface, `SETTINGS`, and HPACK `GET /health?ok=1&case=...`
   frames over loopback TCP, requiring HTTP/2 `200` headers and body echo both
   under the stock allocator and with an in-bounds near-limit `:path` under a
   `PROT_NONE` guard page. Any normal-control, linkage, or socket failure exits
   `2` (`infrastructure` error), never `0` or `1`.
2. **Vector 1 (`v1_query_at_limit_minus_2`, OOB offset `+0`)**: Positions
   `ah->pos` at `1046` before `'?'` followed by `'Z'` (`0x5a`), checking both
   trailing canary corruption (`canary[0] == 0x5a`) and hardware `PROT_NONE`
   guard-page `SIGSEGV` (`SEGV_ACCERR` at `ah_end + 0`).
3. **Vector 2 (`v2_query_past_limit_incomplete_eq_control`, OOB offset `+1`)**:
   Positions `ah->pos` at `1047` before `"?Z"` so `++ah->pos` jumps to `1049`,
   catching an incomplete repair that checks `ah->pos == max_http_header_data`
   instead of `>=`.
4. **Vector 3 (`v3_semicolon_delimiter_incomplete_qmark_control`, OOB offset `+1`)**:
   Uses `";Z"` without `'?'` at `ah->pos == 1047`, catching an incomplete
   repair that patches only `'?'` in `lws_parse_urldecode()` without guarding
   `lws_frag_append()` and `;`/`&`.
5. **Unhooked stock glibc allocator check (`stock_glibc_allocator`)**: Runs
   without `lws_set_allocator()`, proving that writing `0x5a` (`PREV_INUSE` bit
   cleared) at `ah->data[1048]` corrupts adjacent glibc 2.35 chunk metadata and
   aborts (`SIGABRT`: `munmap_chunk(): invalid pointer`) on `lws_context_destroy()`.

Exit-code contract:

- `0`: Normal HTTP/2 controls passed AND all 7 security subchecks rejected the
  oversized `:path` frames cleanly with zero out-of-bounds writes, zero crashes,
  and verified post-attack HTTP/2 `200` liveness (expected on repaired target).
- `1`: Normal HTTP/2 controls passed AND all 7 security subchecks positively
  reproduced the targeted out-of-bounds write inside `libwebsockets.so.18`
  (expected on vulnerable baseline).
- `2`: Broken setup, library mismatch, failed normal HTTP/2 control, timeout, or
  off-target fault.

### Recorded baseline target execution

Build and run from a clean standalone checkout of the frozen test commit
(`6e3e70b94281c8f75f52f90e77152deba7372c83`):

```sh
FIRMDURA_WORK_VOLUME=firmdura-kirkstone-baseline sh kas/run baseline build

docker --context colima-firmdura-kirkstone run --rm --init \
  --read-only --network none --user "$(id -u):$(id -g)" \
  --cpus 2 --memory 1g --pids-limit 256 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=128m \
  --mount type=volume,source=firmdura-kirkstone-baseline,target=/work,readonly \
  --mount "type=bind,source=$PWD,target=/repo,readonly" \
  --entrypoint python3 "$(cat kas/builder-image.txt)" \
  /repo/tests/run-cve-2026-19773.py \
  --qemu /work/build-baseline/tmp/work/aarch64-linux/qemu-helper-native/1.0-r1/recipe-sysroot-native/usr/bin/qemu-system-aarch64 \
  --kernel /work/build-baseline/tmp/deploy/images/qemuarm64/Image--5.15.211+git0+73e7c4ea36_e3ab4c73da-r0-qemuarm64-20261117213416.bin \
  --rootfs /work/build-baseline/tmp/deploy/images/qemuarm64/firmdura-reference-baseline-qemuarm64-20261118113155.rootfs.ext4 \
  --library-sha256 77809db0b9f6a1f97917292a5976e332de130bed90c21eb219e8032cfe3ae05a \
  --library-version 4.2.1-v4.2.2 \
  --harness-sha256 774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795 \
  --expected-security-outcome vulnerable
```

Observed results in
[`evidence/20261118-sti109-reproduction/run.json`](../evidence/20261118-sti109-reproduction/run.json):

- `/usr/lib/libwebsockets.so.18` remained byte-identical to the initial baseline
  build (`77809db0b9f6a1f97917292a5976e332de130bed90c21eb219e8032cfe3ae05a`).
- Normal HTTP/2 controls passed (`exit 0`) inside the booted `qemuarm64` guest.
- All three HPACK `:path` boundary vectors wrote `0x5a` out of bounds (`+0`,
  `+1`, `+1`) and faulted on the `PROT_NONE` guard page at relative instruction
  offset `0x4049c` inside `/usr/lib/libwebsockets.so.18`, resolved by
  `aarch64-poky-linux-addr2line` to `lws_frag_append` at
  `lib/roles/h2/hpack.c:277` inlined by `lws_hpack_interpret` at
  `lib/roles/h2/hpack.c:1168`.
- The unhooked stock glibc 2.35 scenario terminated with `SIGABRT` (`6`), and
  `ptest-runner firmdura-lws-h2-tests` reported `PASS: firmdura-h2-normal-controls`
  and `FAIL: firmdura-cve-2026-19773-bounds-enforced`.
- Demanding `--expected-security-outcome repaired` or passing an all-zero
  `--library-sha256` each exited `1` as negative controls while leaving the
  frozen kernel and rootfs SHA-256 digests unchanged.

## Paired `baseline` versus `patched` candidate validation

### Scoped repair layer

[`recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend`](../recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend)
scopes the repair explicitly to `libwebsockets` `4.2.2`, sets
`PR:append = ".firmdura1"` while keeping `PV = "4.2.2"` (so CPE identity stays
intact without hiding `CVE-2026-19773` from scanners), and applies two upstream
backports in order:

1. [`CVE-2026-19773-1.patch`](../recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-1.patch)
   ([`824151862f37bc72f46d9a3e01d5b9408d313a0b`](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b)):
   enforces `(unsigned int)ah->pos >= wsi->a.context->max_http_header_data` at
   entry to `lws_frag_append()` (`lib/roles/h2/hpack.c`).
2. [`CVE-2026-19773-2.patch`](../recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-2.patch)
   ([`0c6cef0922c531f2662e87e74e17c191fa18162b`](https://github.com/warmcat/libwebsockets/commit/0c6cef0922c531f2662e87e74e17c191fa18162b)):
   enforces `(unsigned int)ah->pos >= wsi->a.context->max_http_header_data`
   immediately after `ah->frags[ah->nfrag].offset = ++ah->pos;` when `'?'`
   starts `WSI_TOKEN_HTTP_URI_ARGS` in `lws_parse_urldecode()`
   (`lib/roles/http/parsers.c`).

`PACKAGECONFIG` (`libuv client server http2 ssl`), kernel binary, external layer
commits, and the compiled target harness `/usr/bin/firmdura-h2-cve-2026-19773`
(`774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795`) remain
identical across both builds at source commit
`a8a2adb0a299221d6f246f7c95e0912e4babd419`.

### Recorded paired commands and comparison

```sh
FIRMDURA_WORK_VOLUME=firmdura-kirkstone-baseline sh kas/run baseline build
FIRMDURA_WORK_VOLUME=firmdura-kirkstone-baseline sh kas/run patched build

docker --context colima-firmdura-kirkstone run --rm --init \
  --read-only --network none --user "$(id -u):$(id -g)" \
  --cpus 2 --memory 1g --pids-limit 256 \
  --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,nosuid,nodev,mode=1777,size=128m \
  --mount type=volume,source=firmdura-kirkstone-baseline,target=/work,readonly \
  --mount "type=bind,source=$PWD,target=/repo,readonly" \
  --entrypoint python3 "$(cat kas/builder-image.txt)" \
  /repo/tests/run-cve-2026-19773.py \
  --qemu /work/build-baseline/tmp/work/aarch64-linux/qemu-helper-native/1.0-r1/recipe-sysroot-native/usr/bin/qemu-system-aarch64 \
  --kernel /work/build-patched/tmp/deploy/images/qemuarm64/Image--5.15.211+git0+73e7c4ea36_e3ab4c73da-r0-qemuarm64-20261117213416.bin \
  --rootfs /work/build-patched/tmp/deploy/images/qemuarm64/firmdura-reference-patched-qemuarm64-20261118120234.rootfs.ext4 \
  --library-sha256 4aac446382e44af454bed760127683a16faf98a8abb1c257d7564da798a717c5 \
  --library-version 4.2.1-v4.2.2 \
  --harness-sha256 774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795 \
  --expected-security-outcome repaired
```

| Property | `baseline` | `patched` |
|---|---|---|
| Package revision | `libwebsockets18` `4.2.2-r0` | `libwebsockets18` `4.2.2-r0.firmdura1` |
| `/usr/lib/libwebsockets.so.18` SHA-256 | `77809db0b9f6a1f97917292a5976e332de130bed90c21eb219e8032cfe3ae05a` | `4aac446382e44af454bed760127683a16faf98a8abb1c257d7564da798a717c5` |
| `/usr/bin/firmdura-h2-cve-2026-19773` SHA-256 | `774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795` | `774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795` |
| `.rootfs.ext4` SHA-256 (`41` packages) | `6f18018f84e0799faeb30a892f827500e209f7831305748eeb64f41813e197a2` | `92a3d9f9aaf40de580590bff13774d39b51aab8b3494b1e14bea1963e344598d` |
| Consolidated SPDX 2.2 SHA-256 | `050eb32b37945ded03465de1f1f178cb433d7a37c408ee1a0fc83327292e3765` | `f050a6e085b2c61afa3507cd35e977252f3fcf9836f91148c099189e20009110` |
| Runtime feature banner (`boot-reference.py`) | `NET CLI SRV H1 H2 WS` (`passed`) | `NET CLI SRV H1 H2 WS` (`passed`) |
| Normal HTTP/2 controls (`--mode normal-only`) | `passed` (`exit 0`) | `passed` (`exit 0`) |
| `CVE-2026-19773` suite (`--mode full`) | `vulnerable-oob-write-reproduced` (`7/7` OOB, `exit 1`) | `bounds-enforced-secure` (`7/7` blocked, post-attack H2 `200`, `exit 0`) |
| `ptest-runner firmdura-lws-h2-tests` | `PASS` normal, `FAIL` bounds (`exit 1`) | `PASS` normal, `PASS` bounds (`TOTAL: 1 FAIL: 0`, `exit 0`) |
| Upstream `libwebsockets-testapps` (`lejp` + HTTP file transfer) | `passed` (`leaf.jpg` `e72831a0...b44f`) | `passed` (`leaf.jpg` `e72831a0...b44f`) |

Two compiled diagnostic incomplete-repair libraries were also checked against
the frozen target harness binary:

- Checking `ah->pos == max_http_header_data` instead of `>=` blocked Vector 1
  (`+0`) while failing Vectors 2 and 3 (`0x5a` written at `+1`).
- Applying only `CVE-2026-19773-2.patch` (`?` post-bump check) without
  `CVE-2026-19773-1.patch` blocked Vectors 1 and 2 (`?`) while failing Vector 3
  (`;Z` wrote `0x5a` at `+1`).

All paired logs, canonical `deploy.tar` inventories, and consolidated SPDX
identities are indexed in
[`evidence/20261118-sti110-paired-validation/run.json`](../evidence/20261118-sti110-paired-validation/run.json).
The reviewed `baseline` and `patched` image pair is frozen for read-only
consumption by bundle packaging, community contribution, and candidate replay.
