# Independent candidate replay and repair evidence review

This document records the independent replay and engineering audit of the frozen
`baseline` and `patched` `qemuarm64` reference candidate at repository commit
`e34b065bb6c4e78f956fd711dd5d0e6c783de343` (zero build, layer, recipe, or
target-test payload differences relative to paired build commit
`a8a2adb0a299221d6f246f7c95e0912e4babd419`). All command logs, exit statuses,
measured digests, and timing intervals are indexed in
[`evidence/20261118-sti115-replay/run.json`](../evidence/20261118-sti115-replay/run.json).

## Frozen input verification and post-replay immutability

Ten frozen candidate inputs were hashed before executing any replay command and
re-hashed after all QEMU boots, clean-volume rebuilds, SBOM/OpenVEX scans, and
redistribution checks completed. Every byte size and SHA-256 digest remained
unchanged:

| Input artifact | Size (bytes) | Pre- and post-replay SHA-256 | Verified status |
|---|---:|---|---|
| `firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz` | `16,416,902` | `ca423ae7d57f411c44916651413b6d6f3ad45d39aac4abb70498800ecd8891b0` | Unchanged |
| `firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz` | `16,419,741` | `aa04251544a1ff48e690620591255f029ca361871acc48af63ee785b462c8678` | Unchanged |
| `firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz` | `436,645,082` | `ad8bded335da769b16cf66a4b3279e93e9667e6839c1dd82cce3f8a24c86c3ef` | Unchanged |
| `firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz` | `250,996` | `351d071eae6de20bd95af40356ba98c353953e7fcfaa4129c4bb5a06c5f15a76` | Unchanged |
| `firmdura-kirkstone-qemuarm64-redistribution-inventory.json` | `169,376` | `e66a37683054d0c70963e6f171e271d2530fdcc0f793687fb4959d9e7d635427` | Unchanged |
| Canonical `baseline` `deploy.tar` | `1,987,225,600` | `2c86ce06bb56f07c01eae0d3fee277adeb6ec487ed93c23e5d4bca53a437ba3b` | Unchanged |
| Canonical `patched` `deploy.tar` | `1,992,468,480` | `7b53c6ea6a846b4182ec40134314d25f091b0b3a3cd2509922e13c5769e306e6` | Unchanged |
| `baseline-41pkg-consolidated.spdx.json` | `262,387` | `050eb32b37945ded03465de1f1f178cb433d7a37c408ee1a0fc83327292e3765` | Unchanged |
| `patched-41pkg-consolidated.spdx.json` | `262,415` | `f050a6e085b2c61afa3507cd35e977252f3fcf9836f91148c099189e20009110` | Unchanged |
| [`vex/firmdura-kirkstone-cve-2026-19773.openvex.json`](../vex/firmdura-kirkstone-cve-2026-19773.openvex.json) | `2,970` | `68850d630989bd25002f495c43b9cd4090cefde299774274f0d1b80e348b906e` | Unchanged |

`git diff --exit-code a8a2adb0a299221d6f246f7c95e0912e4babd419..e34b065bb6c4e78f956fd711dd5d0e6c783de343 -- conf kas recipes-connectivity meta-firmdura-tests tests/run-cve-2026-19773.py`
returned empty (`exit 0`), confirming that subsequent commits between the
paired build and `e34b065bb6c4e78f956fd711dd5d0e6c783de343` added packaging,
OpenVEX, signing, and documentation tooling without altering any BitBake layer,
recipe, patch, or target test binary input.

## Standalone prebuilt QEMU bundle replay

Both evaluation bundles documented in [the evaluation guide](evaluation.md) were
streamed into clean disposable tmpfs directories inside the pinned ARM64
container (`ghcr.io/siemens/kas/kas@sha256:718b8f0dbf8174645ddb18c7979e7a635a4ed7bd55e750d75c1c8091454b8ce7`)
with `--network none`, `--read-only`, no repository bind mount, and
`firmdura-kirkstone-baseline` mounted `readonly` solely to supply the
Yocto-built `qemu-system-aarch64` emulator:

- **Prebuilt `baseline` bundle (`run-evaluation.py`, `16.04 s`)**:
  - Guest verified `aarch64`, `Poky 4.0.35`, `/usr/lib/libwebsockets.so.18`
    (`77809db0b9f6a1f97917292a5976e332de130bed90c21eb219e8032cfe3ae05a`), and
    `/usr/bin/firmdura-h2-cve-2026-19773`
    (`774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795`).
  - `--mode normal-only` passed (`exit 0`, `"verdict": "normal-controls-passed"`).
  - `--mode full` exited `1` (`"verdict": "vulnerable-oob-write-reproduced"`)
    specifically due to the `7/7` targeted `CVE-2026-19773` out-of-bounds write
    subchecks across all three boundary vectors (`0x5a` canary overwrite at
    offsets `0`/`1`, `SIGSEGV` `SEGV_ACCERR` on the `PROT_NONE` guard page at
    `libwebsockets.so.18+0x4049c`, and `SIGABRT` `term_sig: 6` under stock
    glibc heap allocation).
  - `ptest-runner firmdura-lws-h2-tests` passed normal HTTP/2 controls and
    exited `1` (`TOTAL: 1 FAIL: 1`) on
    `FAIL: firmdura-cve-2026-19773-bounds-enforced`.
- **Prebuilt `patched` bundle (`run-evaluation.py`, `16.20 s`, plus standalone
  `launch-qemu.sh`, `14.79 s`)**:
  - Guest verified `/usr/lib/libwebsockets.so.18`
    (`4aac446382e44af454bed760127683a16faf98a8abb1c257d7564da798a717c5`) and
    identical harness digest (`774de9bf...`).
  - `--mode normal-only` passed (`exit 0`).
  - `--mode full` passed (`exit 0`, `"verdict": "bounds-enforced-secure"`,
    `clean_blocked_subchecks: 7`, `oob_reproduced_subchecks: 0`, and HTTP/2
    `200` liveness preserved after every oversized `:path` case across canary,
    guard-page, and stock-allocator runs).
  - `ptest-runner firmdura-lws-h2-tests` exited `0` (`TOTAL: 1 FAIL: 0`), and
    direct execution via `launch-qemu.sh` verified its safety banner, disposable
    rootfs copy guard, `-nic none` isolation, and clean `poweroff`.

## Clean-volume source rebuild and binary comparison

### Declared cache and download policy

To rebuild both variants from source within the dedicated ARM64 builder VM's
`16 GiB` free disk budget while enforcing BitBake's `5 GB` `BB_DISKMON_DIRS`
floor, a fresh Docker volume (`firmdura-kirkstone-sti115-replay`) and a
standalone local Git clone at `e34b065bb6c4e78f956fd711dd5d0e6c783de343` (used
because [`kas/run`](../kas/run) bind-mounts a single read-only repository root)
were initialized under the following strict reuse policy:

1. **Zero copied layer checkouts or build directories**: `sh kas/run baseline checkout`
   cloned `poky`, `meta-openembedded`, and `meta-lts-collab` directly from their
   public Git remotes (`25.10 s`), resolving to the exact locked commits in
   [`kas/common.yml`](../kas/common.yml)
   (`93431249a6260da7bd29ee3ca32145d89e5b8259`,
   `ce8539c941f6fcbecaca4d16640ac105c0595589`, and
   `e127ed67e74ca6b7e0fdc6cbda572302886c00a0`).
2. **Zero seeded `downloads/`**: `/work/downloads` was omitted completely so
   BitBake fetched `warmcat/libwebsockets.git` (`8d605f0649ed1ab6d27a443c7688598ea21fdb75`)
   directly from public GitHub during `baseline` build.
3. **Filtered base-system `sstate-cache` only**: `7,104` unchanged base-system
   sstate files (`~3.5 GiB`) were seeded read-only from
   `firmdura-kirkstone-baseline`, while all `152` entries matching
   `*libwebsockets*`, `*firmdura-lws-h2-tests*`, or `*firmdura-reference-image*`
   were excluded and verified absent (`0` matches) prior to `sh kas/run baseline build`.
   After testing the rebuilt `baseline` image, `/work/build-baseline/tmp` and
   all `81` newly emitted target sstate entries were deleted (`11 GiB` free on
   `/dev/vdb1`) before running `sh kas/run patched build`, forcing both variants
   to compile `libwebsockets`, `firmdura-lws-h2-tests`, and
   `firmdura-reference-image` from scratch.

### Rebuild results and digest comparison against frozen artifacts

- `sh kas/run baseline build` succeeded (`exit 0`) in **`155.53 s`** (`7.1 GiB`
  free at completion).
- `sh kas/run patched build` succeeded (`exit 0`) in **`151.12 s`** (`7.0 GiB`
  free at completion), applying
  [`CVE-2026-19773-1.patch`](../recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-1.patch)
  and
  [`CVE-2026-19773-2.patch`](../recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-2.patch)
  in order with zero fuzz during `do_patch` and `do_qa_patch`.

| Output payload | Variant | Rebuilt SHA-256 | Frozen candidate SHA-256 | Comparison |
|---|---|---|---|---|
| `Image--5.15.211+git0+...bin` (`20,648,448` B) | Both | `4866e9a8df7c5be803372af05fc187b35792ef170fd2d8745053f18f6af6d36c` | `4866e9a8df7c5be803372af05fc187b35792ef170fd2d8745053f18f6af6d36c` | **Byte-identical** (restored from base kernel sstate) |
| `/usr/lib/libwebsockets.so.18` (`436,448` B) | `baseline` | `77809db0b9f6a1f97917292a5976e332de130bed90c21eb219e8032cfe3ae05a` | `77809db0b9f6a1f97917292a5976e332de130bed90c21eb219e8032cfe3ae05a` | **Byte-identical** (freshly compiled from upstream Git) |
| `/usr/lib/libwebsockets.so.18` (`436,448` B) | `patched` | `4aac446382e44af454bed760127683a16faf98a8abb1c257d7564da798a717c5` | `4aac446382e44af454bed760127683a16faf98a8abb1c257d7564da798a717c5` | **Byte-identical** (freshly compiled with backport patches) |
| `/usr/bin/firmdura-h2-cve-2026-19773` (`26,720` B) | Both | `774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795` | `774de9bf7a48e6f750886015c9ef8260c483cfd049187e19369eede1489f7795` | **Byte-identical** (freshly compiled in both variants) |
| `.rootfs.manifest` (`41` pkgs, `1,379` B) | `baseline` | `f214dc6108d1f9bb9708b4e0b1fdd7e75e24865ddd5d71bc627c5a41bb52aa58` | `f214dc6108d1f9bb9708b4e0b1fdd7e75e24865ddd5d71bc627c5a41bb52aa58` | **Byte-identical** |
| `.rootfs.manifest` (`41` pkgs, `1,409` B) | `patched` | `c379bb00254ab1539ac8bda96653d8c76bf8586f2d5e0660766ab5540b858928` | `c379bb00254ab1539ac8bda96653d8c76bf8586f2d5e0660766ab5540b858928` | **Byte-identical** |
| `.rootfs.ext4` (`26,022,912` B) | `baseline` | `85cdffcb5593b2ae4e9483fdde4f3eee05a287bbdcee964f8b5d29dc563a045e` | `6f18018f84e0799faeb30a892f827500e209f7831305748eeb64f41813e197a2` | Expected rootfs image variance (`do_rootfs` `/etc/timestamp`, `/etc/version`, ext4 UUID/mtime) |
| `.rootfs.ext4` (`26,022,912` B) | `patched` | `f93e874d19d30ebb7dbcf773e057749b64cadcfb898755fa481828ea4a203eb5` | `92a3d9f9aaf40de580590bff13774d39b51aab8b3494b1e14bea1963e344598d` | Expected rootfs image variance (`do_rootfs` `/etc/timestamp`, `/etc/version`, ext4 UUID/mtime) |

Both freshly rebuilt `.rootfs.ext4` images were booted in offline system-mode
QEMU (`-nic none`) via [`tests/run-cve-2026-19773.py`](../tests/run-cve-2026-19773.py):

- **Rebuilt `baseline` (`15.60 s`)**: `--mode normal-only` passed (`exit 0`),
  `--mode full` reproduced all `7/7` `CVE-2026-19773` out-of-bounds subchecks
  (`exit 1`), and `ptest-runner` exited `1` (`TOTAL: 1 FAIL: 1`).
- **Rebuilt `patched` (`16.31 s`)**: `--mode normal-only` passed (`exit 0`),
  `--mode full` enforced bounds across all `7/7` subchecks with post-attack
  HTTP/2 `200` liveness (`exit 0`), and `ptest-runner` passed (`exit 0`,
  `TOTAL: 1 FAIL: 0`).
- **Emulator path note**: Yocto's `qemu-helper-native` binary embeds an absolute
  uninative `PT_INTERP` path (`/work/build-baseline/tmp/sysroots-uninative/aarch64-linux/lib/ld-linux-aarch64.so.1`).
  When reusing that native binary across containers, the volume supplying
  `qemu-system-aarch64` must remain mounted at `/work` (or a host-installed
  `qemu-system-aarch64` must be used).

## Independent SPDX, Grype `0.122.0` OpenVEX, and OSV provenance replay

- **SPDX 2.2 normalization and OpenVEX determinism**: Re-running
  [`scripts/vex/normalize_spdx.py`](../scripts/vex/normalize_spdx.py) on both
  frozen canonical `deploy.tar` archives reproduced
  `baseline-41pkg-consolidated.spdx.json` (`050eb32b...`) and
  `patched-41pkg-consolidated.spdx.json` (`f050a6e0...`) byte-for-byte, and
  [`scripts/vex/generate_openvex.py`](../scripts/vex/generate_openvex.py)
  reproduced [`vex/firmdura-kirkstone-cve-2026-19773.openvex.json`](../vex/firmdura-kirkstone-cve-2026-19773.openvex.json)
  (`68850d63...`) byte-for-byte.
- **Offline Grype `0.122.0` control matrix**: Eight isolated offline scans
  (`docker.io/anchore/grype@sha256:68205d0d11c88aec5999c3139b04ebc242f8b41c40322d2a56b7e880f1e641b4`,
  `--network none`, `--read-only`, `validate-by-hash-on-start=true`,
  `add-cpes-if-none=false`) confirmed all expected outcomes documented in
  [the OpenVEX guide](vex.md):
  - **Auxiliary CPE test DB unfiltered**: `154` active matches including `3`
    `CVE-2026-19773` package matches (`libwebsockets18`,
    `libwebsockets-evlib-uv`, `libwebsockets-testapps`) on both `baseline` and
    `patched` prior to VEX application.
  - **Positive control (`patched` SBOM + OpenVEX on auxiliary DB)**: **`0`
    active `CVE-2026-19773` matches**, **`3` `ignoredMatches`** carrying
    `{"namespace": "vex", "vex-status": "fixed"}`, and all **`151` unrelated
    matches preserved**.
  - **Mandatory negative control (`baseline` SBOM + same OpenVEX on auxiliary
    DB)**: **`3` active `CVE-2026-19773` matches retained** (`154` total active,
    `0` ignored), proving the `patched` image-hash product PURL
    (`pkg:generic/firmdura-reference-patched-qemuarm64-20261118120234@1.0-sha256.92a3d9f9...`)
    never suppresses findings on the vulnerable `baseline` image
    (`sha256.6f18018f...`).
  - **Stock Anchore DB `v6.1.10` (`2026-11-18T06:21:08Z`)**: `151` active
    matches and `0` `CVE-2026-19773` matches both without and with `--vex`
    while NIST NVD remains `Awaiting Analysis`.
- **Companion OSV Git provenance**: Re-running
  [`scripts/vex/osv_git_provenance.py`](../scripts/vex/osv_git_provenance.py)
  reported `status: "affected"` (`3` matches) on the frozen `baseline`
  `deploy.tar` and `status: "fixed_by_verified_backport"` (`0` matches,
  verified `CVE-2026-19773-1.patch`) on the frozen `patched` `deploy.tar`.

## Engineering, configuration, and redistribution audit

1. **Backport patch logic against upstream commits**:
   - [`CVE-2026-19773-1.patch`](../recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-1.patch)
     accurately backports upstream commit
     [`824151862f37bc72f46d9a3e01d5b9408d313a0b`](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b)
     onto `libwebsockets` `4.2.2` (`8d605f0649ed1ab6d27a443c7688598ea21fdb75`),
     adding `if ((unsigned int)ah->pos >= wsi->a.context->max_http_header_data) return 1;`
     before writing `ah->data[ah->pos++]` in `lws_frag_append`
     (`lib/roles/h2/hpack.c`). Using `>=` rather than `==` is essential because
     both the `?` URI-argument start (`parsers.c:942`) and the `&`/`;`
     argument-delimiter split (`parsers.c:842`) in `lws_parse_urldecode` call
     `issue_char(wsi, '\0')` and then increment `++ah->pos` a second time,
     capable of advancing `ah->pos` from `limit - 1` straight to `limit + 1`.
   - [`CVE-2026-19773-2.patch`](../recipes-connectivity/libwebsockets/libwebsockets/CVE-2026-19773-2.patch)
     accurately backports upstream follow-up commit
     [`0c6cef0922c531f2662e87e74e17c191fa18162b`](https://github.com/warmcat/libwebsockets/commit/0c6cef0922c531f2662e87e74e17c191fa18162b),
     checking `if ((unsigned int)ah->pos >= wsi->a.context->max_http_header_data) goto excessive;`
     immediately after `ah->frags[ah->nfrag].offset = ++ah->pos;` on the `?`
     transition (`parsers.c:959`). Note that upstream `0c6cef092` did not add a
     parallel immediate `goto excessive` after `++ah->pos` on the `&`/`;`
     delimiter branch (`parsers.c:854`); however, with Patch 1 in place, any
     subsequent character write in `lws_frag_append` as well as header
     termination in `lws_frag_end` (`lws_frag_append(wsi, 0)`) rejects
     `ah->pos >= max_http_header_data`, preventing any out-of-bounds write on
     both `?` and `;` paths (verified at runtime by vector `v3`).
   - Both patches carry `CVE: CVE-2026-19773`, `Upstream-Status: Backport [...]`,
     original author attribution, and `Signed-off-by` headers, and apply onto
     `8d605f0649ed1ab6d27a443c7688598ea21fdb75` with `git apply --check --whitespace=error`
     and `git am` with zero fuzz.
2. **Recipe, BitBake environment, and package-manifest equality**:
   - [`libwebsockets_4.2.2.bbappend`](../recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend)
     preserves `PV = "4.2.2"` and `SRCREV = "8d605f0649ed1ab6d27a443c7688598ea21fdb75"`,
     setting only `PR:append = ".firmdura1"` and appending the two patch files.
   - Clean-volume `bitbake -e libwebsockets` outputs matched identically across
     `baseline` and `patched` on `PACKAGECONFIG="libuv client server http2 ssl"`,
     `EXTRA_OECMAKE` (`-DLWS_WITH_HTTP2=ON -DLWS_WITH_SSL=ON -DLWS_WITH_LIBUV=ON -DLWS_WITHOUT_CLIENT=OFF -DLWS_WITHOUT_SERVER=OFF`),
     `MACHINE="qemuarm64"`, `DISTRO="poky"`, `DISTRO_VERSION="4.0.35"`,
     `TARGET_SYS="aarch64-poky-linux"`, and `TUNE_FEATURES="aarch64 armv8a crc cortexa57"`.
   - Both `.rootfs.manifest` files contain `41` target packages: `38` packages
     are identical across variants and only `libwebsockets18`,
     `libwebsockets-evlib-uv`, and `libwebsockets-testapps` advance from
     `4.2.2-r0` to `4.2.2-r0.firmdura1`.
3. **Corresponding-source and licence redistribution completeness**:
   - Direct stream inspection (without case-insensitive host extraction) verified
     all `367` regular-file members in `firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz`
     and all `152` regular-file members in `firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz`
     against `firmdura-kirkstone-qemuarm64-redistribution-inventory.json`.
   - Every distributed binary (`linux-yocto` kernel plus all `41` `baseline` and
     `41` `patched` packages across `28` target recipes) maps to existing,
     checksum-verified source and licence archive entries, including the offline
     `glibc-2.35` Git archive (`bb59339d02faebac534a87eea50c83c948f35b77`),
     `gcc-source-11.5.0`, `linux-yocto-5.15.211`, both `libwebsockets` revisions
     with `CVE-2026-19773-{1,2}.patch`, and `build-configuration/`.
   - Scanning all text and metadata members across all five deliverables found
     zero host-specific paths, zero secret/credential patterns, and zero
     undisclosed private build prerequisites. All `44` repository unit tests
     (`python3 -m unittest discover -s tests -p '*_test.py' -v`) passed.

<a id="remaining-boundaries-and-publication-gates"></a>

## Release status at the time of the review

- The November 18 stock Anchore Grype snapshot (`v6.1.10`) contained no CPE
  rows for this CVE. NVD listed it as `Awaiting Analysis`. The review also
  used offline OSV Git provenance and a separate test database. Their results
  are recorded separately from the stock scan.
- When the review ran, [the upstream pull request](https://github.com/garmin/meta-lts-collab/pull/283)
  was awaiting first-time contributor CI approval. The [contribution record](contribution.md)
  lists the checks that ran locally.
- The review covered the isolated `qemuarm64` Poky 4.0.35 configuration with
  `debug-tweaks` enabled. Signing followed the review. The [release record](release.md)
  identifies the approved signing run and the manifest published for v0.1.0.
