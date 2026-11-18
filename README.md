# Firmdura Kirkstone reference sample

A reproducible **Yocto Kirkstone (`4.0.35`, `qemuarm64`)** reference sample showing
how a security backport in **libwebsockets `4.2.2`** can be delivered, tested on an
emulated ARM64 target, tracked in vulnerability scanners without hiding unpatched
builds, and redistributed with complete source and licences.

When maintaining a long-lived Yocto Kirkstone system, backporting an upstream C fix
typically leaves the package version (`4.2.2`) unchanged—so version-based scanners
either keep flagging the repaired image or miss newly disclosed CVEs entirely, and
claims of "fixed" are hard to trust without a target test that actually fails
before the patch and passes after it.

Published release
[`v0.1.0`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0)
demonstrates the full workflow end to end for
[`CVE-2026-19773`](https://www.zerodayinitiative.com/advisories/ZDI-26-590/)
(an out-of-bounds heap write in `libwebsockets`' HTTP/2 HPACK `:path` parser):

- **Standalone Yocto repair layer**
  ([`recipes-connectivity/libwebsockets/`](recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend))
  backporting the two upstream fix commits onto `libwebsockets` `4.2.2` with
  HTTP/2, TLS, `libuv`, client, and server support enabled.
- **Paired `baseline` and `patched` ARM64 QEMU bundles** signed via keyless
  GitHub Actions Cosign OIDC, so you can watch the exploit crash/corrupt the
  unpatched library and verify clean rejection on the patched library in ~2 minutes.
- **Consolidated SPDX 2.2 SBOMs and image-hash-scoped OpenVEX**
  ([`vex/firmdura-kirkstone-cve-2026-19773.openvex.json`](vex/firmdura-kirkstone-cve-2026-19773.openvex.json))
  verified with Grype `0.122.0` so only the repaired rootfs digest is marked
  `fixed` while the vulnerable `baseline` image continues to report the finding.
- **Upstream community contribution** submitted to Garmin's Kirkstone LTS layer at
  [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283),
  plus complete corresponding source (`436.6 MB`) and licence archives.

> **Experimental evaluation sample:** The reference images enable Yocto
> `debug-tweaks` for unattended local QEMU testing and target a single
> emulated `qemuarm64` configuration. Use them for isolated technical evaluation,
> not as production firmware.

## Try the prebuilt demo (~2 minutes)

You need `cosign` `v3.1.4`, Python 3.11+, GitHub CLI (`gh`), and
`qemu-system-aarch64`. The evaluation runner boots disposable copies of each
rootfs with QEMU networking disabled (`-nic none`):

```sh
git clone https://github.com/firmdura/meta-firmdura-kirkstone.git
cd meta-firmdura-kirkstone

# 1. Download all 13 release files and verify the Sigstore OIDC signature + SHA-256 digests
python3 scripts/release/verify.py github-release \
  --assets ./downloaded-v0.1.0 \
  --manifest-sha256 ca8ec949fbdb8d04f6ecd91a89efffbfaff7f17af86c6ac6e61e2d68346d7ac3 \
  --release-id v0.1.0 \
  --source-commit 4e15e71a54e32e63bfafaf3b79c99d8bbe6a0e35

# 2. Unpack and boot both ARM64 images in offline QEMU
mkdir -p eval-baseline eval-patched
tar -xzf downloaded-v0.1.0/firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz -C eval-baseline
tar -xzf downloaded-v0.1.0/firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz -C eval-patched
python3 eval-baseline/firmdura-kirkstone-qemuarm64-baseline-eval/run-evaluation.py
python3 eval-patched/firmdura-kirkstone-qemuarm64-patched-eval/run-evaluation.py
```

Both scripts exit `0` when the guest behaves as expected: `baseline` confirms the
out-of-bounds write reproduction (`vulnerable-oob-write-reproduced`), and
`patched` confirms bounds enforcement with normal HTTP/2 traffic still working
afterward (`bounds-enforced-secure`).

## What changes between `baseline` and `patched`

Both images contain the same `41` target packages built from locked Kirkstone
commits; only `libwebsockets` changes (`4.2.2-r0` vs `4.2.2-r0.firmdura1`):

| Verification check | Unpatched `baseline` (`4.2.2-r0`) | Repaired `patched` (`4.2.2-r0.firmdura1`) |
|---|---|---|
| Normal HTTP/2 + TLS client/server traffic | Passes (`exit 0`) | Passes (`exit 0`) |
| `CVE-2026-19773` oversized `:path` test (`7` boundary cases) | **Reproduces vulnerability** (`exit 1`: heap canary overwrite, guard-page `SIGSEGV` in `lws_frag_append`, and glibc `SIGABRT`) | **Blocks cleanly** (`exit 0`: all `7` oversized headers rejected; subsequent valid HTTP/2 requests still return `200`) |
| On-target `ptest-runner firmdura-lws-h2-tests` | Fails (`TOTAL: 1 FAIL: 1`) | Passes (`TOTAL: 1 FAIL: 0`) |
| Grype `0.122.0` + OpenVEX (on labelled CPE test DB) | **Still flagged** (`3` active `CVE-2026-19773` matches kept — patched VEX does not mask `baseline`) | **Suppressed as `fixed`** (`0` active `CVE-2026-19773` matches; `151` unrelated findings left untouched) |
| Stock Anchore Grype DB (`v6.1.10`, `2026-11-18`) | `0` `CVE-2026-19773` matches (`151` other matches) while NIST NVD lists the CVE as `Awaiting Analysis` | `0` `CVE-2026-19773` matches (`151` other matches) while NIST NVD lists the CVE as `Awaiting Analysis` |
| Offline OSV Git/patch provenance (`osv_git_provenance.py`) | Reports `affected` (`SRCREV` `8d605f06...` lacks fix) | Reports `fixed_by_verified_backport` (`CVE-2026-19773-1.patch`) |

Both prebuilt bundles and clean-volume source rebuilds were independently
replayed in a fresh environment; see [the replay review](docs/replay-review.md).

## Use the repair layer or rebuild from source

- **Add only the repair layer to an existing Kirkstone build:** include this
  repository's root layer ([`conf/layer.conf`](conf/layer.conf)), which supplies
  [`recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend`](recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend)
  and the zero-fuzz backports of upstream commits
  [`824151862f`](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b)
  and
  [`0c6cef0922`](https://github.com/warmcat/libwebsockets/commit/0c6cef0922c531f2662e87e74e17c191fa18162b).
  The test harness lives in [`meta-firmdura-tests/`](meta-firmdura-tests/) so
  consumers of the repair layer do not pull test packages into their images.
- **Rebuild both reference images from source:** requires Docker on a **Linux
  ARM64** builder (or a Linux ARM64 VM such as Colima on Apple Silicon; see the
  [build guide](docs/build.md) for disk and volume setup):

```sh
docker volume create --label org.firmdura.sample=kirkstone firmdura-kirkstone-work
sh kas/run baseline build
sh kas/run patched build
```

## Upstream community contribution

Rather than keeping the backport only in this sample repository, the same
Kirkstone `libwebsockets` `4.2.2` patch series has been submitted upstream to
Garmin's community LTS maintenance layer at
[`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283).
As of `v0.1.0`, the pull request is **open and awaiting maintainer review and
first-time contributor CI approval** (it has not yet been merged upstream); local
`oelint-adv`, `ruff`, and `yamllint` checks and provenance details are documented
in [the contribution record](docs/contribution.md).

## Guides and raw evidence

- [Release `v0.1.0` index](docs/release.md) — direct download links and SHA-256
  digests for all `13` signed release assets, including
  [`firmdura-kirkstone-v0.1.0-raw-evidence-logs.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-v0.1.0-raw-evidence-logs.tar.gz)
  (`227` raw BitBake, QEMU serial, `ptest`, SPDX, and Grype JSON logs).
- [Evaluation guide](docs/evaluation.md) and [testing guide](docs/testing.md) —
  QEMU boot procedure, C HTTP/2 boundary harness design, and incomplete-fix
  regression controls.
- [Scanner guide](docs/scanner.md) and [OpenVEX guide](docs/vex.md) — why raw
  Yocto SPDX needs graph consolidation for Grype, why stock NVD feeds currently
  miss `CVE-2026-19773`, and how positive/negative OpenVEX matching is verified.
- [Signing guide](docs/signing.md) — protected GitHub Actions keyless Cosign
  signing and `manifest.json` v1 verification rules.
- [Independent replay review](docs/replay-review.md),
  [first-cycle operating review](docs/first-cycle-review.md),
  [maintenance boundary](docs/maintenance-decision.md), and machine-readable run
  records under [`evidence/`](evidence/).

## Scope and limitations

- Validated only on this pinned `qemuarm64` Poky `4.0.35` configuration
  (`poky` `93431249a6...`, `meta-openembedded` `ce8539c941...`,
  `meta-lts-collab` `e127ed67e7...`). Compatibility with other Kirkstone BSPs,
  physical boards, different `PACKAGECONFIG` flags, or customer firmware has not
  been tested.
- Stock Anchore Grype DB `v6.1.10` still has zero CPE rows for `CVE-2026-19773`
  until NIST NVD completes analysis; once NVD adds `libwebsockets <= 4.2.2` CPE
  configurations, stock Grype databases will match the published SPDX SBOMs and
  OpenVEX product PURLs without regenerating them.
- Published as a completed single-case (`v0.1.0`) reference sample with no
  implied SLA, recurring update schedule, or open-ended Kirkstone EOL commitment;
  see [the maintenance boundary](docs/maintenance-decision.md).

## Licensing and corresponding source

Original Firmdura files are licensed under [MIT](LICENSE). Third-party layers,
patches, sources, and binaries retain their upstream licences and notices.
Complete corresponding source
([`firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz)),
case-preserving licence texts
([`firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz)),
and the [redistribution inventory](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-redistribution-inventory.json)
are published with [`v0.1.0`](docs/release.md); see the
[licence boundary](docs/build.md#licence-boundary).
