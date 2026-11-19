# Firmdura Kirkstone reference sample

This Yocto Kirkstone reference layer backports a security fix to
`libwebsockets` 4.2.2 on Poky 4.0.35 for `qemuarm64`. Both the baseline
and patched images report the same upstream package version. Their root
filesystem digests distinguish the two builds.

Release [`v0.1.0`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0)
covers [CVE-2026-19773](https://www.zerodayinitiative.com/advisories/ZDI-26-590/)
and includes:

- **Standalone Yocto repair layer**
  ([`recipes-connectivity/libwebsockets/`](recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend))
  backporting the two upstream fix commits onto `libwebsockets` `4.2.2` with
  HTTP/2, TLS, `libuv`, client, and server support enabled.
- **Baseline and patched ARM64 QEMU bundles.** The release manifest records
  both bundles' SHA-256 digests and is signed with Cosign through GitHub Actions.
- **Consolidated SPDX 2.2 SBOMs and image-hash-scoped OpenVEX**
  ([`vex/firmdura-kirkstone-cve-2026-19773.openvex.json`](vex/firmdura-kirkstone-cve-2026-19773.openvex.json))
  for the two root filesystems. With the labelled test database, Grype
  `0.122.0` applied the `fixed` statement only to the patched image. The
  stock database snapshot had no match for this CVE on either image.
- **Upstream community contribution** submitted to Garmin's Kirkstone LTS layer at
  [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283),
  plus complete corresponding source (`436.6 MB`) and licence archives.

> Both images enable Yocto `debug-tweaks` for unattended boot tests. Use
> them only in an isolated QEMU environment.

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

Firmdura submitted the two-patch backport to Garmin's Kirkstone LTS layer in
[`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283).
At the time of the release, maintainer review and approval for first-time
contributor CI were pending. The [contribution record](docs/contribution.md)
lists the local `oelint-adv`, `ruff`, and `yamllint` checks.

## Guides and raw evidence

- [Release `v0.1.0` index](docs/release.md) — direct download links and SHA-256
  digests for all 13 release files, including
  [`firmdura-kirkstone-v0.1.0-raw-evidence-logs.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-v0.1.0-raw-evidence-logs.tar.gz)
  (`227` raw BitBake, QEMU serial, `ptest`, SPDX, and Grype JSON logs).
- [Evaluation guide](docs/evaluation.md) and [testing guide](docs/testing.md) —
  QEMU boot procedure, C HTTP/2 boundary harness design, and incomplete-fix
  regression controls.
- [Scanner guide](docs/scanner.md) and [OpenVEX guide](docs/vex.md) — why raw
  Yocto SPDX needs graph consolidation for Grype, why the November 18 stock Grype snapshot
  returned no match for this CVE, and how positive/negative OpenVEX matching is verified.
- [Signing guide](docs/signing.md) — protected GitHub Actions keyless Cosign
  signing and `manifest.json` v1 verification rules.
- [Independent replay review](docs/replay-review.md),
  [first release build and validation review](docs/first-cycle-review.md),
  [release scope and package audit](docs/maintenance-decision.md), and machine-readable run
  records under [`evidence/`](evidence/).

## Scope and limitations

- Validated only on this pinned `qemuarm64` Poky `4.0.35` configuration
  (`poky` `93431249a6...`, `meta-openembedded` `ce8539c941...`,
  `meta-lts-collab` `e127ed67e7...`). Compatibility with other Kirkstone BSPs,
  physical boards, different `PACKAGECONFIG` flags, or customer firmware has not
  been tested.
- On November 18, 2026, the stock Anchore Grype database had no CPE rows for
  this CVE. The OpenVEX matching result above used a separate, labelled test
  database.
- `v0.1.0` covers one case. It carries no SLA or recurring update schedule.
  The [package audit](docs/maintenance-decision.md) records the findings for
  the other packages in this image.

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
