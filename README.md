# Firmdura Kirkstone reference sample

A Yocto Kirkstone (`4.0.35`, `qemuarm64`) security maintenance reference sample
for embedded Linux engineers evaluating backported repairs and artifact-scoped
VEX evidence for **libwebsockets** `4.2.2`
([`CVE-2026-19773`](https://www.zerodayinitiative.com/advisories/ZDI-26-590/)).

**Experimental:** signed release
[`v0.1.0`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0)
provides paired `baseline` and `patched` QEMU evaluation bundles, complete
corresponding source and licences, consolidated SPDX 2.2 SBOMs, and an
image-hash-scoped OpenVEX statement for isolated evaluation only—not production
firmware (`debug-tweaks` is enabled for unattended local testing, and upstream
NVD CPE configurations for `CVE-2026-19773` remain `Awaiting Analysis`).

## Before / after results (`CVE-2026-19773`)

Measured at paired build commit `a8a2adb0a299221d6f246f7c95e0912e4babd419` and
independently replayed from clean source rebuilds and prebuilt bundles in
[the replay review](docs/replay-review.md):

| Check | `baseline` (`4.2.2-r0`, `libwebsockets.so.18` `77809db0...`) | `patched` (`4.2.2-r0.firmdura1`, `libwebsockets.so.18` `4aac4463...`) |
|---|---|---|
| Normal HTTP/2 client/server & TLS controls | **Pass** (`exit 0`) | **Pass** (`exit 0`) |
| `CVE-2026-19773` HPACK `:path` boundary (`7` subchecks) | **Vulnerable** (`exit 1`: `7/7` OOB writes — `0x5a` canary corruption, `PROT_NONE` `SIGSEGV` in `lws_frag_append`, stock glibc `SIGABRT`) | **Fixed** (`exit 0`: `7/7` oversized `:path` cases rejected cleanly, HTTP/2 `200` liveness preserved) |
| `ptest-runner firmdura-lws-h2-tests` | `TOTAL: 1 FAIL: 1` (`exit 1`) | `TOTAL: 1 FAIL: 0` (`exit 0`) |
| Consolidated 41-pkg SPDX 2.2 + OpenVEX (`Grype 0.122.0` on labelled CPE test DB) | **Mandatory negative control**: `3` active `CVE-2026-19773` matches retained (`0` ignored) | **Positive control**: `0` active `CVE-2026-19773` matches (`3` ignored via `vex-status: fixed`; `151` unrelated findings kept) |
| Stock Anchore Grype DB `v6.1.10` (`2026-11-18`) | `151` active matches, `0` `CVE-2026-19773` (NVD `Awaiting Analysis`) | `151` active matches, `0` `CVE-2026-19773` (NVD `Awaiting Analysis`) |
| Offline OSV Git/source provenance (`osv_git_provenance.py`) | `affected` (`3` package matches) | `fixed_by_verified_backport` (`CVE-2026-19773-1.patch`, `0` matches) |

Structured run records live under [`evidence/`](evidence/)
([paired validation](evidence/20261118-sti110-paired-validation/run.json),
[OpenVEX controls](evidence/20261118-sti113-openvex/run.json),
[independent replay](evidence/20261118-sti115-replay/run.json),
[release verification](evidence/20261118-sti116-release/run.json)), and raw
build, QEMU serial, `ptest`, SPDX, and Grype JSON logs are published in
[`firmdura-kirkstone-v0.1.0-raw-evidence-logs.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-v0.1.0-raw-evidence-logs.tar.gz).

## Quick evaluation (`v0.1.0` signed bundles, ~2 minutes)

Requires `cosign` `v3.1.4`, Python 3.11+, GitHub CLI (`gh`), and
`qemu-system-aarch64` (never run vulnerable baseline images on bridged networks;
the evaluation runner enforces `-nic none` and disposable rootfs copies):

```sh
git clone https://github.com/firmdura/meta-firmdura-kirkstone.git
cd meta-firmdura-kirkstone

python3 scripts/release/verify.py github-release \
  --assets ./downloaded-v0.1.0 \
  --manifest-sha256 ca8ec949fbdb8d04f6ecd91a89efffbfaff7f17af86c6ac6e61e2d68346d7ac3 \
  --release-id v0.1.0 \
  --source-commit 4e15e71a54e32e63bfafaf3b79c99d8bbe6a0e35

mkdir -p eval-baseline eval-patched
tar -xzf downloaded-v0.1.0/firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz -C eval-baseline
tar -xzf downloaded-v0.1.0/firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz -C eval-patched
python3 eval-baseline/firmdura-kirkstone-qemuarm64-baseline-eval/run-evaluation.py
python3 eval-patched/firmdura-kirkstone-qemuarm64-patched-eval/run-evaluation.py
```

See the [release index](docs/release.md), [evaluation guide](docs/evaluation.md),
[signing guide](docs/signing.md), and [OpenVEX guide](docs/vex.md) for direct
asset links, SHA-256 digests, and offline Grype `0.122.0` commands.

## Full source reproduction and layer consumption

- **Separately consumable maintenance layer**:
  [`conf/layer.conf`](conf/layer.conf) and
  [`recipes-connectivity/libwebsockets/`](recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend)
  backport upstream commits
  [`824151862f`](https://github.com/warmcat/libwebsockets/commit/824151862f37bc72f46d9a3e01d5b9408d313a0b)
  and
  [`0c6cef0922`](https://github.com/warmcat/libwebsockets/commit/0c6cef0922c531f2662e87e74e17c191fa18162b)
  onto `libwebsockets` `4.2.2` (`PACKAGECONFIG = "libuv client server http2 ssl"`),
  also submitted upstream at
  [`garmin/meta-lts-collab#283`](https://github.com/garmin/meta-lts-collab/pull/283)
  ([contribution record](docs/contribution.md)).
- **Clean source build** (requires Docker and a **Linux ARM64** builder; see the
  [build guide](docs/build.md) and [testing guide](docs/testing.md)):

```sh
docker volume create --label org.firmdura.sample=kirkstone firmdura-kirkstone-work
sh kas/run baseline build
sh kas/run patched build
```

## Limitations

- Results apply only to this pinned `qemuarm64` Poky `4.0.35` reference
  configuration (`93431249a6...`, `meta-openembedded` `ce8539c941...`,
  `meta-lts-collab` `e127ed67e7...`). Compatibility with other Kirkstone BSPs,
  physical boards, or customer firmware has not been validated.
- Stock Anchore Grype DB `v6.1.10` still lacks CPE applicability rows for
  `CVE-2026-19773` while NIST NVD lists the CVE as `Awaiting Analysis`; see the
  [scanner guide](docs/scanner.md) and [OpenVEX guide](docs/vex.md).
- No ongoing SLA or universal CVE maintenance commitment is implied by this
  single-case reference release.

## Licensing and corresponding source

[MIT](LICENSE) applies to original Firmdura files. Third-party layers, sources,
and binaries retain their own licences and notices; complete corresponding
source ([`firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz)),
licences/notices ([`firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz)),
and [redistribution inventory](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-redistribution-inventory.json)
are published with [`v0.1.0`](docs/release.md); see the
[licence boundary](docs/build.md#licence-boundary).
