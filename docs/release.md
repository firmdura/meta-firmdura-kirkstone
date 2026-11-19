# Release files and verification for v0.1.0

Firmdura published [v0.1.0](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0)
on November 18, 2026. The signed manifest lists 11 files. The manifest itself
and its Sigstore bundle bring the download count to 13. The
[verification record](../evidence/20261118-sti116-release/run.json) includes
the approval, signing run, and download checks. That record lists the manifest
as 2,489 bytes. The published file is 2,757 bytes and matches the SHA-256
recorded there.

For the run records as shipped, use the
[evidence directory at the signed source revision](https://github.com/firmdura/meta-firmdura-kirkstone/tree/4e15e71a54e32e63bfafaf3b79c99d8bbe6a0e35/evidence).
The default branch includes later reviews and editorial changes.

## Release, source, and cryptographic identities

| Field | Value |
|---|---|
| Release tag & URL | [`v0.1.0`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/tag/v0.1.0) |
| Release source & evidence commit (`source.commit`) | `4e15e71a54e32e63bfafaf3b79c99d8bbe6a0e35` |
| Paired image build commit (`baseline` & `patched`) | `a8a2adb0a299221d6f246f7c95e0912e4babd419` |
| Frozen target test harness commit | `6e3e70b94281c8f75f52f90e77152deba7372c83` |
| Protected OIDC signing workflow run | [`44372975734`](https://github.com/firmdura/meta-firmdura-kirkstone/actions/runs/44372975734) (`release-signing` human deployment `7892852402`, staged artifact `14460645429` from run [`44372854449`](https://github.com/firmdura/meta-firmdura-kirkstone/actions/runs/44372854449)) |
| Signed `manifest.json` (`2,757` B) SHA-256 | `ca8ec949fbdb8d04f6ecd91a89efffbfaff7f17af86c6ac6e61e2d68346d7ac3` |
| Sigstore bundle `manifest.sigstore.json` (`11,063` B) SHA-256 | `952746a316c0892c8cded527f60b77ba4ab59edb0caf67111a5f15b3ad7100fc` |
| Fulcio leaf X.509 DER SHA-256 | `6b955b5a82a982cb958d1fab4b19e49b294d2e625ddd6b63addd227642b7d43b` |
| Certificate SAN (`--certificate-identity`) | `https://github.com/firmdura/meta-firmdura-kirkstone/.github/workflows/release.yml@refs/heads/main` |
| Certificate OIDC issuer (`--certificate-oidc-issuer`) | `https://token.actions.githubusercontent.com` |

## Complete published asset manifest (`13` uploaded files)

All files below are publicly downloadable under
`https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/<filename>`:

| Asset | Role / variant | Size (bytes) | SHA-256 |
|---|---|---:|---|
| [`manifest.json`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/manifest.json) | Signed manifest v1 | `2,757` | `ca8ec949fbdb8d04f6ecd91a89efffbfaff7f17af86c6ac6e61e2d68346d7ac3` |
| [`manifest.sigstore.json`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/manifest.sigstore.json) | Keyless Cosign Sigstore bundle | `11,063` | `952746a316c0892c8cded527f60b77ba4ab59edb0caf67111a5f15b3ad7100fc` |
| [`firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz) | `qemu-bundle` (`baseline`) | `16,416,902` | `ca423ae7d57f411c44916651413b6d6f3ad45d39aac4abb70498800ecd8891b0` |
| [`firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz) | `qemu-bundle` (`patched`) | `16,419,741` | `aa04251544a1ff48e690620591255f029ca361871acc48af63ee785b462c8678` |
| [`firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz) | `corresponding-source` (`367` members) | `436,645,082` | `ad8bded335da769b16cf66a4b3279e93e9667e6839c1dd82cce3f8a24c86c3ef` |
| [`firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz) | `licenses` (`152` members) | `250,996` | `351d071eae6de20bd95af40356ba98c353953e7fcfaa4129c4bb5a06c5f15a76` |
| [`firmdura-kirkstone-qemuarm64-redistribution-inventory.json`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-redistribution-inventory.json) | `redistribution-inventory` | `169,376` | `e66a37683054d0c70963e6f171e271d2530fdcc0f793687fb4959d9e7d635427` |
| [`firmdura-kirkstone-qemuarm64-baseline.spdx.json`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-baseline.spdx.json) | `sbom` (`baseline`, `41` pkgs) | `262,387` | `050eb32b37945ded03465de1f1f178cb433d7a37c408ee1a0fc83327292e3765` |
| [`firmdura-kirkstone-qemuarm64-patched.spdx.json`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-qemuarm64-patched.spdx.json) | `sbom` (`patched`, `41` pkgs) | `262,415` | `f050a6e085b2c61afa3507cd35e977252f3fcf9836f91148c099189e20009110` |
| [`firmdura-kirkstone-cve-2026-19773.openvex.json`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-cve-2026-19773.openvex.json) | `vex` (OpenVEX v0.2.0) | `2,970` | `68850d630989bd25002f495c43b9cd4090cefde299774274f0d1b80e348b906e` |
| [`firmdura-kirkstone-v0.1.0-source-and-evidence.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-v0.1.0-source-and-evidence.tar.gz) | `source-layer` (`4e15e71a...` archive) | `243,796` | `6dd961876f76cfe21dad69815316149c144e72a1c4213fee955b10e59fecc5d6` |
| [`firmdura-kirkstone-v0.1.0-raw-evidence-logs.tar.gz`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-v0.1.0-raw-evidence-logs.tar.gz) | `evidence-logs` (`227` raw logs + `INDEX.json`) | `6,406,380` | `614781d570c067180d5efe86f7b24136577bb90f22f294b096145c80f494c1f5` |
| [`firmdura-kirkstone-v0.1.0-release-notes.md`](https://github.com/firmdura/meta-firmdura-kirkstone/releases/download/v0.1.0/firmdura-kirkstone-v0.1.0-release-notes.md) | `release-notes` | `5,491` | `982626ee2225d0dd596b6ef389c136297c27023e0e60a9c733e4cfec44278eee` |

## Public download verification and quick QEMU evaluation

Verify the complete published release (`13` files) with Cosign `v3.1.4`, Python
3.11+, and GitHub CLI:

```sh
python3 scripts/release/verify.py github-release \
  --assets ./downloaded-v0.1.0 \
  --manifest-sha256 ca8ec949fbdb8d04f6ecd91a89efffbfaff7f17af86c6ac6e61e2d68346d7ac3 \
  --release-id v0.1.0 \
  --source-commit 4e15e71a54e32e63bfafaf3b79c99d8bbe6a0e35
```

Extract and run both QEMU evaluation bundles offline (`qemu-system-aarch64`
required; `run-evaluation.py` boots on disposable rootfs copies with `-nic none`
and exits `0` when each bundle matches its expected `baseline` vs `patched`
behavior):

```sh
mkdir -p eval-baseline eval-patched
tar -xzf downloaded-v0.1.0/firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz -C eval-baseline
tar -xzf downloaded-v0.1.0/firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz -C eval-patched
python3 eval-baseline/firmdura-kirkstone-qemuarm64-baseline-eval/run-evaluation.py
python3 eval-patched/firmdura-kirkstone-qemuarm64-patched-eval/run-evaluation.py
```

Post-publication checks verified both `verify.py github-release` and
unauthenticated public HTTPS downloads (`curl -fsSL`), followed by offline QEMU
boots confirming `vulnerable-oob-write-reproduced` (`7/7` OOB subchecks) on
`baseline` and `bounds-enforced-secure` (`7/7` blocked + HTTP/2 `200` liveness,
`ptest` `FAIL: 0`) on `patched`. See [the signing guide](signing.md),
[the evaluation guide](evaluation.md), and
[the independent replay review](replay-review.md).
