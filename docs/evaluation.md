# Quick QEMU evaluation and corresponding-source redistribution

This guide covers evaluating the frozen `baseline` and `patched` `qemuarm64`
reference bundles without running a full Yocto build, alongside the
corresponding-source and licence redistribution archives produced by
[`scripts/bundle/package_bundles.py`](../scripts/bundle/package_bundles.py) and
recorded in [`evidence/20261118-sti112-bundles/run.json`](../evidence/20261118-sti112-bundles/run.json).

**Safety boundary:** Both bundles are **isolated evaluation references only**,
not production firmware (`debug-tweaks` passwordless root login is enabled). The
`baseline` bundle intentionally contains unpatched `libwebsockets` `4.2.2-r0`
vulnerable to `CVE-2026-19773` ([ZDI-26-590](https://www.zerodayinitiative.com/advisories/ZDI-26-590/)).
Always boot disposable rootfs copies with outward networking disabled
(`-nic none`); never attach a bridged interface or expose the guest to an
untrusted network.

## Packaged deliverables and SHA-256 digests

All inner kernel and rootfs payloads match the reviewed frozen image pair in
[`evidence/20261118-sti110-paired-validation/run.json`](../evidence/20261118-sti110-paired-validation/run.json)
byte-for-byte (`producer_source_commit`:
`a8a2adb0a299221d6f246f7c95e0912e4babd419`):

| Deliverable | Size (bytes) | SHA-256 | Contents |
|---|---:|---|---|
| `firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz` | `16,416,902` | `ca423ae7d57f411c44916651413b6d6f3ad45d39aac4abb70498800ecd8891b0` | Frozen vulnerable `baseline` `Image` (`4866e9a8...`), `.rootfs.ext4` (`6f18018f...`), `.rootfs.manifest`, sanitized `.qemuboot.conf`, consolidated 41-pkg SPDX 2.2 SBOM (`050eb32b...`), `WARNING-VULNERABLE-REFERENCE-ONLY.txt`, `launch-qemu.sh`, `run-evaluation.py`, and `bundle-inventory.json` |
| `firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz` | `16,419,741` | `aa04251544a1ff48e690620591255f029ca361871acc48af63ee785b462c8678` | Frozen repaired `patched` `Image` (`4866e9a8...`), `.rootfs.ext4` (`92a3d9f9...`), `.rootfs.manifest`, sanitized `.qemuboot.conf`, consolidated 41-pkg SPDX 2.2 SBOM (`f050a6e0...`), `NOTICE-REFERENCE-ONLY.txt`, `launch-qemu.sh`, `run-evaluation.py`, and `bundle-inventory.json` |
| `firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz` | `436,645,082` | `ad8bded335da769b16cf66a4b3279e93e9667e6839c1dd82cce3f8a24c86c3ef` | `367` archived upstream source tarballs, Yocto/OE/Firmdura patch series, and BitBake recipes covering all `41` installed target packages (`28` target recipes, including both `libwebsockets-4.2.2-r0` and `4.2.2-r0.firmdura1`, `glibc-2.35` at `bb59339d...`, `gcc-source-11.5.0`, `linux-libc-headers-5.16`) plus `linux-yocto-5.15.211` and `build-configuration/` (`kas/`, `conf/`, `recipes-connectivity/`, `meta-firmdura-tests/`) |
| `firmdura-kirkstone-qemuarm64-licenses-and-notices.tar.gz` | `250,996` | `351d071eae6de20bd95af40356ba98c353953e7fcfaa4129c4bb5a06c5f15a76` | `152` image licence manifests (`license.manifest`, `package.manifest`, `image_license.manifest`) and recipe licence/notice files preserved in a case-sensitive POSIX tar archive, plus `LICENSE.MIT` for original Firmdura files |
| `firmdura-kirkstone-qemuarm64-redistribution-inventory.json` | `169,376` | `e66a37683054d0c70963e6f171e271d2530fdcc0f793687fb4959d9e7d635427` | Machine-readable mapping of the distributed kernel and all `41` `baseline` / `41` `patched` binary packages to their exact archived source and licence members |

## Quick evaluation without a Yocto rebuild

### Prerequisites

- `qemu-system-aarch64` (QEMU 6.2+ supporting `-machine virt -cpu cortex-a57`)
- Standard POSIX shell utilities (`tar`, `mktemp`, `sha256sum` or `shasum`)
- Optional automated runner: Python 3.10+ with `pexpect`

### Interactive isolated boot (`launch-qemu.sh`)

Extract either bundle into a clean directory and run `./launch-qemu.sh`:

```sh
mkdir -p eval-run
tar -xzf firmdura-kirkstone-qemuarm64-baseline-eval-bundle.tar.gz -C eval-run
tar -xzf firmdura-kirkstone-qemuarm64-patched-eval-bundle.tar.gz -C eval-run

# Interactive boot (uses a temporary rootfs copy and -nic none; verifies frozen SHA-256 before and after)
./eval-run/firmdura-kirkstone-qemuarm64-patched-eval/launch-qemu.sh
```

At `qemuarm64 login:`, sign in as `root` (no password) and execute the packaged
target checks:

```sh
ifconfig lo 127.0.0.1 up
ptest-runner firmdura-lws-h2-tests
/usr/bin/firmdura-h2-cve-2026-19773 --mode full
poweroff
```

Expected guest observations:

- **`baseline` (`libwebsockets` `4.2.2-r0`, library SHA-256 `77809db0...cfe3ae05a`)**:
  - Normal HTTP/2 prior-knowledge requests pass (`PASS: firmdura-h2-normal-controls`).
  - `CVE-2026-19773` suite exits `1` (`"verdict": "vulnerable-oob-write-reproduced"`,
    `7/7` out-of-bounds subchecks reproduced) and `ptest-runner` reports
    `FAIL: firmdura-cve-2026-19773-bounds-enforced`.
- **`patched` (`libwebsockets` `4.2.2-r0.firmdura1`, library SHA-256 `4aac4463...a717c5`)**:
  - Normal HTTP/2 prior-knowledge requests pass (`PASS: firmdura-h2-normal-controls`).
  - `CVE-2026-19773` suite exits `0` (`"verdict": "bounds-enforced-secure"`,
    `7/7` subchecks blocked with zero out-of-bounds writes and post-attack HTTP/2
    `200` liveness) and `ptest-runner` reports
    `PASS: firmdura-cve-2026-19773-bounds-enforced` (`TOTAL: 1 FAIL: 0`).

### Automated non-interactive evaluation (`run-evaluation.py`)

Each bundle embeds a standalone `run-evaluation.py` script requiring no
repository checkout:

```sh
python3 ./eval-run/firmdura-kirkstone-qemuarm64-baseline-eval/run-evaluation.py --qemu qemu-system-aarch64
python3 ./eval-run/firmdura-kirkstone-qemuarm64-patched-eval/run-evaluation.py --qemu qemu-system-aarch64
```

Both invocations verify the frozen kernel and rootfs SHA-256 digests before and
after running, boot a temporary ext4 copy with `-nic none`, assert the expected
`vulnerable` (`baseline`) or `repaired` (`patched`) verdict, and exit `0` only
when every expected check matches.

## Full source rebuild

To rebuild both images from source rather than evaluating the prebuilt bundles,
follow [the pinned build guide](build.md) on an isolated Linux ARM64 builder:

```sh
git clone https://github.com/firmdura/meta-firmdura-kirkstone.git
cd meta-firmdura-kirkstone
git checkout a8a2adb0a299221d6f246f7c95e0912e4babd419

docker volume create --label org.firmdura.sample=kirkstone firmdura-kirkstone-work
sh kas/run baseline build
sh kas/run patched build
```

Offline source reconstruction is also supported directly from
`firmdura-kirkstone-qemuarm64-corresponding-source.tar.gz`, which bundles all
target recipe tarballs, patch series, `glibc-2.35` (`bb59339d...`),
`gcc-source-11.5.0`, `linux-yocto-5.15.211`, and the `build-configuration/`
layer and `kas` files. Extract licence and source archives on a case-sensitive
Linux filesystem so case-distinct licence filenames remain intact.

## Troubleshooting boundaries

- **Missing `qemu-system-aarch64`**: Set `QEMU_SYSTEM_AARCH64=/path/to/qemu-system-aarch64`
  for `launch-qemu.sh` or pass `--qemu /path/to/qemu-system-aarch64` to
  `run-evaluation.py`.
- **Host architecture**: The guest kernel and rootfs are `aarch64` (`cortex-a57`);
  `qemu-system-aarch64` runs under TCG emulation on both ARM64 and x86_64 hosts,
  whereas the pinned Yocto build container in `kas/builder-image.txt` targets a
  Linux ARM64 builder.
- **Scope limits**: Passing these isolated `qemuarm64` checks does not validate
  physical boards, vendor BSP kernels, or non-HTTP/2 `libwebsockets` subsystems.
