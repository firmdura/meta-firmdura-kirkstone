# Firmdura Kirkstone reference sample

A Yocto Kirkstone reference project for embedded Linux engineers evaluating
security maintenance for **libwebsockets**. It provides a pinned ARM64 QEMU
image configuration and checks for the library running inside it.

**Experimental:** paired `baseline` and `patched` images build, boot, and
demonstrate the reviewed target HTTP/2 fix in isolated QEMU checks, while
external scanner feed coverage and a signed downloadable release are not yet
complete. Use this repository only for isolated evaluation, not as production
firmware.

## What is included

- A `qemuarm64` image based on Poky 4.0.35, meta-openembedded and Garmin's
  [meta-lts-collab](https://github.com/garmin/meta-lts-collab).
- Immutable layer revisions and a pinned kas build container.
- A separately consumable repair layer
  ([`recipes-connectivity/libwebsockets/`](recipes-connectivity/libwebsockets/libwebsockets_4.2.2.bbappend))
  backporting the upstream `CVE-2026-19773` bounds checks onto `libwebsockets`
  4.2.2 with HTTP/2, TLS, client and server support kept enabled.
- Target C and `ptest` checks verifying library identity, normal HTTP/2
  request handling, targeted `CVE-2026-19773` out-of-bounds write reproduction
  on `baseline`, and enforced bounds with post-attack HTTP/2 service on
  `patched`.
- [Paired validation results](evidence/20261118-sti110-paired-validation/run.json)
  and [initial baseline build results](evidence/20261117-sti108-baseline/run.json)
  linking source revisions to package, SBOM and image hashes.

## Getting started

Builds require Docker and a **Linux ARM64** builder. macOS can control a Linux
VM, but build files must stay on the Linux filesystem. The
[build guide](docs/build.md) covers builder setup, disk space, Docker contexts
and the work volume.

```sh
git clone https://github.com/firmdura/meta-firmdura-kirkstone.git
cd meta-firmdura-kirkstone
```

After completing the builder and work-volume setup, run as a non-root user
from the repository root:

```sh
sh kas/run baseline build
sh kas/run patched build
```

Then follow the [QEMU boot and target test procedures](docs/testing.md#boot-and-identify-the-actual-library)
to verify the installed library and run the HTTP/2 regression and security
checks on disposable rootfs copies.

## Current security work

The target case is [CVE-2026-19773](https://www.zerodayinitiative.com/advisories/ZDI-26-590/).
On `qemuarm64`, the `baseline` build reproduces the HTTP/2 HPACK `:path`
out-of-bounds heap write in `lws_frag_append`, and the `patched` build rejects
the oversized `:path` inputs cleanly while continuing to serve valid HTTP/2
traffic. The reviewed `baseline` and `patched` image pair is frozen for
evaluation-bundle packaging.

Full-image SPDX 2.2 consolidation lets pinned Grype catalog all installed
target packages offline, while upstream vulnerability feeds still lack CPE
applicability configurations for `CVE-2026-19773`; see the
[testing guide](docs/testing.md) and [scanner guide](docs/scanner.md) for
measured results and open publication gates.

Results apply only to this reference configuration. Compatibility with other
Kirkstone BSPs, physical boards or customer firmware has not been validated.

## Licensing

[MIT](LICENSE) applies to original Firmdura files. Third-party layers, sources
and binaries retain their own licences and notices; see the
[licence boundary](docs/build.md#licence-boundary).
