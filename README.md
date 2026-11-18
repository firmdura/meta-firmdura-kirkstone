# Firmdura Kirkstone reference sample

A Yocto Kirkstone reference project for embedded Linux engineers evaluating
security maintenance for **libwebsockets**. It provides a pinned ARM64 QEMU
image configuration and checks for the library running inside it.

**Experimental:** the baseline builds and boots, but there is no validated
security repair or downloadable release yet. Use it only for isolated
evaluation, not as production firmware.

## What is included

- A `qemuarm64` image based on Poky 4.0.35, meta-openembedded and Garmin's
  [meta-lts-collab](https://github.com/garmin/meta-lts-collab).
- Immutable layer revisions and a pinned kas build container.
- libwebsockets 4.2.2 with HTTP/2, TLS, client and server support enabled.
- A QEMU boot check that verifies the installed library's bytes, runtime
  version and enabled features.
- [Build results](evidence/20261117-sti108-baseline/run.json) linking source
  revisions to package and image hashes.

The `patched` configuration is a placeholder and does **not** contain a repair.

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
```

Then follow the [QEMU boot procedure](docs/testing.md#boot-and-identify-the-actual-library)
to start the image and verify the installed library. A successful boot check
does not prove that a vulnerability has been reproduced or fixed.

## Current security work

The target case is [CVE-2026-19773](https://www.zerodayinitiative.com/advisories/ZDI-26-590/).
The baseline is ready for runtime reproduction and repair work, but neither
has been demonstrated yet. The pinned Grype scanner and database do not
report this CVE for the actual build. Scanner interoperability is a separate
unresolved requirement for VEX and publication, not evidence that the component
is unaffected.

See [testing and scanner limitations](docs/testing.md) for the findings and
what the existing checks do and do not establish.

Results apply only to this reference configuration. Compatibility with other
Kirkstone BSPs, physical boards or customer firmware has not been validated.

## Licensing

[MIT](LICENSE) applies to original Firmdura files. Third-party layers, sources
and binaries retain their own licences and notices; see the
[licence boundary](docs/build.md#licence-boundary).
