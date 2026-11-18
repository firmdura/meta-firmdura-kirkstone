# Keyless signing of frozen release assets

The signing workflow, strict manifest v1 verifier, human-gated
`release-signing` environment, and trusted `kind=fixture` GitHub Actions OIDC
smoke run are verified in
[`evidence/20261118-sti111-oidc-fixture/run.json`](../evidence/20261118-sti111-oidc-fixture/run.json)
(supplementing the initial local preparation record in
[`evidence/20261118-sti111-keyless-signing/run.json`](../evidence/20261118-sti111-keyless-signing/run.json)).
Fixture signatures are **not** production release evidence: exact-release human
approval, `kind=release` signing over the final frozen candidate assets,
publication, and public-download verification remain separately required.

## Frozen manifest v1

The [build and evidence contract](build.md#ownership-and-evidence-interface)
remains authoritative. The concrete interface below was reviewed on 2026-11-18
for release packaging, VEX integration and publication:

- `schema_version`: integer `1`.
- `release`: exactly `kind` (`release` or `fixture`) and `id` (the planned release
  tag, or the explicit fixture identifier). IDs use ASCII letters, digits,
  `.`, `_`, `-`, begin with a letter/digit, and are at most 128 characters.
- `source`: exactly `repository`, fixed to
  `https://github.com/firmdura/meta-firmdura-kirkstone`, and `commit`, the full
  lowercase 40-character reviewed producer source/evidence commit. This is not
  necessarily the signing workflow's checkout. Per-variant provenance payloads
  must retain the actual baseline/patched source, test and image identities;
  do not relabel historical builds as this common producer commit.
- `artifacts`: nonempty array of objects containing `path`, `role`, `size`
  (nonnegative integer bytes), and lowercase `sha256`. Include `variant`
  (`baseline` or `patched`) for variant-specific payloads; omit it for shared
  material. Roles are lowercase descriptive tokens such as `qemu-bundle`,
  `corresponding-source`, `licenses`, `sbom`, `vex`, or `provenance`. Schema
  checks do not certify that the selected roles satisfy redistribution or
  runtime/scanner requirements; their human review remains mandatory.

`manifest.json` binds **every** deliverable: image/QEMU bundles, corresponding
source, licences, SBOMs, VEX, instructions, inventories and evidence as applicable.
The only unlisted files are `manifest.json` itself and the later
`manifest.sigstore.json` bundle. Unknown fields, duplicate JSON keys/paths, missing
files, extra files and empty extraneous directories fail.

Paths are normalized relative POSIX names. Components start with an ASCII
letter/digit and contain only letters/digits, `.`, `_`, `-`; no absolute paths,
dot segments, hidden components, trailing dots, backslashes, reserved device
names, or case-colliding file/directory names. Paths are at most 240 characters.
**Release** payloads use flat filenames because GitHub release attachments have
flat names; labelled fixtures may also exercise subdirectories. There are at
most 10,000 payloads; manifest and signature bundle are each at most 1 MiB.
Filesystem and ZIP symlinks/special files are rejected.

Keep Linux deploy trees in canonical **tar payloads**, with the separately
verified path/size/hash/link inventory. These helpers treat each tar as opaque
bytes: they do not unpack Linux files on a case-insensitive control host, fix
absolute aliases, or claim portability. ZIP is only a transport for those
already frozen files. The workflow neither builds nor regenerates a manifest,
tar, SBOM, VEX, licence file, or other payload.

The [unsigned labelled fixture](../tests/release-fixtures/unsigned/manifest.json)
contains one harmless text payload. Its source field names the starting commit
for this schema exercise, **not a firmware build from that commit**. There is
deliberately no fabricated signature bundle in Git.

## Trust and human approval

Pinned released tools/actions:

| Component | Version | Immutable revision |
|---|---|---|
| Cosign | `v3.1.4` | release commit `0e48502cf5ef34e2e60bbd3617aa19945712f705` |
| cosign-installer | `v4.1.3` | `756fe2d284c7292c4e9b62c8a28f1e5629c59532` |
| checkout | `v7.0.1` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| upload-artifact | `v7.0.2` | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |

The pinned installer embeds the released Cosign binary digests; the workflow
explicitly selects `v3.1.4`. Verification also rejects another Cosign version.
Use that released tool, Python 3.11+ and GitHub CLI; the fixture certificate
inspection additionally needs OpenSSL. No Python packages are required.

[release.yml](../.github/workflows/release.yml) is manual-dispatch only. A
non-OIDC preflight requires the exact repository, `refs/heads/main`, and an
existing `release-signing` environment with:

1. Explicit human user reviewers (not bots or a team-only surrogate).
2. Exactly one custom deployment policy: branch `main`, not a tag or wildcard.

Explicit human environment approval is mandatory in every case. Prevent
self-review is recommended when separate authorized dispatcher and reviewer
accounts exist, but is not required by the preflight. When the dispatcher is
also an authorized reviewer, `prevent_self_review: false` permits approval by
that account without removing the required human approval gate.

Only the subsequent environment-gated signing job gets `id-token: write`.
Its other permissions are `contents: read` and `actions: read`; it has no release
write permission. Checkout uses the dispatch commit with credentials disabled.
Untrusted PR code is never checked out or executed. Candidate downloads are
data, not scripts. The policy is rechecked after approval. Protection/API errors
fail the workflow, rather than silently skipping signing successfully.

**Verified environment protection:** `release-signing` is configured with
explicit human user review, `can_admins_bypass: false`, and a single custom
deployment branch policy permitting only `main`. `scripts/release/approval.py`
verifies this policy both before and after human deployment approval.

Signing code must be reviewed and integrated into trusted main **before** a
fixture dispatch. Do not run signing code from an unreviewed topic branch.

## Sign and verify

The reviewer approves all dispatch inputs together: `kind`, optional numeric
artifact ID (blank for the in-tree fixture or when `kind=release` downloads a
staged unpublished `draft` GitHub Release for `release_id`), the independently
recorded exact manifest SHA-256, release ID, and source commit. For real
releases, the staged input must be either an immutable GitHub Actions ZIP or a
single unpublished `draft` GitHub Release (`verify.py stage-download`) whose
asset set contains `manifest.json` and exactly its listed frozen payloads, with
no preexisting signature bundle or wrapper directory. Assemble the frozen
candidate deterministically from `<store>` and the reviewed release commit with
[`scripts/release/assemble_candidate.py`](../scripts/release/assemble_candidate.py),
and verify the staged draft release after attaching `manifest.sigstore.json`
with `verify.py draft-release` before flipping `draft` to `false`. Review the
bytes and provenance before approval, not just a job name.

The only signing command is:

```sh
cosign sign-blob --yes --oidc-provider github-actions \
  --bundle candidate/manifest.sigstore.json candidate/manifest.json
```

There is no stored private key or local signing fallback. `--yes` accepts
Cosign's transparency-service prompt; it does not replace environment approval.
The exact manifest digest is checked before signing. After signing, verification
uses **both literal constraints**, with no regular-expression or insecure flags:

```text
issuer:   https://token.actions.githubusercontent.com
identity: https://github.com/firmdura/meta-firmdura-kirkstone/.github/workflows/release.yml@refs/heads/main
```

The certificate authenticates that precise trusted main workflow. The signed
manifest plus independently approved inputs bind the release/tag and producer
commit separately; a certificate on `main` is not evidence of a release-tag
workflow or of a tested firmware pair.

For an already complete, immutable local asset directory:

```sh
python3 scripts/release/verify.py verify --assets candidate \
  --manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --release-id "$APPROVED_RELEASE_ID" --source-commit "$APPROVED_SOURCE_COMMIT"
```

Obtain those expected values from the independently approved release record,
not by blindly calculating them from an untrusted download. The verifier first
checks schema/asset-set safety, invokes pinned Cosign, and then checks every
payload size/digest and the still-unchanged approved manifest. Nothing in a
candidate directory is executed. Keep that directory private/read-only to other
writers during verification.

For a published release, use the complete-download path, not filtered assets:

```sh
python3 scripts/release/verify.py github-release --assets new-download-directory \
  --manifest-sha256 "$APPROVED_MANIFEST_SHA256" \
  --release-id "$APPROVED_RELEASE_ID" --source-commit "$APPROVED_SOURCE_COMMIT"
```

It snapshots **all uploaded release assets**, paginating the API, downloads all
of them into a new directory, requires exact agreement with both the snapshot
and manifest, performs cryptographic/payload verification, and checks that the
remote asset identities did not change during the operation. It does not treat
GitHub's automatically generated source-code links as reviewed corresponding
source; the required actual source archives must be listed uploaded payloads.
A local directory check cannot detect an omitted remote asset by itself.

`check` is only a frozen-byte preflight and prints
`payloads-checked-no-signature`; it never claims authenticity. `unpack` safely
checks a frozen unsigned ZIP against the approved inputs before extraction into
a new directory. Failed output must not be used. Neither command signs anything.

The workflow retains a signed candidate Actions artifact for **14 days** and
prints manifest/bundle hashes. This is a handoff, **not durable publication**.
Copy unchanged bytes and logs to the approved durable artifact store before
expiry, obtain exact-release human approval, publish all assets,
and run the complete public-download verifier. This workflow never publishes.

## Focused validation and verified trusted OIDC fixture run

Only the small sanitized `run.json` is committed under each evidence run
directory. Raw command logs are retained in the approved
`local://firmdura-kirkstone/logs/` store, with byte sizes and SHA-256 values in the
run record. Its `<checkout>` and `<store>` aliases keep host paths out of Git.

```sh
python3 -m unittest discover -s tests -p release_test.py -v
actionlint .github/workflows/release.yml
```

Local tests exercise valid fixture bytes, changed manifest/payloads, missing and
unsigned assets, wrong source/kind, unsafe paths, duplicates, ZIP extraction,
complete/paginated remote asset sets and human-policy failures. Cosign
orchestration tests use explicit mocks: they check exact arguments and failure
propagation, **not cryptographic authenticity or GitHub OIDC**.

On 2026-11-18, `release.yml` was dispatched on trusted `main`
(`b028134144e00abb123d7b2d8d0235f018e3d90b`) in
[Actions run `44306456937`](https://github.com/firmdura/meta-firmdura-kirkstone/actions/runs/44306456937)
with `kind=fixture`, blank `artifact_id`, `release_id=sti111-keyless-fixture`,
`source_commit=44210974feddea19687ea2d7466f99f45d43588b`, and
`manifest_sha256=fddfeeedd471693861cf6649f22030c3b41a1923eda49b20e1e83afdf184bb60`.
After `approval-policy` passed and human deployment approval was granted on
`release-signing`, `sign` minted a Fulcio certificate via GitHub Actions OIDC,
emitted Sigstore bundle `manifest.sigstore.json`
(`4f85529b613a09ad223ede82644ace7b814d11c8c329d4afb285bd29c7325de6`, certificate
DER `b71f7a5206b351bf31d48b626baf9b7e1b49ad96d311a30c5a5a0043a480e9c2`, SAN
`URI:https://github.com/firmdura/meta-firmdura-kirkstone/.github/workflows/release.yml@refs/heads/main`,
issuer `https://token.actions.githubusercontent.com`), and passed all
`tests/release_oidc.py` positive and negative controls both in-workflow and
upon local archive download and re-verification:

- Real valid fixture signature, actual certificate SAN and certificate/bundle hashes.
- Wrong exact identity and wrong issuer rejected by real Cosign `v3.1.4`.
- Changed manifest bytes rejected by Cosign even with the new digest supplied.
- Changed/missing payload, unsigned extra and renamed/mismatched asset sets rejected.
- Original frozen fixture still verifies after the negative controls.

Full run metadata, approval records, durable bundle locators, and local
re-verification logs are indexed in
[`evidence/20261118-sti111-oidc-fixture/run.json`](../evidence/20261118-sti111-oidc-fixture/run.json).
This fixture signature is **not** production release evidence.
