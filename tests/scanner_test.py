#!/usr/bin/env python3
"""Unit tests for Yocto SPDX 2.2 external-document graph consolidation and fail-closed checks."""

from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS.parent / "scripts" / "vex"))
import normalize_spdx  # noqa: E402


def _spdx_doc(
    name: str,
    namespace: str,
    *,
    packages: list[dict] | None = None,
    files: list[dict] | None = None,
    external_refs: list[dict] | None = None,
    relationships: list[dict] | None = None,
) -> dict:
    doc = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "spdxVersion": "SPDX-2.2",
        "dataLicense": "CC0-1.0",
        "name": name,
        "documentNamespace": namespace,
        "creationInfo": {
            "created": "2026-11-17T22:59:29Z",
            "creators": ["Tool: OpenEmbedded Core create-spdx.bbclass"],
        },
        "relationships": relationships or [],
    }
    if packages is not None:
        doc["packages"] = packages
    if files is not None:
        doc["files"] = files
    if external_refs is not None:
        doc["externalDocumentRefs"] = external_refs
    return doc


def _encode(doc: dict) -> bytes:
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _ext_ref(doc_id: str, namespace: str, raw: bytes, algorithm: str = "SHA1") -> dict:
    digest = (
        hashlib.sha1(raw).hexdigest()
        if algorithm == "SHA1"
        else hashlib.sha256(raw).hexdigest()
    )
    return {
        "externalDocumentId": doc_id,
        "spdxDocument": namespace,
        "checksum": {"algorithm": algorithm, "checksumValue": digest},
    }


class NormalizeSpdxTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory(
            prefix="scanner-tests-", dir=TESTS
        )
        self.addCleanup(self.directory.cleanup)
        self.base = Path(self.directory.name)
        self._build_fixture_tree()

    def _build_fixture_tree(self) -> None:
        # Build-only native recipe (must be traversed & verified, then excluded from target SBOM).
        self.native_ns = "http://spdx.org/spdxdoc/recipe-cmake-native-1111"
        self.native_doc = _spdx_doc(
            "recipe-cmake-native",
            self.native_ns,
            packages=[
                {
                    "SPDXID": "SPDXRef-Recipe-cmake-native",
                    "name": "cmake-native",
                    "versionInfo": "3.22.3",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "BSD-3-Clause",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": normalize_spdx.YOCTO_CPE23_URI,
                            "referenceLocator": "cpe:2.3:a:cmake_project:cmake:3.22.3:*:*:*:*:*:*:*",
                        }
                    ],
                }
            ],
            relationships=[
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Recipe-cmake-native",
                }
            ],
        )
        self.native_bytes = _encode(self.native_doc)

        # Target recipe with Yocto full-URI cpe23Type + build-traceable purl.
        self.lws_recipe_ns = "http://spdx.org/spdxdoc/recipe-libwebsockets-2222"
        self.lws_recipe_doc = _spdx_doc(
            "recipe-libwebsockets",
            self.lws_recipe_ns,
            packages=[
                {
                    "SPDXID": "SPDXRef-Recipe-libwebsockets",
                    "name": "libwebsockets",
                    "versionInfo": "4.2.2",
                    "downloadLocation": "git://github.com/warmcat/libwebsockets.git",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "MIT",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": normalize_spdx.YOCTO_CPE23_URI,
                            "referenceLocator": "cpe:2.3:a:*:libwebsockets:4.2.2:*:*:*:*:*:*:*",
                        },
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:generic/libwebsockets@4.2.2",
                        },
                    ],
                }
            ],
            external_refs=[
                _ext_ref(
                    "DocumentRef-dependency-recipe-cmake-native",
                    self.native_ns,
                    self.native_bytes,
                    algorithm="SHA256",
                )
            ],
            relationships=[
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Recipe-libwebsockets",
                },
                {
                    "spdxElementId": "DocumentRef-dependency-recipe-cmake-native:SPDXRef-Recipe-cmake-native",
                    "relationshipType": "BUILD_DEPENDENCY_OF",
                    "relatedSpdxElement": "SPDXRef-Recipe-libwebsockets",
                },
            ],
        )
        self.lws_recipe_bytes = _encode(self.lws_recipe_doc)

        self.libc_recipe_ns = "http://spdx.org/spdxdoc/recipe-glibc-3333"
        self.libc_recipe_doc = _spdx_doc(
            "recipe-glibc",
            self.libc_recipe_ns,
            packages=[
                {
                    "SPDXID": "SPDXRef-Recipe-glibc",
                    "name": "glibc",
                    "versionInfo": "2.35",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "LGPL-2.1-or-later",
                    "copyrightText": "NOASSERTION",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": normalize_spdx.YOCTO_CPE23_URI,
                            "referenceLocator": "cpe:2.3:a:*:glibc:2.35:*:*:*:*:*:*:*",
                        }
                    ],
                }
            ],
            relationships=[
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Recipe-glibc",
                }
            ],
        )
        self.libc_recipe_bytes = _encode(self.libc_recipe_doc)

        # Binary packages.
        lib_bytes = b"\x7fELF-fake-libwebsockets-binary"
        self.lib_sha1 = hashlib.sha1(lib_bytes).hexdigest()
        self.lib_sha256 = hashlib.sha256(lib_bytes).hexdigest()

        self.lws_pkg_ns = "http://spdx.org/spdxdoc/libwebsockets18-4444"
        self.lws_pkg_doc = _spdx_doc(
            "libwebsockets18",
            self.lws_pkg_ns,
            packages=[
                {
                    "SPDXID": "SPDXRef-Package-libwebsockets18",
                    "name": "libwebsockets18",
                    "versionInfo": "4.2.2",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "MIT",
                    "copyrightText": "NOASSERTION",
                    "hasFiles": ["SPDXRef-PackagedFile-libwebsockets18-1"],
                }
            ],
            files=[
                {
                    "SPDXID": "SPDXRef-PackagedFile-libwebsockets18-1",
                    "fileName": "usr/lib/libwebsockets.so.18",
                    "fileTypes": ["BINARY"],
                    "licenseConcluded": "NOASSERTION",
                    "licenseInfoInFiles": ["NOASSERTION"],
                    "copyrightText": "NOASSERTION",
                    "checksums": [
                        {"algorithm": "SHA1", "checksumValue": self.lib_sha1},
                        {"algorithm": "SHA256", "checksumValue": self.lib_sha256},
                    ],
                }
            ],
            external_refs=[
                _ext_ref(
                    "DocumentRef-recipe-libwebsockets",
                    self.lws_recipe_ns,
                    self.lws_recipe_bytes,
                )
            ],
            relationships=[
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Package-libwebsockets18",
                },
                {
                    "spdxElementId": "SPDXRef-Package-libwebsockets18",
                    "relationshipType": "GENERATED_FROM",
                    "relatedSpdxElement": "DocumentRef-recipe-libwebsockets:SPDXRef-Recipe-libwebsockets",
                },
                {
                    "spdxElementId": "SPDXRef-Package-libwebsockets18",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "SPDXRef-PackagedFile-libwebsockets18-1",
                },
                {
                    "spdxElementId": "SPDXRef-PackagedFile-libwebsockets18-1",
                    "relationshipType": "GENERATED_FROM",
                    "relatedSpdxElement": "NOASSERTION",
                },
            ],
        )
        self.lws_pkg_bytes = _encode(self.lws_pkg_doc)

        self.libc_pkg_ns = "http://spdx.org/spdxdoc/libc6-5555"
        self.libc_pkg_doc = _spdx_doc(
            "libc6",
            self.libc_pkg_ns,
            packages=[
                {
                    "SPDXID": "SPDXRef-Package-libc6",
                    "name": "libc6",
                    "versionInfo": "2.35",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "LGPL-2.1-or-later",
                    "copyrightText": "NOASSERTION",
                }
            ],
            external_refs=[
                _ext_ref(
                    "DocumentRef-recipe-glibc",
                    self.libc_recipe_ns,
                    self.libc_recipe_bytes,
                )
            ],
            relationships=[
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "DESCRIBES",
                    "relatedSpdxElement": "SPDXRef-Package-libc6",
                },
                {
                    "spdxElementId": "SPDXRef-Package-libc6",
                    "relationshipType": "GENERATED_FROM",
                    "relatedSpdxElement": "DocumentRef-recipe-glibc:SPDXRef-Recipe-glibc",
                },
            ],
        )
        self.libc_pkg_bytes = _encode(self.libc_pkg_doc)

        # Runtime dependency doc.
        self.rt_lws_ns = "http://spdx.org/spdxdoc/runtime-libwebsockets18-6666"
        self.rt_lws_doc = _spdx_doc(
            "runtime-libwebsockets18",
            self.rt_lws_ns,
            external_refs=[
                _ext_ref(
                    "DocumentRef-package-libwebsockets",
                    self.lws_pkg_ns,
                    self.lws_pkg_bytes,
                ),
                _ext_ref(
                    "DocumentRef-runtime-dependency-libc6",
                    self.libc_pkg_ns,
                    self.libc_pkg_bytes,
                ),
            ],
            relationships=[
                {
                    "spdxElementId": "SPDXRef-DOCUMENT",
                    "relationshipType": "AMENDS",
                    "relatedSpdxElement": "DocumentRef-package-libwebsockets:SPDXRef-DOCUMENT",
                },
                {
                    "spdxElementId": "DocumentRef-runtime-dependency-libc6:SPDXRef-Package-libc6",
                    "relationshipType": "RUNTIME_DEPENDENCY_OF",
                    "relatedSpdxElement": "DocumentRef-package-libwebsockets:SPDXRef-Package-libwebsockets18",
                },
            ],
        )
        self.rt_lws_bytes = _encode(self.rt_lws_doc)

        # Root image SPDX.
        self.image_stem = "firmdura-reference-baseline-qemuarm64-20261117213416"
        self.root_ns = f"http://spdx.org/spdxdoc/{self.image_stem}-7777"
        self.root_doc = _spdx_doc(
            self.image_stem,
            self.root_ns,
            packages=[
                {
                    "SPDXID": f"SPDXRef-Image-{self.image_stem}",
                    "name": "firmdura-reference-image",
                    "versionInfo": "1.0",
                    "downloadLocation": "NOASSERTION",
                    "licenseConcluded": "NOASSERTION",
                    "licenseDeclared": "NOASSERTION",
                    "copyrightText": "NOASSERTION",
                }
            ],
            external_refs=[
                _ext_ref(
                    "DocumentRef-libwebsockets18",
                    self.lws_pkg_ns,
                    self.lws_pkg_bytes,
                ),
                _ext_ref(
                    "DocumentRef-libc6",
                    self.libc_pkg_ns,
                    self.libc_pkg_bytes,
                ),
                _ext_ref(
                    "DocumentRef-runtime-libwebsockets18",
                    self.rt_lws_ns,
                    self.rt_lws_bytes,
                ),
            ],
            relationships=[
                {
                    "spdxElementId": f"SPDXRef-Image-{self.image_stem}",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "DocumentRef-libwebsockets18:SPDXRef-Package-libwebsockets18",
                },
                {
                    "spdxElementId": f"SPDXRef-Image-{self.image_stem}",
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": "DocumentRef-libc6:SPDXRef-Package-libc6",
                },
                {
                    "spdxElementId": f"SPDXRef-Image-{self.image_stem}",
                    "relationshipType": "OTHER",
                    "relatedSpdxElement": "DocumentRef-runtime-libwebsockets18:SPDXRef-DOCUMENT",
                },
            ],
        )
        self.root_bytes = _encode(self.root_doc)

        self.rootfs_bytes = b"EXT4-ROOTFS-PAYLOAD-BYTES"
        self.rootfs_sha256 = hashlib.sha256(self.rootfs_bytes).hexdigest()
        self.manifest_bytes = (
            b"libc6 cortexa57 2.35-r0\n"
            b"libwebsockets18 cortexa57 4.2.2-r0\n"
        )

        # Write directory layout.
        self.deploy_dir = self.base / "deploy"
        img_dir = self.deploy_dir / "images" / "qemuarm64"
        spdx_dir = self.deploy_dir / "spdx" / "qemuarm64"
        for sub in ("packages", "recipes", "runtime", "by-namespace"):
            (spdx_dir / sub).mkdir(parents=True, exist_ok=True)
        img_dir.mkdir(parents=True, exist_ok=True)

        self.root_spdx_file = img_dir / f"{self.image_stem}.spdx.json"
        self.root_spdx_file.write_bytes(self.root_bytes)
        (img_dir / f"{self.image_stem}.rootfs.ext4").write_bytes(self.rootfs_bytes)
        (img_dir / f"{self.image_stem}.rootfs.manifest").write_bytes(self.manifest_bytes)

        self.file_map = {
            (spdx_dir / "recipes" / "recipe-cmake-native.spdx.json"): (
                self.native_ns,
                self.native_bytes,
            ),
            (spdx_dir / "recipes" / "recipe-libwebsockets.spdx.json"): (
                self.lws_recipe_ns,
                self.lws_recipe_bytes,
            ),
            (spdx_dir / "recipes" / "recipe-glibc.spdx.json"): (
                self.libc_recipe_ns,
                self.libc_recipe_bytes,
            ),
            (spdx_dir / "packages" / "libwebsockets18.spdx.json"): (
                self.lws_pkg_ns,
                self.lws_pkg_bytes,
            ),
            (spdx_dir / "packages" / "libc6.spdx.json"): (
                self.libc_pkg_ns,
                self.libc_pkg_bytes,
            ),
            (spdx_dir / "runtime" / "runtime-libwebsockets18.spdx.json"): (
                self.rt_lws_ns,
                self.rt_lws_bytes,
            ),
        }
        for path, (ns, raw) in self.file_map.items():
            path.write_bytes(raw)
            rel_target = Path("..") / path.parent.name / path.name
            (spdx_dir / "by-namespace" / ns.replace("/", "_")).symlink_to(rel_target)

    def _build_deploy_tar(self) -> Path:
        tar_path = self.base / "deploy.tar"
        with tarfile.open(tar_path, "w") as archive:
            for item in sorted(self.deploy_dir.rglob("*")):
                arcname = f"deploy/{item.relative_to(self.deploy_dir).as_posix()}"
                if item.is_symlink():
                    info = tarfile.TarInfo(arcname)
                    info.type = tarfile.SYMTYPE
                    info.linkname = item.readlink().as_posix()
                    archive.addfile(info)
                elif item.is_file():
                    data = item.read_bytes()
                    info = tarfile.TarInfo(arcname)
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        return tar_path

    def test_tar_and_directory_modes_produce_identical_consolidated_sbom(self) -> None:
        tar_path = self._build_deploy_tar()
        tar_sha = hashlib.sha256(tar_path.read_bytes()).hexdigest()

        tar_sbom_bytes, tar_manifest = normalize_spdx.normalize_image_spdx(
            deploy_tar=tar_path,
            expected_deploy_tar_sha256=tar_sha,
            expected_package_count=2,
        )
        dir_sbom_bytes, dir_manifest = normalize_spdx.normalize_image_spdx(
            spdx_root=self.root_spdx_file,
            spdx_dirs=[self.deploy_dir / "spdx" / "qemuarm64"],
            expected_package_count=2,
        )

        self.assertEqual(tar_sbom_bytes, dir_sbom_bytes)
        sbom = json.loads(tar_sbom_bytes.decode("utf-8"))
        self.assertNotIn("externalDocumentRefs", sbom)
        self.assertEqual(
            sbom["documentDescribes"],
            [f"SPDXRef-DocumentRoot-File-{self.image_stem}"],
        )

        pkg_by_id = {p["SPDXID"]: p for p in sbom["packages"]}
        # Root source + 2 installed packages + 2 target recipes; cmake-native excluded!
        self.assertEqual(
            set(pkg_by_id),
            {
                f"SPDXRef-DocumentRoot-File-{self.image_stem}",
                "SPDXRef-Package-libc6",
                "SPDXRef-Package-libwebsockets18",
                "SPDXRef-Recipe-glibc",
                "SPDXRef-Recipe-libwebsockets",
            },
        )
        root_pkg = pkg_by_id[f"SPDXRef-DocumentRoot-File-{self.image_stem}"]
        self.assertEqual(root_pkg["versionInfo"], f"1.0-sha256.{self.rootfs_sha256}")
        self.assertEqual(
            root_pkg["checksums"],
            [{"algorithm": "SHA256", "checksumValue": self.rootfs_sha256}],
        )

        lws_pkg = pkg_by_id["SPDXRef-Package-libwebsockets18"]
        self.assertEqual(
            lws_pkg["externalRefs"],
            [
                {
                    "referenceCategory": "SECURITY",
                    "referenceType": "cpe23Type",
                    "referenceLocator": "cpe:2.3:a:*:libwebsockets:4.2.2:*:*:*:*:*:*:*",
                },
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:generic/libwebsockets@4.2.2",
                },
            ],
        )

        self.assertEqual(tar_manifest["graph"]["traversed_document_count"], 7)
        self.assertEqual(
            tar_manifest["graph"]["document_counts_by_role"],
            {
                "root_image": 1,
                "installed_package": 2,
                "runtime_dependency": 1,
                "recipe_target_traced": 2,
                "recipe_build_only_excluded": 1,
            },
        )
        self.assertEqual(tar_manifest["output"]["installed_package_count"], 2)
        self.assertEqual(
            tar_manifest["output"]["root_source_package"]["grype_openvex_product_purl"],
            f"pkg:generic/{self.image_stem}@1.0-sha256.{self.rootfs_sha256}",
        )
        self.assertEqual(
            tar_manifest["normalizations_applied"]["reference_type_rewrites_count"], 2
        )
        self.assertEqual(
            dir_manifest["output"]["consolidated_spdx_sha256"],
            tar_manifest["output"]["consolidated_spdx_sha256"],
        )

    def test_missing_external_document_fails_closed(self) -> None:
        (
            self.deploy_dir
            / "spdx"
            / "qemuarm64"
            / "recipes"
            / "recipe-cmake-native.spdx.json"
        ).unlink()
        (
            self.deploy_dir
            / "spdx"
            / "qemuarm64"
            / "by-namespace"
            / self.native_ns.replace("/", "_")
        ).unlink()
        with self.assertRaisesRegex(
            normalize_spdx.NormalizationError, "missing external SPDX document"
        ):
            normalize_spdx.normalize_image_spdx(
                spdx_root=self.root_spdx_file,
                spdx_dirs=[self.deploy_dir / "spdx" / "qemuarm64"],
            )

    def test_external_document_checksum_mismatch_fails_closed(self) -> None:
        target = (
            self.deploy_dir
            / "spdx"
            / "qemuarm64"
            / "recipes"
            / "recipe-libwebsockets.spdx.json"
        )
        target.write_bytes(target.read_bytes() + b"\n")
        with self.assertRaisesRegex(
            normalize_spdx.NormalizationError, "SHA1 checksum mismatch"
        ):
            normalize_spdx.normalize_image_spdx(
                spdx_root=self.root_spdx_file,
                spdx_dirs=[self.deploy_dir / "spdx" / "qemuarm64"],
            )

    def test_dangling_external_spdxref_fails_closed(self) -> None:
        bad_root = dict(self.root_doc)
        bad_root["relationships"] = [
            *self.root_doc["relationships"],
            {
                "spdxElementId": f"SPDXRef-Image-{self.image_stem}",
                "relationshipType": "CONTAINS",
                "relatedSpdxElement": "DocumentRef-libc6:SPDXRef-Package-does-not-exist",
            },
        ]
        self.root_spdx_file.write_bytes(_encode(bad_root))
        with self.assertRaisesRegex(
            normalize_spdx.NormalizationError, "dangling external SPDXRef"
        ):
            normalize_spdx.normalize_image_spdx(
                spdx_root=self.root_spdx_file,
                spdx_dirs=[self.deploy_dir / "spdx" / "qemuarm64"],
            )

    def test_missing_installed_package_in_manifest_fails_closed(self) -> None:
        manifest_path = (
            self.deploy_dir
            / "images"
            / "qemuarm64"
            / f"{self.image_stem}.rootfs.manifest"
        )
        manifest_path.write_bytes(
            manifest_path.read_bytes() + b"busybox cortexa57 1.35.0-r0\n"
        )
        with self.assertRaisesRegex(
            normalize_spdx.NormalizationError,
            "installed package set mismatch between root SPDX and rootfs.manifest",
        ):
            normalize_spdx.normalize_image_spdx(
                spdx_root=self.root_spdx_file,
                spdx_dirs=[self.deploy_dir / "spdx" / "qemuarm64"],
            )

    def test_duplicate_json_key_fails_closed(self) -> None:
        raw = self.root_spdx_file.read_bytes().replace(
            b'"spdxVersion": "SPDX-2.2"',
            b'"spdxVersion": "SPDX-2.2", "spdxVersion": "SPDX-2.2"',
        )
        self.root_spdx_file.write_bytes(raw)
        with self.assertRaisesRegex(
            normalize_spdx.NormalizationError, "duplicate JSON key"
        ):
            normalize_spdx.normalize_image_spdx(
                spdx_root=self.root_spdx_file,
                spdx_dirs=[self.deploy_dir / "spdx" / "qemuarm64"],
            )

    def test_dangling_local_spdxref_fails_closed(self) -> None:
        bad_root = dict(self.root_doc)
        bad_root["relationships"] = [
            *self.root_doc["relationships"],
            {
                "spdxElementId": "SPDXRef-Image-missing-local",
                "relationshipType": "DESCRIBES",
                "relatedSpdxElement": f"SPDXRef-Image-{self.image_stem}",
            },
        ]
        self.root_spdx_file.write_bytes(_encode(bad_root))
        with self.assertRaisesRegex(
            normalize_spdx.NormalizationError, "dangling local SPDXRef"
        ):
            normalize_spdx.normalize_image_spdx(
                spdx_root=self.root_spdx_file,
                spdx_dirs=[self.deploy_dir / "spdx" / "qemuarm64"],
            )

    def test_missing_generated_from_recipe_fails_closed(self) -> None:
        bad_lws_pkg = dict(self.lws_pkg_doc)
        bad_lws_pkg["relationships"] = [
            r
            for r in self.lws_pkg_doc["relationships"]
            if r["relationshipType"] != "GENERATED_FROM"
            or r["spdxElementId"] != "SPDXRef-Package-libwebsockets18"
        ]
        bad_lws_bytes = _encode(bad_lws_pkg)
        (
            self.deploy_dir
            / "spdx"
            / "qemuarm64"
            / "packages"
            / "libwebsockets18.spdx.json"
        ).write_bytes(bad_lws_bytes)

        # Update checksums referencing libwebsockets18.spdx.json so we reach GENERATED_FROM check.
        updated_rt = dict(self.rt_lws_doc)
        updated_rt["externalDocumentRefs"] = [
            _ext_ref(
                "DocumentRef-package-libwebsockets", self.lws_pkg_ns, bad_lws_bytes
            ),
            _ext_ref(
                "DocumentRef-runtime-dependency-libc6",
                self.libc_pkg_ns,
                self.libc_pkg_bytes,
            ),
        ]
        updated_rt_bytes = _encode(updated_rt)
        (
            self.deploy_dir
            / "spdx"
            / "qemuarm64"
            / "runtime"
            / "runtime-libwebsockets18.spdx.json"
        ).write_bytes(updated_rt_bytes)

        updated_root = dict(self.root_doc)
        updated_root["externalDocumentRefs"] = [
            _ext_ref("DocumentRef-libwebsockets18", self.lws_pkg_ns, bad_lws_bytes),
            _ext_ref("DocumentRef-libc6", self.libc_pkg_ns, self.libc_pkg_bytes),
            _ext_ref(
                "DocumentRef-runtime-libwebsockets18", self.rt_lws_ns, updated_rt_bytes
            ),
        ]
        self.root_spdx_file.write_bytes(_encode(updated_root))

        with self.assertRaisesRegex(
            normalize_spdx.NormalizationError,
            "expected exactly 1 GENERATED_FROM recipe for SPDXRef-Package-libwebsockets18",
        ):
            normalize_spdx.normalize_image_spdx(
                spdx_root=self.root_spdx_file,
                spdx_dirs=[self.deploy_dir / "spdx" / "qemuarm64"],
            )

    def test_cli_writes_deterministic_outputs_and_returns_nonzero_on_error(self) -> None:
        tar_path = self._build_deploy_tar()
        out_sbom = self.base / "out" / "consolidated.spdx.json"
        out_manifest = self.base / "out" / "normalization-manifest.json"
        rc = normalize_spdx.main(
            [
                "--deploy-tar",
                str(tar_path),
                "--expected-package-count",
                "2",
                "--output",
                str(out_sbom),
                "--manifest-out",
                str(out_manifest),
            ]
        )
        self.assertEqual(rc, 0)
        self.assertTrue(out_sbom.is_file())
        self.assertTrue(out_manifest.is_file())

        bad_rc = normalize_spdx.main(
            [
                "--deploy-tar",
                str(tar_path),
                "--expected-package-count",
                "39",
                "--output",
                str(out_sbom),
                "--manifest-out",
                str(out_manifest),
            ]
        )
        self.assertEqual(bad_rc, 1)


if __name__ == "__main__":
    unittest.main()
