#!/usr/bin/env python3
"""Consolidate and normalize a Yocto SPDX 2.2 image graph for Syft/Grype consumption."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import posixpath
import re
import sys
import tarfile
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
TOOL_PATH = "scripts/vex/normalize_spdx.py"
YOCTO_CPE23_URI = "http://spdx.org/rdf/references/cpe23Type"
YOCTO_PURL_URI = "http://spdx.org/rdf/references/purl"
SPDX_CPE23_TYPE = "cpe23Type"
SPDX_PURL_TYPE = "purl"
SPECIAL_ELEMENTS = frozenset({"NONE", "NOASSERTION"})
SUPPORTED_CHECKSUM_ALGORITHMS = {
    "SHA1": ("sha1", 40),
    "SHA256": ("sha256", 64),
}


class NormalizationError(ValueError):
    """Raised when an SPDX graph or image inventory violates fail-closed invariants."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise NormalizationError(message)


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NormalizationError(f"invalid JSON in {label}: {exc}") from exc
    require(isinstance(parsed, dict), f"expected top-level JSON object in {label}")
    return parsed


def sanitize_spdx_id_fragment(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9.-]+", "-", value).strip("-")
    require(bool(cleaned), f"cannot derive valid SPDX identifier fragment from {value!r}")
    return cleaned


def compute_digests(raw: bytes) -> dict[str, str]:
    return {
        "SHA1": hashlib.sha1(raw).hexdigest(),
        "SHA256": hashlib.sha256(raw).hexdigest(),
    }


def stream_sha256_and_size(stream: Any) -> tuple[str, int]:
    hasher = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        hasher.update(chunk)
        size += len(chunk)
    return hasher.hexdigest(), size


def file_sha256_and_size(path: Path) -> tuple[str, int]:
    with path.open("rb") as stream:
        return stream_sha256_and_size(stream)


@dataclass(frozen=True)
class RawDocumentRecord:
    locator: str
    raw_bytes: bytes
    sha1: str
    sha256: str
    size: int
    document: dict[str, Any]


@dataclass(frozen=True)
class BinaryArtifactDigest:
    locator: str
    sha256: str
    size: int


class SpdxDocumentStore:
    """Abstract read-only resolver for SPDX documents in deploy.tar or a directory."""

    def load_root(self, root_locator: str | None) -> RawDocumentRecord:
        raise NotImplementedError

    def resolve_namespace(self, namespace: str) -> RawDocumentRecord:
        raise NotImplementedError

    def load_optional_spdx_index(self, root_locator: str) -> RawDocumentRecord | None:
        raise NotImplementedError

    def load_rootfs_digest(
        self, root_locator: str, explicit_rootfs: str | None
    ) -> tuple[BinaryArtifactDigest | None, BinaryArtifactDigest | None]:
        raise NotImplementedError

    def load_manifest_text(
        self, root_locator: str, explicit_manifest: str | None
    ) -> tuple[str, BinaryArtifactDigest] | None:
        raise NotImplementedError


class TarDeployStore(SpdxDocumentStore):
    """Reads SPDX documents and image metadata directly from a canonical deploy.tar."""

    def __init__(self, archive: tarfile.TarFile) -> None:
        self._archive = archive
        self._members_by_name: dict[str, tarfile.TarInfo] = {}
        self._by_namespace_targets: dict[str, str] = {}
        self._spdx_json_members: list[str] = []
        self._scanned_all_namespaces = False
        self._namespace_cache: dict[str, RawDocumentRecord] = {}

        for member in archive.getmembers():
            if member.isdir():
                continue
            norm_name = posixpath.normpath(member.name)
            require(
                not norm_name.startswith("/") and not norm_name.startswith(".."),
                f"unsafe tar member path: {member.name}",
            )
            require(
                norm_name not in self._members_by_name,
                f"duplicate tar member path: {norm_name}",
            )
            self._members_by_name[norm_name] = member

        for norm_name, member in self._members_by_name.items():
            if "/by-namespace/" in norm_name:
                key = posixpath.basename(norm_name)
                target = self._resolve_member_path(norm_name)
                previous = self._by_namespace_targets.get(key)
                require(
                    previous is None or previous == target,
                    f"conflicting by-namespace entries for {key}: {previous} vs {target}",
                )
                self._by_namespace_targets[key] = target
            elif (
                member.isfile()
                and norm_name.endswith(".spdx.json")
                and not norm_name.endswith(".spdx.index.json")
            ):
                self._spdx_json_members.append(norm_name)

    def _resolve_member_path(self, name: str) -> str:
        visited: set[str] = set()
        current = posixpath.normpath(name)
        while True:
            require(current not in visited, f"symlink cycle in tar archive at {name}")
            visited.add(current)
            member = self._members_by_name.get(current)
            require(member is not None, f"missing tar member: {current}")
            if member.issym():
                require(
                    not member.linkname.startswith("/"),
                    f"unsupported absolute symlink for SPDX/image member: {current} -> {member.linkname}",
                )
                current = posixpath.normpath(
                    posixpath.join(posixpath.dirname(current), member.linkname)
                )
                require(
                    not current.startswith(".."),
                    f"archive symlink escapes root: {name} -> {current}",
                )
                continue
            if member.islnk():
                current = posixpath.normpath(member.linkname)
                continue
            require(member.isfile(), f"unsupported tar member type for {current}")
            return current

    def _read_bytes(self, name: str) -> tuple[str, bytes]:
        resolved = self._resolve_member_path(name)
        stream = self._archive.extractfile(self._members_by_name[resolved])
        require(stream is not None, f"unable to read tar member: {resolved}")
        with stream:
            return resolved, stream.read()

    def _read_stream_digest(self, name: str) -> BinaryArtifactDigest:
        resolved = self._resolve_member_path(name)
        stream = self._archive.extractfile(self._members_by_name[resolved])
        require(stream is not None, f"unable to stream tar member: {resolved}")
        with stream:
            sha256, size = stream_sha256_and_size(stream)
        return BinaryArtifactDigest(locator=resolved, sha256=sha256, size=size)

    def _load_spdx_record(self, name: str) -> RawDocumentRecord:
        resolved, raw = self._read_bytes(name)
        digests = compute_digests(raw)
        document = parse_json_bytes(raw, resolved)
        ns = document.get("documentNamespace")
        require(
            isinstance(ns, str) and bool(ns),
            f"missing documentNamespace in {resolved}",
        )
        existing = self._namespace_cache.get(ns)
        if existing is not None:
            require(
                existing.locator == resolved and existing.sha256 == digests["SHA256"],
                f"conflicting SPDX documents for namespace {ns}: {existing.locator} vs {resolved}",
            )
            return existing
        record = RawDocumentRecord(
            locator=resolved,
            raw_bytes=raw,
            sha1=digests["SHA1"],
            sha256=digests["SHA256"],
            size=len(raw),
            document=document,
        )
        self._namespace_cache[ns] = record
        return record

    def load_root(self, root_locator: str | None) -> RawDocumentRecord:
        if root_locator is not None:
            return self._load_spdx_record(root_locator)
        candidates = sorted(
            name
            for name, member in self._members_by_name.items()
            if member.isfile()
            and ("/images/" in f"/{name}")
            and name.endswith(".spdx.json")
            and not name.endswith(".spdx.index.json")
        )
        require(
            len(candidates) == 1,
            f"expected exactly 1 regular image .spdx.json in deploy.tar, found {len(candidates)}: {candidates}",
        )
        return self._load_spdx_record(candidates[0])

    def resolve_namespace(self, namespace: str) -> RawDocumentRecord:
        cached = self._namespace_cache.get(namespace)
        if cached is not None:
            return cached
        by_ns_key = namespace.replace("/", "_")
        target = self._by_namespace_targets.get(by_ns_key)
        if target is not None:
            record = self._load_spdx_record(target)
            require(
                record.document.get("documentNamespace") == namespace,
                f"by-namespace target {target} has documentNamespace "
                f"{record.document.get('documentNamespace')!r}, expected {namespace!r}",
            )
            return record
        if not self._scanned_all_namespaces:
            for member_name in sorted(self._spdx_json_members):
                self._load_spdx_record(member_name)
            self._scanned_all_namespaces = True
        cached = self._namespace_cache.get(namespace)
        require(
            cached is not None,
            f"missing external SPDX document for namespace: {namespace}",
        )
        return cached

    @staticmethod
    def _image_stem(root_locator: str) -> str:
        require(
            root_locator.endswith(".spdx.json"),
            f"root SPDX locator must end with .spdx.json: {root_locator}",
        )
        return root_locator[: -len(".spdx.json")]

    def load_optional_spdx_index(self, root_locator: str) -> RawDocumentRecord | None:
        index_name = f"{self._image_stem(root_locator)}.spdx.index.json"
        if index_name not in self._members_by_name:
            return None
        resolved, raw = self._read_bytes(index_name)
        digests = compute_digests(raw)
        document = parse_json_bytes(raw, resolved)
        return RawDocumentRecord(
            locator=resolved,
            raw_bytes=raw,
            sha1=digests["SHA1"],
            sha256=digests["SHA256"],
            size=len(raw),
            document=document,
        )

    def load_rootfs_digest(
        self, root_locator: str, explicit_rootfs: str | None
    ) -> tuple[BinaryArtifactDigest | None, BinaryArtifactDigest | None]:
        if explicit_rootfs is not None:
            return self._read_stream_digest(explicit_rootfs), None
        stem = self._image_stem(root_locator)
        ext4_name = f"{stem}.rootfs.ext4"
        require(
            ext4_name in self._members_by_name,
            f"missing canonical rootfs ext4 member in deploy.tar: {ext4_name}",
        )
        ext4_digest = self._read_stream_digest(ext4_name)
        tar_bz2_name = f"{stem}.rootfs.tar.bz2"
        tar_bz2_digest = (
            self._read_stream_digest(tar_bz2_name)
            if tar_bz2_name in self._members_by_name
            else None
        )
        return ext4_digest, tar_bz2_digest

    def load_manifest_text(
        self, root_locator: str, explicit_manifest: str | None
    ) -> tuple[str, BinaryArtifactDigest] | None:
        manifest_name = (
            explicit_manifest
            if explicit_manifest is not None
            else f"{self._image_stem(root_locator)}.rootfs.manifest"
        )
        require(
            manifest_name in self._members_by_name,
            f"missing rootfs manifest member in deploy.tar: {manifest_name}",
        )
        resolved, raw = self._read_bytes(manifest_name)
        digests = compute_digests(raw)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NormalizationError(f"invalid UTF-8 in {resolved}: {exc}") from exc
        return (
            text,
            BinaryArtifactDigest(
                locator=resolved, sha256=digests["SHA256"], size=len(raw)
            ),
        )


class DirectorySpdxStore(SpdxDocumentStore):
    """Reads SPDX documents from a Linux SPDX directory hierarchy."""

    def __init__(self, root_spdx_path: Path, search_dirs: list[Path]) -> None:
        self._root_spdx_path = root_spdx_path.resolve()
        self._search_dirs = [d.resolve() for d in search_dirs]
        self._base_dir = (
            self._search_dirs[0] if self._search_dirs else self._root_spdx_path.parent
        )
        self._namespace_cache: dict[str, RawDocumentRecord] = {}
        self._indexed = False

    def _rel_locator(self, path: Path) -> str:
        resolved = path.resolve()
        for base in [self._base_dir, *self._search_dirs, self._root_spdx_path.parent]:
            if resolved.is_relative_to(base):
                rel = resolved.relative_to(base).as_posix()
                return rel if rel != "." else resolved.name
        return resolved.name

    def _load_file_record(self, path: Path) -> RawDocumentRecord:
        require(path.is_file(), f"missing SPDX file: {path.name}")
        resolved = path.resolve()
        raw = resolved.read_bytes()
        locator = self._rel_locator(resolved)
        digests = compute_digests(raw)
        document = parse_json_bytes(raw, locator)
        ns = document.get("documentNamespace")
        require(
            isinstance(ns, str) and bool(ns),
            f"missing documentNamespace in {locator}",
        )
        existing = self._namespace_cache.get(ns)
        if existing is not None:
            require(
                existing.sha256 == digests["SHA256"],
                f"conflicting SPDX documents for namespace {ns}: {existing.locator} vs {locator}",
            )
            return existing
        record = RawDocumentRecord(
            locator=locator,
            raw_bytes=raw,
            sha1=digests["SHA1"],
            sha256=digests["SHA256"],
            size=len(raw),
            document=document,
        )
        self._namespace_cache[ns] = record
        return record

    def _ensure_indexed(self) -> None:
        if self._indexed:
            return
        seen_files: set[Path] = set()
        for directory in self._search_dirs:
            require(directory.is_dir(), f"SPDX search directory does not exist: {directory.name}")
            for candidate in sorted(directory.rglob("*.spdx.json")):
                if candidate.name.endswith(".spdx.index.json"):
                    continue
                resolved = candidate.resolve()
                if resolved in seen_files or not resolved.is_file():
                    continue
                seen_files.add(resolved)
                self._load_file_record(resolved)
        self._indexed = True

    def load_root(self, root_locator: str | None) -> RawDocumentRecord:
        del root_locator
        return self._load_file_record(self._root_spdx_path)

    def resolve_namespace(self, namespace: str) -> RawDocumentRecord:
        cached = self._namespace_cache.get(namespace)
        if cached is not None:
            return cached
        by_ns_name = namespace.replace("/", "_")
        for directory in self._search_dirs:
            for candidate in (
                directory / "by-namespace" / by_ns_name,
                directory / by_ns_name,
            ):
                if candidate.exists():
                    record = self._load_file_record(candidate)
                    require(
                        record.document.get("documentNamespace") == namespace,
                        f"by-namespace entry {candidate.name} has mismatched documentNamespace",
                    )
                    return record
        self._ensure_indexed()
        cached = self._namespace_cache.get(namespace)
        require(
            cached is not None,
            f"missing external SPDX document for namespace: {namespace}",
        )
        return cached

    def load_optional_spdx_index(self, root_locator: str) -> RawDocumentRecord | None:
        del root_locator
        if not self._root_spdx_path.name.endswith(".spdx.json"):
            return None
        stem = self._root_spdx_path.name[: -len(".spdx.json")]
        index_path = self._root_spdx_path.with_name(f"{stem}.spdx.index.json")
        if not index_path.is_file():
            return None
        raw = index_path.read_bytes()
        locator = self._rel_locator(index_path)
        digests = compute_digests(raw)
        document = parse_json_bytes(raw, locator)
        return RawDocumentRecord(
            locator=locator,
            raw_bytes=raw,
            sha1=digests["SHA1"],
            sha256=digests["SHA256"],
            size=len(raw),
            document=document,
        )

    def load_rootfs_digest(
        self, root_locator: str, explicit_rootfs: str | None
    ) -> tuple[BinaryArtifactDigest | None, BinaryArtifactDigest | None]:
        del root_locator
        if explicit_rootfs is not None:
            rootfs_path = Path(explicit_rootfs)
            require(rootfs_path.is_file(), f"missing rootfs file: {rootfs_path.name}")
            sha256, size = file_sha256_and_size(rootfs_path)
            return (
                BinaryArtifactDigest(
                    locator=self._rel_locator(rootfs_path), sha256=sha256, size=size
                ),
                None,
            )
        if not self._root_spdx_path.name.endswith(".spdx.json"):
            return None, None
        stem = self._root_spdx_path.name[: -len(".spdx.json")]
        ext4_path = self._root_spdx_path.with_name(f"{stem}.rootfs.ext4")
        if not ext4_path.is_file():
            return None, None
        sha256, size = file_sha256_and_size(ext4_path)
        ext4_digest = BinaryArtifactDigest(
            locator=self._rel_locator(ext4_path), sha256=sha256, size=size
        )
        tar_bz2_path = self._root_spdx_path.with_name(f"{stem}.rootfs.tar.bz2")
        tar_bz2_digest = None
        if tar_bz2_path.is_file():
            bz2_sha, bz2_size = file_sha256_and_size(tar_bz2_path)
            tar_bz2_digest = BinaryArtifactDigest(
                locator=self._rel_locator(tar_bz2_path), sha256=bz2_sha, size=bz2_size
            )
        return ext4_digest, tar_bz2_digest

    def load_manifest_text(
        self, root_locator: str, explicit_manifest: str | None
    ) -> tuple[str, BinaryArtifactDigest] | None:
        del root_locator
        if explicit_manifest is not None:
            manifest_path = Path(explicit_manifest)
            require(manifest_path.is_file(), f"missing manifest file: {manifest_path.name}")
        elif self._root_spdx_path.name.endswith(".spdx.json"):
            stem = self._root_spdx_path.name[: -len(".spdx.json")]
            manifest_path = self._root_spdx_path.with_name(f"{stem}.rootfs.manifest")
            if not manifest_path.is_file():
                return None
        else:
            return None
        raw = manifest_path.read_bytes()
        digests = compute_digests(raw)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise NormalizationError(f"invalid UTF-8 in manifest: {exc}") from exc
        return (
            text,
            BinaryArtifactDigest(
                locator=self._rel_locator(manifest_path),
                sha256=digests["SHA256"],
                size=len(raw),
            ),
        )


def parse_rootfs_manifest(text: str, locator: str) -> dict[str, dict[str, str]]:
    packages: dict[str, dict[str, str]] = {}
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        require(
            len(parts) == 3,
            f"malformed rootfs manifest line {line_no} in {locator}: {raw_line!r}",
        )
        name, arch, version = parts
        require(
            name not in packages,
            f"duplicate package {name!r} in rootfs manifest {locator}",
        )
        packages[name] = {"architecture": arch, "version": version}
    require(bool(packages), f"rootfs manifest {locator} contains zero installed packages")
    return packages


def validate_spdx_header(doc: dict[str, Any], locator: str) -> None:
    require(
        doc.get("spdxVersion") == "SPDX-2.2",
        f"unsupported spdxVersion in {locator}: {doc.get('spdxVersion')!r}",
    )
    require(
        doc.get("dataLicense") == "CC0-1.0",
        f"unexpected dataLicense in {locator}: {doc.get('dataLicense')!r}",
    )
    require(
        doc.get("SPDXID") == "SPDXRef-DOCUMENT",
        f"invalid document SPDXID in {locator}: {doc.get('SPDXID')!r}",
    )
    require(
        isinstance(doc.get("name"), str) and bool(doc["name"]),
        f"missing document name in {locator}",
    )
    require(
        isinstance(doc.get("documentNamespace"), str)
        and doc["documentNamespace"].startswith(("http://", "https://")),
        f"invalid documentNamespace in {locator}: {doc.get('documentNamespace')!r}",
    )
    creation = doc.get("creationInfo")
    require(
        isinstance(creation, dict)
        and isinstance(creation.get("created"), str)
        and bool(creation["created"])
        and isinstance(creation.get("creators"), list)
        and bool(creation["creators"]),
        f"invalid creationInfo in {locator}",
    )


def collect_document_elements(doc: dict[str, Any], locator: str) -> set[str]:
    elements: set[str] = {"SPDXRef-DOCUMENT"}
    file_ids: set[str] = set()

    for file_entry in doc.get("files", []):
        require(isinstance(file_entry, dict), f"invalid file entry in {locator}")
        spdxid = file_entry.get("SPDXID")
        require(
            isinstance(spdxid, str) and spdxid.startswith("SPDXRef-"),
            f"invalid file SPDXID in {locator}: {spdxid!r}",
        )
        require(spdxid not in elements, f"duplicate SPDXID {spdxid} in {locator}")
        require(
            isinstance(file_entry.get("fileName"), str) and bool(file_entry["fileName"]),
            f"missing fileName for {spdxid} in {locator}",
        )
        checksums = file_entry.get("checksums")
        require(
            isinstance(checksums, list) and bool(checksums),
            f"missing checksums for file {spdxid} in {locator}",
        )
        algorithms = {
            c.get("algorithm"): c.get("checksumValue")
            for c in checksums
            if isinstance(c, dict)
        }
        require(
            isinstance(algorithms.get("SHA1"), str)
            and re.fullmatch(r"[0-9a-f]{40}", algorithms["SHA1"]) is not None,
            f"missing or invalid SHA1 checksum for file {spdxid} in {locator}",
        )
        elements.add(spdxid)
        file_ids.add(spdxid)

    for pkg_entry in doc.get("packages", []):
        require(isinstance(pkg_entry, dict), f"invalid package entry in {locator}")
        spdxid = pkg_entry.get("SPDXID")
        require(
            isinstance(spdxid, str) and spdxid.startswith("SPDXRef-"),
            f"invalid package SPDXID in {locator}: {spdxid!r}",
        )
        require(spdxid not in elements, f"duplicate SPDXID {spdxid} in {locator}")
        require(
            isinstance(pkg_entry.get("name"), str) and bool(pkg_entry["name"]),
            f"missing package name for {spdxid} in {locator}",
        )
        for has_file_id in pkg_entry.get("hasFiles", []):
            require(
                isinstance(has_file_id, str) and has_file_id in file_ids,
                f"dangling hasFiles reference {has_file_id!r} on {spdxid} in {locator}",
            )
        elements.add(spdxid)

    for snippet in doc.get("snippets", []):
        require(isinstance(snippet, dict), f"invalid snippet entry in {locator}")
        spdxid = snippet.get("SPDXID")
        require(
            isinstance(spdxid, str) and spdxid.startswith("SPDXRef-"),
            f"invalid snippet SPDXID in {locator}: {spdxid!r}",
        )
        require(spdxid not in elements, f"duplicate SPDXID {spdxid} in {locator}")
        elements.add(spdxid)

    return elements


def validate_and_map_external_refs(
    doc: dict[str, Any], locator: str
) -> list[tuple[str, str, str, str]]:
    """Returns [(externalDocumentId, spdxDocument, algorithm, checksumValue), ...]."""
    refs = doc.get("externalDocumentRefs", [])
    require(isinstance(refs, list), f"externalDocumentRefs must be a list in {locator}")
    seen_ids: set[str] = set()
    parsed: list[tuple[str, str, str, str]] = []
    for entry in refs:
        require(isinstance(entry, dict), f"invalid externalDocumentRef in {locator}")
        ext_id = entry.get("externalDocumentId")
        target_ns = entry.get("spdxDocument")
        checksum = entry.get("checksum")
        require(
            isinstance(ext_id, str) and ext_id.startswith("DocumentRef-"),
            f"invalid externalDocumentId in {locator}: {ext_id!r}",
        )
        require(
            ext_id not in seen_ids,
            f"duplicate externalDocumentId {ext_id} in {locator}",
        )
        seen_ids.add(ext_id)
        require(
            isinstance(target_ns, str) and target_ns.startswith(("http://", "https://")),
            f"invalid spdxDocument URI for {ext_id} in {locator}: {target_ns!r}",
        )
        require(
            isinstance(checksum, dict),
            f"missing checksum object for {ext_id} in {locator}",
        )
        algorithm = checksum.get("algorithm")
        value = checksum.get("checksumValue")
        require(
            algorithm in SUPPORTED_CHECKSUM_ALGORITHMS,
            f"unsupported checksum algorithm {algorithm!r} for {ext_id} in {locator}",
        )
        _, hex_len = SUPPORTED_CHECKSUM_ALGORITHMS[algorithm]
        require(
            isinstance(value, str)
            and re.fullmatch(rf"[0-9a-f]{{{hex_len}}}", value) is not None,
            f"malformed {algorithm} checksumValue for {ext_id} in {locator}: {value!r}",
        )
        parsed.append((ext_id, target_ns, algorithm, value))
    return parsed


def normalize_package_external_ref(
    ref: dict[str, Any],
    *,
    document_locator: str,
    package_spdxid: str,
    rewrites_out: list[dict[str, str]],
) -> dict[str, Any]:
    require(
        isinstance(ref, dict),
        f"invalid externalRef on {package_spdxid} in {document_locator}",
    )
    category = ref.get("referenceCategory")
    ref_type = ref.get("referenceType")
    locator = ref.get("referenceLocator")
    require(
        isinstance(category, str) and bool(category),
        f"missing referenceCategory on {package_spdxid} in {document_locator}",
    )
    require(
        isinstance(ref_type, str) and bool(ref_type),
        f"missing referenceType on {package_spdxid} in {document_locator}",
    )
    require(
        isinstance(locator, str) and bool(locator),
        f"missing referenceLocator on {package_spdxid} in {document_locator}",
    )

    normalized = copy.deepcopy(ref)
    if ref_type == YOCTO_CPE23_URI:
        require(
            locator.startswith("cpe:2.3:"),
            f"invalid CPE 2.3 locator on {package_spdxid} in {document_locator}: {locator!r}",
        )
        normalized["referenceType"] = SPDX_CPE23_TYPE
        rewrites_out.append(
            {
                "document": document_locator,
                "package_spdxid": package_spdxid,
                "reference_locator": locator,
                "from_reference_type": YOCTO_CPE23_URI,
                "to_reference_type": SPDX_CPE23_TYPE,
            }
        )
    elif ref_type == SPDX_CPE23_TYPE:
        require(
            locator.startswith("cpe:2.3:"),
            f"invalid CPE 2.3 locator on {package_spdxid} in {document_locator}: {locator!r}",
        )
    elif ref_type == YOCTO_PURL_URI:
        require(
            locator.startswith("pkg:"),
            f"invalid PURL locator on {package_spdxid} in {document_locator}: {locator!r}",
        )
        normalized["referenceType"] = SPDX_PURL_TYPE
        rewrites_out.append(
            {
                "document": document_locator,
                "package_spdxid": package_spdxid,
                "reference_locator": locator,
                "from_reference_type": YOCTO_PURL_URI,
                "to_reference_type": SPDX_PURL_TYPE,
            }
        )
    elif ref_type == SPDX_PURL_TYPE:
        require(
            locator.startswith("pkg:"),
            f"invalid PURL locator on {package_spdxid} in {document_locator}: {locator!r}",
        )
    return normalized


def deduplicate_external_refs(refs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    result: list[dict[str, Any]] = []
    for ref in refs:
        key = (
            ref["referenceCategory"],
            ref["referenceType"],
            ref["referenceLocator"],
        )
        if key not in seen:
            seen.add(key)
            result.append(ref)
    return result


def resolve_endpoint(
    endpoint: str,
    *,
    current_ns: str,
    ext_map: dict[str, str],
    doc_elements: dict[str, set[str]],
    locator: str,
    allow_special: bool,
) -> tuple[str, str] | None:
    require(
        isinstance(endpoint, str) and bool(endpoint),
        f"empty relationship endpoint in {locator}",
    )
    if endpoint in SPECIAL_ELEMENTS:
        require(
            allow_special,
            f"special value {endpoint!r} is not allowed as spdxElementId in {locator}",
        )
        return None
    if ":" in endpoint:
        doc_ref, elem_ref = endpoint.split(":", 1)
        require(
            doc_ref in ext_map,
            f"dangling external DocumentRef {doc_ref!r} in {endpoint!r} ({locator})",
        )
        target_ns = ext_map[doc_ref]
        require(
            elem_ref in doc_elements[target_ns],
            f"dangling external SPDXRef {elem_ref!r} in {target_ns} referenced from {locator}",
        )
        return target_ns, elem_ref
    require(
        endpoint in doc_elements[current_ns],
        f"dangling local SPDXRef {endpoint!r} in {locator}",
    )
    return current_ns, endpoint


def normalize_from_store(
    store: SpdxDocumentStore,
    *,
    input_mode: str,
    deploy_tar_digest: BinaryArtifactDigest | None = None,
    root_spdx_locator: str | None = None,
    explicit_rootfs: str | None = None,
    explicit_rootfs_sha256: str | None = None,
    explicit_manifest: str | None = None,
    expected_package_count: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    root_record = store.load_root(root_spdx_locator)
    root_doc = root_record.document
    root_ns = root_doc["documentNamespace"]

    # 1. Full transitive BFS traversal of externalDocumentRefs with checksum verification.
    visited_records: dict[str, RawDocumentRecord] = {root_ns: root_record}
    doc_elements: dict[str, set[str]] = {}
    doc_ext_maps: dict[str, dict[str, str]] = {}
    queue: deque[str] = deque([root_ns])
    edge_count = 0

    while queue:
        cur_ns = queue.popleft()
        cur_record = visited_records[cur_ns]
        validate_spdx_header(cur_record.document, cur_record.locator)
        doc_elements[cur_ns] = collect_document_elements(
            cur_record.document, cur_record.locator
        )
        parsed_refs = validate_and_map_external_refs(
            cur_record.document, cur_record.locator
        )
        ext_map: dict[str, str] = {}
        for ext_id, target_ns, algorithm, expected_digest in parsed_refs:
            edge_count += 1
            target_record = store.resolve_namespace(target_ns)
            actual_digest = (
                target_record.sha1 if algorithm == "SHA1" else target_record.sha256
            )
            require(
                actual_digest == expected_digest,
                f"{algorithm} checksum mismatch for {ext_id} ({target_ns}) referenced from "
                f"{cur_record.locator}: expected {expected_digest}, got {actual_digest}",
            )
            ext_map[ext_id] = target_ns
            if target_ns not in visited_records:
                visited_records[target_ns] = target_record
                queue.append(target_ns)
        doc_ext_maps[cur_ns] = ext_map

    # 2. Validate every relationship endpoint across every traversed document.
    verified_relationship_count = 0
    for cur_ns, cur_record in visited_records.items():
        rels = cur_record.document.get("relationships", [])
        require(
            isinstance(rels, list),
            f"relationships must be a list in {cur_record.locator}",
        )
        ext_map = doc_ext_maps[cur_ns]
        for rel in rels:
            require(
                isinstance(rel, dict),
                f"invalid relationship object in {cur_record.locator}",
            )
            rel_type = rel.get("relationshipType")
            require(
                isinstance(rel_type, str) and bool(rel_type),
                f"missing relationshipType in {cur_record.locator}",
            )
            resolve_endpoint(
                rel.get("spdxElementId", ""),
                current_ns=cur_ns,
                ext_map=ext_map,
                doc_elements=doc_elements,
                locator=cur_record.locator,
                allow_special=False,
            )
            resolve_endpoint(
                rel.get("relatedSpdxElement", ""),
                current_ns=cur_ns,
                ext_map=ext_map,
                doc_elements=doc_elements,
                locator=cur_record.locator,
                allow_special=True,
            )
            verified_relationship_count += 1

    # 3. Cross-check optional .spdx.index.json when present.
    spdx_index_record = store.load_optional_spdx_index(root_record.locator)
    if spdx_index_record is not None:
        index_docs = spdx_index_record.document.get("documents")
        require(
            isinstance(index_docs, list) and bool(index_docs),
            f"invalid documents list in {spdx_index_record.locator}",
        )
        index_by_ns: dict[str, str] = {}
        for item in index_docs:
            require(
                isinstance(item, dict)
                and isinstance(item.get("documentNamespace"), str)
                and isinstance(item.get("sha1"), str),
                f"malformed entry in {spdx_index_record.locator}",
            )
            ns = item["documentNamespace"]
            require(
                ns not in index_by_ns,
                f"duplicate namespace {ns} in {spdx_index_record.locator}",
            )
            index_by_ns[ns] = item["sha1"]
        expected_index_ns = set(visited_records) - {root_ns}
        for ns, expected_sha1 in index_by_ns.items():
            rec = visited_records.get(ns) or store.resolve_namespace(ns)
            require(
                rec.sha1 == expected_sha1,
                f"spdx.index.json SHA1 mismatch for {ns}: expected {expected_sha1}, got {rec.sha1}",
            )
        require(
            expected_index_ns <= set(index_by_ns),
            f"spdx.index.json is missing traversed external documents: "
            f"{sorted(expected_index_ns - set(index_by_ns))}",
        )

    # 4. Identify root image package and optional rootfs / manifest bindings.
    root_packages = root_doc.get("packages", [])
    require(
        isinstance(root_packages, list) and len(root_packages) == 1,
        f"expected exactly 1 root image package in {root_record.locator}, found {len(root_packages)}",
    )
    orig_image_pkg = root_packages[0]
    orig_image_spdxid = orig_image_pkg["SPDXID"]
    orig_image_version = orig_image_pkg.get("versionInfo")
    require(
        isinstance(orig_image_version, str) and bool(orig_image_version),
        f"missing versionInfo on root image package {orig_image_spdxid} in {root_record.locator}",
    )

    rootfs_ext4_digest, rootfs_tar_bz2_digest = store.load_rootfs_digest(
        root_record.locator, explicit_rootfs
    )
    if explicit_rootfs_sha256 is not None:
        require(
            re.fullmatch(r"[0-9a-f]{64}", explicit_rootfs_sha256) is not None,
            f"invalid explicit rootfs SHA-256: {explicit_rootfs_sha256!r}",
        )
        if rootfs_ext4_digest is not None:
            require(
                rootfs_ext4_digest.sha256 == explicit_rootfs_sha256,
                f"rootfs SHA-256 mismatch for {rootfs_ext4_digest.locator}: "
                f"expected {explicit_rootfs_sha256}, got {rootfs_ext4_digest.sha256}",
            )
        else:
            rootfs_ext4_digest = BinaryArtifactDigest(
                locator="explicit-sha256", sha256=explicit_rootfs_sha256, size=0
            )

    manifest_loaded = store.load_manifest_text(root_record.locator, explicit_manifest)
    manifest_packages: dict[str, dict[str, str]] | None = None
    manifest_digest: BinaryArtifactDigest | None = None
    if manifest_loaded is not None:
        manifest_text, manifest_digest = manifest_loaded
        manifest_packages = parse_rootfs_manifest(
            manifest_text, manifest_digest.locator
        )

    # 5. Extract all installed binary packages from root CONTAINS relationships.
    root_ext_map = doc_ext_maps[root_ns]
    installed_targets: list[tuple[str, str]] = []
    runtime_doc_namespaces: set[str] = set()

    for rel in root_doc.get("relationships", []):
        if rel["spdxElementId"] != orig_image_spdxid:
            continue
        resolved = resolve_endpoint(
            rel["relatedSpdxElement"],
            current_ns=root_ns,
            ext_map=root_ext_map,
            doc_elements=doc_elements,
            locator=root_record.locator,
            allow_special=False,
        )
        assert resolved is not None
        target_ns, target_spdxid = resolved
        if rel["relationshipType"] == "CONTAINS":
            installed_targets.append((target_ns, target_spdxid))
        elif rel["relationshipType"] == "OTHER" and target_spdxid == "SPDXRef-DOCUMENT":
            runtime_doc_namespaces.add(target_ns)

    require(
        bool(installed_targets),
        f"root image {orig_image_spdxid} CONTAINS zero installed packages in {root_record.locator}",
    )
    if expected_package_count is not None:
        require(
            len(installed_targets) == expected_package_count,
            f"installed package count mismatch: expected {expected_package_count}, "
            f"found {len(installed_targets)}",
        )

    installed_pkg_ns_set: set[str] = set()
    installed_pkg_by_spdxid: dict[str, tuple[RawDocumentRecord, dict[str, Any]]] = {}
    installed_pkg_by_name: dict[str, str] = {}

    for pkg_ns, pkg_spdxid in installed_targets:
        require(
            pkg_spdxid not in installed_pkg_by_spdxid,
            f"duplicate installed package SPDXID in root CONTAINS: {pkg_spdxid}",
        )
        pkg_record = visited_records[pkg_ns]
        installed_pkg_ns_set.add(pkg_ns)
        matching_pkgs = [
            p
            for p in pkg_record.document.get("packages", [])
            if p["SPDXID"] == pkg_spdxid
        ]
        require(
            len(matching_pkgs) == 1,
            f"unable to locate unique package {pkg_spdxid} in {pkg_record.locator}",
        )
        pkg_obj = matching_pkgs[0]
        pkg_name = pkg_obj["name"]
        require(
            pkg_name not in installed_pkg_by_name,
            f"duplicate installed package name {pkg_name!r} in root CONTAINS",
        )
        require(
            isinstance(pkg_obj.get("versionInfo"), str) and bool(pkg_obj["versionInfo"]),
            f"missing versionInfo on installed package {pkg_spdxid} in {pkg_record.locator}",
        )
        installed_pkg_by_spdxid[pkg_spdxid] = (pkg_record, pkg_obj)
        installed_pkg_by_name[pkg_name] = pkg_spdxid

    if manifest_packages is not None:
        missing_in_spdx = sorted(set(manifest_packages) - set(installed_pkg_by_name))
        extra_in_spdx = sorted(set(installed_pkg_by_name) - set(manifest_packages))
        require(
            not missing_in_spdx and not extra_in_spdx,
            f"installed package set mismatch between root SPDX and rootfs.manifest: "
            f"missing_in_spdx={missing_in_spdx}, extra_in_spdx={extra_in_spdx}",
        )

    # 6. Trace each installed binary package to its GENERATED_FROM recipe and normalize externalRefs.
    cpe_rewrites: list[dict[str, str]] = []
    propagated_refs: list[dict[str, str]] = []
    traced_recipes_by_spdxid: dict[
        str, tuple[RawDocumentRecord, dict[str, Any], list[dict[str, Any]], list[str]]
    ] = {}
    traced_recipe_ns_set: set[str] = set()

    consolidated_binary_packages: list[dict[str, Any]] = []
    consolidated_files: list[dict[str, Any]] = []
    package_file_relationships: list[dict[str, str]] = []
    generated_from_relationships: list[dict[str, str]] = []
    installed_summary_rows: list[dict[str, Any]] = []
    global_spdxids: set[str] = {"SPDXRef-DOCUMENT"}

    root_source_spdxid = (
        f"SPDXRef-DocumentRoot-File-{sanitize_spdx_id_fragment(root_doc['name'])}"
    )
    global_spdxids.add(root_source_spdxid)

    for pkg_name in sorted(installed_pkg_by_name):
        pkg_spdxid = installed_pkg_by_name[pkg_name]
        pkg_record, pkg_obj = installed_pkg_by_spdxid[pkg_spdxid]
        pkg_ns = pkg_record.document["documentNamespace"]
        pkg_ext_map = doc_ext_maps[pkg_ns]

        require(
            pkg_spdxid not in global_spdxids,
            f"SPDXID collision on installed package {pkg_spdxid}",
        )
        global_spdxids.add(pkg_spdxid)

        pkg_files = pkg_record.document.get("files", [])
        file_map_local = {f["SPDXID"]: f for f in pkg_files}
        referenced_file_ids: set[str] = set(pkg_obj.get("hasFiles", []))
        for rel in pkg_record.document.get("relationships", []):
            if (
                rel["spdxElementId"] == pkg_spdxid
                and rel["relationshipType"] == "CONTAINS"
                and rel["relatedSpdxElement"] in file_map_local
            ):
                referenced_file_ids.add(rel["relatedSpdxElement"])

        for file_spdxid in sorted(referenced_file_ids):
            file_entry = file_map_local[file_spdxid]
            checksums_by_alg = {
                c["algorithm"]: c["checksumValue"]
                for c in file_entry.get("checksums", [])
            }
            require(
                isinstance(checksums_by_alg.get("SHA256"), str)
                and re.fullmatch(r"[0-9a-f]{64}", checksums_by_alg["SHA256"]) is not None,
                f"packaged file {file_spdxid} in {pkg_record.locator} lacks valid SHA256 checksum",
            )
            require(
                file_spdxid not in global_spdxids,
                f"SPDXID collision on packaged file {file_spdxid}",
            )
            global_spdxids.add(file_spdxid)
            consolidated_files.append(copy.deepcopy(file_entry))
            package_file_relationships.append(
                {
                    "spdxElementId": pkg_spdxid,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": file_spdxid,
                }
            )

        gen_targets: list[tuple[str, str]] = []
        for rel in pkg_record.document.get("relationships", []):
            if (
                rel["spdxElementId"] == pkg_spdxid
                and rel["relationshipType"] == "GENERATED_FROM"
            ):
                resolved = resolve_endpoint(
                    rel["relatedSpdxElement"],
                    current_ns=pkg_ns,
                    ext_map=pkg_ext_map,
                    doc_elements=doc_elements,
                    locator=pkg_record.locator,
                    allow_special=False,
                )
                assert resolved is not None
                gen_targets.append(resolved)

        require(
            len(gen_targets) == 1,
            f"expected exactly 1 GENERATED_FROM recipe for {pkg_spdxid} in {pkg_record.locator}, "
            f"found {len(gen_targets)}",
        )
        recipe_ns, recipe_spdxid = gen_targets[0]
        recipe_record = visited_records[recipe_ns]
        traced_recipe_ns_set.add(recipe_ns)

        if recipe_spdxid not in traced_recipes_by_spdxid:
            matching_recipes = [
                p
                for p in recipe_record.document.get("packages", [])
                if p["SPDXID"] == recipe_spdxid
            ]
            require(
                len(matching_recipes) == 1,
                f"unable to locate recipe package {recipe_spdxid} in {recipe_record.locator}",
            )
            recipe_obj = matching_recipes[0]
            require(
                isinstance(recipe_obj.get("versionInfo"), str)
                and bool(recipe_obj["versionInfo"]),
                f"missing versionInfo on recipe {recipe_spdxid} in {recipe_record.locator}",
            )
            normalized_recipe_refs = deduplicate_external_refs(
                [
                    normalize_package_external_ref(
                        ref,
                        document_locator=recipe_record.locator,
                        package_spdxid=recipe_spdxid,
                        rewrites_out=cpe_rewrites,
                    )
                    for ref in recipe_obj.get("externalRefs", [])
                ]
            )
            traced_recipes_by_spdxid[recipe_spdxid] = (
                recipe_record,
                recipe_obj,
                normalized_recipe_refs,
                [],
            )
        else:
            existing_rec_record, _, _, _ = traced_recipes_by_spdxid[recipe_spdxid]
            require(
                existing_rec_record.document["documentNamespace"] == recipe_ns,
                f"SPDXID collision across distinct recipe documents for {recipe_spdxid}",
            )

        recipe_record, recipe_obj, normalized_recipe_refs, recipe_bins = (
            traced_recipes_by_spdxid[recipe_spdxid]
        )
        recipe_bins.append(pkg_name)

        own_normalized_refs = [
            normalize_package_external_ref(
                ref,
                document_locator=pkg_record.locator,
                package_spdxid=pkg_spdxid,
                rewrites_out=cpe_rewrites,
            )
            for ref in pkg_obj.get("externalRefs", [])
        ]
        own_ref_keys = {
            (r["referenceCategory"], r["referenceType"], r["referenceLocator"])
            for r in own_normalized_refs
        }
        combined_refs = deduplicate_external_refs(
            [*own_normalized_refs, *copy.deepcopy(normalized_recipe_refs)]
        )
        for ref in normalized_recipe_refs:
            key = (
                ref["referenceCategory"],
                ref["referenceType"],
                ref["referenceLocator"],
            )
            if key not in own_ref_keys:
                propagated_refs.append(
                    {
                        "binary_package": pkg_name,
                        "binary_spdxid": pkg_spdxid,
                        "recipe_name": recipe_obj["name"],
                        "recipe_spdxid": recipe_spdxid,
                        "reference_category": ref["referenceCategory"],
                        "reference_type": ref["referenceType"],
                        "reference_locator": ref["referenceLocator"],
                    }
                )

        new_pkg = copy.deepcopy(pkg_obj)
        if combined_refs:
            new_pkg["externalRefs"] = combined_refs
        manifest_entry = (
            manifest_packages[pkg_name] if manifest_packages is not None else None
        )
        provenance_parts = [
            f"package_spdx_namespace={pkg_ns}",
            f"package_spdx_sha256={pkg_record.sha256}",
            f"recipe_spdxid={recipe_spdxid}",
            f"recipe_spdx_namespace={recipe_ns}",
            f"recipe_spdx_sha256={recipe_record.sha256}",
        ]
        if manifest_entry is not None:
            provenance_parts.append(
                f"manifest_arch={manifest_entry['architecture']}"
            )
            provenance_parts.append(
                f"manifest_version={manifest_entry['version']}"
            )
        new_pkg["sourceInfo"] = "; ".join(provenance_parts)
        consolidated_binary_packages.append(new_pkg)

        generated_from_relationships.append(
            {
                "spdxElementId": pkg_spdxid,
                "relationshipType": "GENERATED_FROM",
                "relatedSpdxElement": recipe_spdxid,
            }
        )

        installed_summary_rows.append(
            {
                "name": pkg_name,
                "spdxid": pkg_spdxid,
                "spdx_version": pkg_obj["versionInfo"],
                "manifest_version": (
                    manifest_entry["version"] if manifest_entry is not None else None
                ),
                "manifest_architecture": (
                    manifest_entry["architecture"]
                    if manifest_entry is not None
                    else None
                ),
                "package_document_path": pkg_record.locator,
                "package_document_namespace": pkg_ns,
                "package_document_sha256": pkg_record.sha256,
                "file_count": len(referenced_file_ids),
                "recipe_name": recipe_obj["name"],
                "recipe_spdxid": recipe_spdxid,
                "recipe_version": recipe_obj["versionInfo"],
                "recipe_document_path": recipe_record.locator,
                "recipe_document_namespace": recipe_ns,
                "recipe_document_sha256": recipe_record.sha256,
                "cpes": [
                    r["referenceLocator"]
                    for r in combined_refs
                    if r["referenceType"] == SPDX_CPE23_TYPE
                ],
                "purls": [
                    r["referenceLocator"]
                    for r in combined_refs
                    if r["referenceType"] == SPDX_PURL_TYPE
                ],
            }
        )

    # 7. Emit traced target recipe packages for complete SPDX GENERATED_FROM provenance.
    consolidated_recipe_packages: list[dict[str, Any]] = []
    recipe_cpe_mappings: list[dict[str, Any]] = []
    for recipe_spdxid in sorted(traced_recipes_by_spdxid):
        require(
            recipe_spdxid not in global_spdxids,
            f"SPDXID collision on recipe package {recipe_spdxid}",
        )
        global_spdxids.add(recipe_spdxid)
        recipe_record, recipe_obj, normalized_recipe_refs, recipe_bins = (
            traced_recipes_by_spdxid[recipe_spdxid]
        )
        new_recipe_pkg = copy.deepcopy(recipe_obj)
        if normalized_recipe_refs:
            new_recipe_pkg["externalRefs"] = copy.deepcopy(normalized_recipe_refs)
        consolidated_recipe_packages.append(new_recipe_pkg)
        recipe_cpe_mappings.append(
            {
                "recipe_name": recipe_obj["name"],
                "recipe_spdxid": recipe_spdxid,
                "recipe_version": recipe_obj["versionInfo"],
                "recipe_document_path": recipe_record.locator,
                "recipe_document_namespace": recipe_record.document[
                    "documentNamespace"
                ],
                "recipe_document_sha256": recipe_record.sha256,
                "installed_binary_packages": sorted(recipe_bins),
                "raw_external_refs": copy.deepcopy(recipe_obj.get("externalRefs", [])),
                "normalized_cpes": [
                    r["referenceLocator"]
                    for r in normalized_recipe_refs
                    if r["referenceType"] == SPDX_CPE23_TYPE
                ],
                "preserved_purls": [
                    r["referenceLocator"]
                    for r in normalized_recipe_refs
                    if r["referenceType"] == SPDX_PURL_TYPE
                ],
            }
        )

    # 8. Resolve intra-image RUNTIME_DEPENDENCY_OF relationships from runtime-*.spdx.json docs.
    runtime_dep_edges: set[tuple[str, str]] = set()
    for rt_ns in sorted(runtime_doc_namespaces):
        rt_record = visited_records[rt_ns]
        rt_ext_map = doc_ext_maps[rt_ns]
        for rel in rt_record.document.get("relationships", []):
            if rel["relationshipType"] == "AMENDS":
                continue
            if rel["relationshipType"] == "RUNTIME_DEPENDENCY_OF":
                left = resolve_endpoint(
                    rel["spdxElementId"],
                    current_ns=rt_ns,
                    ext_map=rt_ext_map,
                    doc_elements=doc_elements,
                    locator=rt_record.locator,
                    allow_special=False,
                )
                right = resolve_endpoint(
                    rel["relatedSpdxElement"],
                    current_ns=rt_ns,
                    ext_map=rt_ext_map,
                    doc_elements=doc_elements,
                    locator=rt_record.locator,
                    allow_special=False,
                )
                assert left is not None and right is not None
                dep_ns, dep_spdxid = left
                pkg_ns, pkg_spdxid = right
                require(
                    dep_spdxid in installed_pkg_by_spdxid
                    and installed_pkg_by_spdxid[dep_spdxid][0].document[
                        "documentNamespace"
                    ]
                    == dep_ns,
                    f"runtime dependency {dep_spdxid} ({dep_ns}) referenced in "
                    f"{rt_record.locator} is missing from installed image packages",
                )
                require(
                    pkg_spdxid in installed_pkg_by_spdxid
                    and installed_pkg_by_spdxid[pkg_spdxid][0].document[
                        "documentNamespace"
                    ]
                    == pkg_ns,
                    f"runtime dependent {pkg_spdxid} ({pkg_ns}) referenced in "
                    f"{rt_record.locator} is missing from installed image packages",
                )
                runtime_dep_edges.add((dep_spdxid, pkg_spdxid))

    runtime_relationships = [
        {
            "spdxElementId": dep_id,
            "relationshipType": "RUNTIME_DEPENDENCY_OF",
            "relatedSpdxElement": pkg_id,
        }
        for dep_id, pkg_id in sorted(runtime_dep_edges)
    ]

    # 9. Preserve any extracted licensing infos used by included documents.
    included_namespaces = (
        {root_ns} | installed_pkg_ns_set | traced_recipe_ns_set
    )
    extracted_licenses: dict[str, dict[str, Any]] = {}
    for ns in sorted(included_namespaces):
        rec = visited_records[ns]
        for lic in rec.document.get("hasExtractedLicensingInfos", []):
            require(
                isinstance(lic, dict) and isinstance(lic.get("licenseId"), str),
                f"invalid hasExtractedLicensingInfos entry in {rec.locator}",
            )
            lic_id = lic["licenseId"]
            prev = extracted_licenses.get(lic_id)
            if prev is not None:
                require(
                    prev == lic,
                    f"conflicting extracted license definition for {lic_id} in {rec.locator}",
                )
            else:
                extracted_licenses[lic_id] = copy.deepcopy(lic)

    # 10. Construct root DESCRIBES image source package bound to exact artifact SHA-256.
    if rootfs_ext4_digest is not None:
        bound_root_version = f"{orig_image_version}-sha256.{rootfs_ext4_digest.sha256}"
    else:
        bound_root_version = orig_image_version

    root_source_pkg: dict[str, Any] = {
        "SPDXID": root_source_spdxid,
        "name": root_doc["name"],
        "versionInfo": bound_root_version,
        "downloadLocation": orig_image_pkg.get("downloadLocation", "NOASSERTION"),
        "licenseConcluded": orig_image_pkg.get("licenseConcluded", "NOASSERTION"),
        "licenseDeclared": orig_image_pkg.get("licenseDeclared", "NOASSERTION"),
        "licenseInfoFromFiles": copy.deepcopy(
            orig_image_pkg.get("licenseInfoFromFiles", ["NOASSERTION"])
        ),
        "copyrightText": orig_image_pkg.get("copyrightText", "NOASSERTION"),
        "supplier": orig_image_pkg.get("supplier", "NOASSERTION"),
    }
    root_source_info = [
        f"original_root_spdxid={orig_image_spdxid}",
        f"original_image_recipe_name={orig_image_pkg['name']}",
        f"original_document_namespace={root_ns}",
        f"original_root_spdx_sha256={root_record.sha256}",
    ]
    if rootfs_ext4_digest is not None:
        root_source_pkg["checksums"] = [
            {"algorithm": "SHA256", "checksumValue": rootfs_ext4_digest.sha256}
        ]
        root_source_info.append(
            f"rootfs_ext4_name={posixpath.basename(rootfs_ext4_digest.locator)}"
        )
        root_source_info.append(f"rootfs_ext4_sha256={rootfs_ext4_digest.sha256}")
    if rootfs_tar_bz2_digest is not None:
        root_source_info.append(
            f"rootfs_tar_bz2_name={posixpath.basename(rootfs_tar_bz2_digest.locator)}"
        )
        root_source_info.append(
            f"rootfs_tar_bz2_sha256={rootfs_tar_bz2_digest.sha256}"
        )
    root_source_pkg["sourceInfo"] = "; ".join(root_source_info)

    root_contains_relationships = [
        {
            "spdxElementId": root_source_spdxid,
            "relationshipType": "CONTAINS",
            "relatedSpdxElement": installed_pkg_by_name[pkg_name],
        }
        for pkg_name in sorted(installed_pkg_by_name)
    ]

    all_relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_source_spdxid,
        },
        *root_contains_relationships,
        *sorted(
            package_file_relationships,
            key=lambda r: (r["spdxElementId"], r["relatedSpdxElement"]),
        ),
        *sorted(
            generated_from_relationships,
            key=lambda r: (r["spdxElementId"], r["relatedSpdxElement"]),
        ),
        *runtime_relationships,
    ]

    consolidated_ns = f"{root_ns.rstrip('/')}/consolidated-v1"
    creation_info = copy.deepcopy(root_doc["creationInfo"])
    creators = list(creation_info.get("creators", []))
    tool_creator = f"Tool: {TOOL_PATH}"
    if tool_creator not in creators:
        creators.append(tool_creator)
    creation_info["creators"] = creators
    creation_info["comment"] = (
        f"Consolidated from Yocto SPDX root document {root_ns} "
        f"(sha256:{root_record.sha256}); {len(visited_records)} graph documents verified."
    )

    consolidated_doc: dict[str, Any] = {
        "spdxVersion": "SPDX-2.2",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": root_doc["name"],
        "documentNamespace": consolidated_ns,
        "documentDescribes": [root_source_spdxid],
        "creationInfo": creation_info,
        "packages": [
            root_source_pkg,
            *consolidated_binary_packages,
            *consolidated_recipe_packages,
        ],
        "files": sorted(consolidated_files, key=lambda f: f["SPDXID"]),
        "relationships": all_relationships,
    }
    if extracted_licenses:
        consolidated_doc["hasExtractedLicensingInfos"] = [
            extracted_licenses[k] for k in sorted(extracted_licenses)
        ]

    consolidated_bytes = (
        json.dumps(consolidated_doc, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    consolidated_sha256 = hashlib.sha256(consolidated_bytes).hexdigest()

    # 11. Classify all traversed documents for the audit manifest.
    role_counts = {
        "root_image": 0,
        "installed_package": 0,
        "runtime_dependency": 0,
        "recipe_target_traced": 0,
        "recipe_build_only_excluded": 0,
    }
    traversed_manifest_rows: list[dict[str, Any]] = []
    for ns, rec in sorted(
        visited_records.items(), key=lambda item: (item[1].locator, item[0])
    ):
        if ns == root_ns:
            role = "root_image"
            included = True
        elif ns in installed_pkg_ns_set:
            role = "installed_package"
            included = True
        elif ns in runtime_doc_namespaces:
            role = "runtime_dependency"
            included = True
        elif ns in traced_recipe_ns_set:
            role = "recipe_target_traced"
            included = True
        else:
            role = "recipe_build_only_excluded"
            included = False
        role_counts[role] += 1
        traversed_manifest_rows.append(
            {
                "path": rec.locator,
                "name": rec.document["name"],
                "document_namespace": ns,
                "role": role,
                "included_in_consolidated_sbom": included,
                "size": rec.size,
                "sha1": rec.sha1,
                "sha256": rec.sha256,
            }
        )

    openvex_product_purl = (
        f"pkg:generic/{root_doc['name'].lower()}@{bound_root_version}"
    )

    normalization_manifest: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "tool": TOOL_PATH,
        "input": {
            "mode": input_mode,
            "deploy_tar": (
                {
                    "sha256": deploy_tar_digest.sha256,
                    "size": deploy_tar_digest.size,
                }
                if deploy_tar_digest is not None
                else None
            ),
            "root_spdx": {
                "path": root_record.locator,
                "name": root_doc["name"],
                "document_namespace": root_ns,
                "original_image_spdxid": orig_image_spdxid,
                "original_image_recipe_name": orig_image_pkg["name"],
                "original_image_version": orig_image_version,
                "size": root_record.size,
                "sha1": root_record.sha1,
                "sha256": root_record.sha256,
            },
            "spdx_index": (
                {
                    "path": spdx_index_record.locator,
                    "size": spdx_index_record.size,
                    "sha256": spdx_index_record.sha256,
                    "document_count": len(spdx_index_record.document["documents"]),
                }
                if spdx_index_record is not None
                else None
            ),
            "rootfs_ext4": (
                {
                    "path": rootfs_ext4_digest.locator,
                    "size": rootfs_ext4_digest.size,
                    "sha256": rootfs_ext4_digest.sha256,
                }
                if rootfs_ext4_digest is not None
                else None
            ),
            "rootfs_tar_bz2": (
                {
                    "path": rootfs_tar_bz2_digest.locator,
                    "size": rootfs_tar_bz2_digest.size,
                    "sha256": rootfs_tar_bz2_digest.sha256,
                }
                if rootfs_tar_bz2_digest is not None
                else None
            ),
            "rootfs_manifest": (
                {
                    "path": manifest_digest.locator,
                    "size": manifest_digest.size,
                    "sha256": manifest_digest.sha256,
                    "package_count": len(manifest_packages or {}),
                }
                if manifest_digest is not None
                else None
            ),
        },
        "graph": {
            "traversed_document_count": len(visited_records),
            "external_document_ref_edge_count": edge_count,
            "verified_relationship_count": verified_relationship_count,
            "document_counts_by_role": role_counts,
            "traversed_documents": traversed_manifest_rows,
        },
        "output": {
            "consolidated_spdx_sha256": consolidated_sha256,
            "consolidated_spdx_size": len(consolidated_bytes),
            "consolidated_document_namespace": consolidated_ns,
            "root_source_package": {
                "spdxid": root_source_spdxid,
                "name": root_doc["name"],
                "version": bound_root_version,
                "rootfs_sha256": (
                    rootfs_ext4_digest.sha256
                    if rootfs_ext4_digest is not None
                    else None
                ),
                "grype_openvex_product_purl": openvex_product_purl,
            },
            "installed_package_count": len(installed_summary_rows),
            "traced_target_recipe_count": len(recipe_cpe_mappings),
            "packaged_file_count": len(consolidated_files),
            "runtime_dependency_relationship_count": len(runtime_relationships),
        },
        "installed_packages": installed_summary_rows,
        "recipe_cpe_mappings": recipe_cpe_mappings,
        "normalizations_applied": {
            "reference_type_rewrites_count": len(cpe_rewrites),
            "reference_type_rewrites": cpe_rewrites,
            "recipe_external_ref_propagations_count": len(propagated_refs),
            "recipe_external_ref_propagations": propagated_refs,
            "root_describes_source_binding": {
                "from_spdxid": orig_image_spdxid,
                "to_spdxid": root_source_spdxid,
                "from_version": orig_image_version,
                "to_version": bound_root_version,
                "describes_relationship_added": True,
                "rootfs_sha256_checksum_attached": rootfs_ext4_digest is not None,
            },
            "build_only_recipes_excluded_from_target_sbom_count": role_counts[
                "recipe_build_only_excluded"
            ],
        },
    }
    return consolidated_bytes, normalization_manifest


def normalize_image_spdx(
    *,
    deploy_tar: Path | None = None,
    spdx_root: Path | None = None,
    spdx_dirs: list[Path] | None = None,
    root_spdx_member: str | None = None,
    rootfs: str | None = None,
    rootfs_sha256: str | None = None,
    manifest: str | None = None,
    expected_deploy_tar_sha256: str | None = None,
    expected_package_count: int | None = None,
) -> tuple[bytes, dict[str, Any]]:
    require(
        (deploy_tar is not None) ^ (spdx_root is not None),
        "specify exactly one of deploy_tar or spdx_root",
    )
    if deploy_tar is not None:
        require(deploy_tar.is_file(), f"missing deploy.tar: {deploy_tar.name}")
        tar_sha, tar_size = file_sha256_and_size(deploy_tar)
        if expected_deploy_tar_sha256 is not None:
            require(
                re.fullmatch(r"[0-9a-f]{64}", expected_deploy_tar_sha256) is not None,
                "expected_deploy_tar_sha256 must be 64 lowercase hex characters",
            )
            require(
                tar_sha == expected_deploy_tar_sha256,
                f"deploy.tar SHA-256 mismatch: expected {expected_deploy_tar_sha256}, got {tar_sha}",
            )
        tar_digest = BinaryArtifactDigest(
            locator=deploy_tar.name, sha256=tar_sha, size=tar_size
        )
        with tarfile.open(deploy_tar, mode="r:") as archive:
            store = TarDeployStore(archive)
            return normalize_from_store(
                store,
                input_mode="deploy_tar",
                deploy_tar_digest=tar_digest,
                root_spdx_locator=root_spdx_member,
                explicit_rootfs=rootfs,
                explicit_rootfs_sha256=rootfs_sha256,
                explicit_manifest=manifest,
                expected_package_count=expected_package_count,
            )

    assert spdx_root is not None
    search_dirs = list(spdx_dirs) if spdx_dirs else [spdx_root.parent]
    store = DirectorySpdxStore(spdx_root, search_dirs)
    return normalize_from_store(
        store,
        input_mode="spdx_directory",
        deploy_tar_digest=None,
        root_spdx_locator=None,
        explicit_rootfs=rootfs,
        explicit_rootfs_sha256=rootfs_sha256,
        explicit_manifest=manifest,
        expected_package_count=expected_package_count,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Traverse and verify a Yocto SPDX 2.2 external-document graph from deploy.tar "
            "or a Linux SPDX directory, emitting a consolidated Syft/Grype SPDX 2.2 SBOM "
            "and a machine-readable audit manifest."
        )
    )
    source_group = parser.add_mutually_exclusive_group(required=True)
    source_group.add_argument(
        "--deploy-tar",
        type=Path,
        help="Read-only canonical Yocto deploy.tar archive.",
    )
    source_group.add_argument(
        "--spdx-root",
        type=Path,
        help="Root image .spdx.json file in a Linux SPDX directory.",
    )
    parser.add_argument(
        "--spdx-dir",
        type=Path,
        action="append",
        default=[],
        help="Directory containing referenced Yocto SPDX documents (repeatable).",
    )
    parser.add_argument(
        "--root-spdx-member",
        help="Explicit root image .spdx.json member path inside --deploy-tar.",
    )
    parser.add_argument(
        "--rootfs",
        help="Explicit rootfs image path (filesystem path or --deploy-tar member).",
    )
    parser.add_argument(
        "--rootfs-sha256",
        help="Expected or explicit 64-hex SHA-256 of the rootfs image payload.",
    )
    parser.add_argument(
        "--manifest",
        help="Explicit .rootfs.manifest path (filesystem path or --deploy-tar member).",
    )
    parser.add_argument(
        "--expected-deploy-tar-sha256",
        help="Require --deploy-tar to match this exact 64-hex SHA-256.",
    )
    parser.add_argument(
        "--expected-package-count",
        type=int,
        help="Require exact installed binary package count (for example, 39).",
    )
    parser.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output path for the consolidated SPDX 2.2 JSON SBOM.",
    )
    parser.add_argument(
        "--manifest-out",
        type=Path,
        required=True,
        help="Output path for the machine-readable normalization audit JSON.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        consolidated_bytes, audit_manifest = normalize_image_spdx(
            deploy_tar=args.deploy_tar,
            spdx_root=args.spdx_root,
            spdx_dirs=args.spdx_dir or None,
            root_spdx_member=args.root_spdx_member,
            rootfs=args.rootfs,
            rootfs_sha256=args.rootfs_sha256,
            manifest=args.manifest,
            expected_deploy_tar_sha256=args.expected_deploy_tar_sha256,
            expected_package_count=args.expected_package_count,
        )
    except NormalizationError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest_out.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(consolidated_bytes)
    manifest_bytes = (
        json.dumps(audit_manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    args.manifest_out.write_bytes(manifest_bytes)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
