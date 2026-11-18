#!/usr/bin/env python3
"""Check frozen release assets and verify their exact GitHub OIDC identity."""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath


REPOSITORY = "firmdura/meta-firmdura-kirkstone"
SOURCE_REPOSITORY = f"https://github.com/{REPOSITORY}"
IDENTITY = f"{SOURCE_REPOSITORY}/.github/workflows/release.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
COSIGN_VERSION = "v3.1.4"
MANIFEST = "manifest.json"
BUNDLE = "manifest.sigstore.json"
MAX_METADATA_SIZE = 1024 * 1024


class InvalidRelease(ValueError):
    """An asset or identity does not satisfy the release contract."""


def require(condition, message):
    if not condition:
        raise InvalidRelease(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def fields(value, required, optional=()):
    require(type(value) is dict, "expected a JSON object")
    require(set(required) <= value.keys() <= set(required) | set(optional),
            f"unexpected or missing fields: {sorted(value)}")


def normalized_path(value):
    require(type(value) is str and 0 < len(value) <= 240, "invalid asset path")
    for part in value.split("/"):
        require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", part) is not None
                and not part.endswith("."), f"non-normalized asset path: {value!r}")
        require(part.split(".")[0].upper() not in {
            "CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(1, 10)],
            *[f"LPT{i}" for i in range(1, 10)],
        }, f"non-portable asset path: {value!r}")
    return value


def path_set(paths):
    files = set()
    directories = set()
    folded = {}
    for path in paths:
        normalized_path(path)
        require(path not in files, f"duplicate asset path: {path}")
        files.add(path)
        components = PurePosixPath(path).parts
        for index in range(1, len(components) + 1):
            prefix = "/".join(components[:index])
            previous = folded.setdefault(prefix.casefold(), prefix)
            require(previous == prefix, f"case-colliding asset paths: {previous}, {prefix}")
            if index < len(components):
                directories.add(prefix)
    require(not files & directories, "asset path is both a file and a directory")
    return files, directories


def load_manifest(raw, *, manifest_sha256, kind, release_id, source_commit):
    require(re.fullmatch(r"[0-9a-f]{64}", manifest_sha256) is not None,
            "approved manifest SHA-256 must be 64 lowercase hex characters")
    require(digest(raw) == manifest_sha256, "approved manifest SHA-256 mismatch")
    require(len(raw) <= MAX_METADATA_SIZE, "manifest is too large")
    document = json.loads(raw, object_pairs_hook=unique_object)
    fields(document, {"schema_version", "release", "source", "artifacts"})
    require(type(document["schema_version"]) is int and document["schema_version"] == 1,
            "unsupported manifest schema_version")
    fields(document["release"], {"kind", "id"})
    release = document["release"]
    require(release["kind"] in ("fixture", "release") and release["kind"] == kind,
            "release kind mismatch (fixture is not release evidence)")
    require(type(release["id"]) is str
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release["id"]) is not None
            and release["id"] == release_id, "release id mismatch or invalid id")
    fields(document["source"], {"repository", "commit"})
    source = document["source"]
    require(source["repository"] == SOURCE_REPOSITORY, "source repository mismatch")
    require(type(source["commit"]) is str
            and re.fullmatch(r"[0-9a-f]{40}", source["commit"]) is not None
            and source["commit"] == source_commit, "source commit mismatch")
    artifacts = document["artifacts"]
    require(type(artifacts) is list and 0 < len(artifacts) <= 10000,
            "artifacts must be a nonempty bounded array")
    for entry in artifacts:
        fields(entry, {"path", "role", "size", "sha256"}, {"variant"})
        normalized_path(entry["path"])
        require(kind != "release" or "/" not in entry["path"],
                "GitHub release payloads must use flat asset filenames")
        require(entry["path"] not in (MANIFEST, BUNDLE), "manifest/bundle cannot list itself")
        require(type(entry["role"]) is str
                and re.fullmatch(r"[a-z][a-z0-9-]{0,63}", entry["role"]) is not None,
                "invalid artifact role")
        require("variant" not in entry or entry["variant"] in ("baseline", "patched"),
                "variant must be baseline or patched; omit it for shared payloads")
        require(type(entry["size"]) is int and entry["size"] >= 0, "invalid artifact size")
        require(type(entry["sha256"]) is str
                and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
                "invalid artifact SHA-256")
    path_set([MANIFEST, BUNDLE, *[entry["path"] for entry in artifacts]])
    return document


def inventory(root):
    require(root.is_dir() and not root.is_symlink(), "asset root must be a real directory")
    files = set()
    directories = set()

    def fail(error):
        raise error

    for parent, dirnames, filenames in os.walk(root, followlinks=False, onerror=fail):
        for name in dirnames + filenames:
            path = Path(parent) / name
            relative = path.relative_to(root).as_posix()
            normalized_path(relative)
            mode = path.lstat().st_mode
            if stat.S_ISDIR(mode):
                directories.add(relative)
            else:
                require(stat.S_ISREG(mode), f"non-regular asset (including symlink): {relative}")
                files.add(relative)
    path_set(files)
    return files, directories


def inspect_assets(root, *, signed, **expected):
    files, directories = inventory(root)
    require(MANIFEST in files, "missing manifest")
    manifest = root / MANIFEST
    require(manifest.stat().st_size <= MAX_METADATA_SIZE, "manifest is too large")
    document = load_manifest(manifest.read_bytes(), **expected)
    names = [MANIFEST, *[entry["path"] for entry in document["artifacts"]]]
    if signed:
        names.append(BUNDLE)
    expected_files, expected_directories = path_set(names)
    require(files == expected_files,
            f"asset set mismatch: missing={sorted(expected_files - files)}, "
            f"extra={sorted(files - expected_files)}")
    require(directories == expected_directories, "unsigned or missing asset directories")
    if signed:
        require(0 < (root / BUNDLE).stat().st_size <= MAX_METADATA_SIZE, "invalid bundle size")
    return document


def check_assets(root, *, signed, **expected):
    document = inspect_assets(root, signed=signed, **expected)
    for entry in document["artifacts"]:
        path = root / entry["path"]
        require(path.stat().st_size == entry["size"], f"payload size mismatch: {entry['path']}")
        require(file_digest(path) == entry["sha256"], f"payload SHA-256 mismatch: {entry['path']}")
    return document


def cosign_version(cosign):
    result = subprocess.run([cosign, "version", "--json"], check=True, capture_output=True, text=True)
    require(json.loads(result.stdout)["gitVersion"] == COSIGN_VERSION,
            f"Cosign {COSIGN_VERSION} is required")


def verification_command(cosign, root):
    return [
        cosign, "verify-blob", "--bundle", str(root / BUNDLE),
        "--certificate-identity", IDENTITY,
        "--certificate-oidc-issuer", ISSUER, str(root / MANIFEST),
    ]


def verify_assets(root, cosign="cosign", **expected):
    inspect_assets(root, signed=True, **expected)
    cosign_version(cosign)
    subprocess.run(verification_command(cosign, root), check=True)
    # Verify the same frozen tree after the subprocess, not a regenerated manifest.
    return check_assets(root, signed=True, **expected)


def release_snapshot(release_id):
    require(re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", release_id) is not None,
            "invalid release id")
    release = subprocess.run(
        ["gh", "api", f"repos/{REPOSITORY}/releases/tags/{release_id}"],
        check=True, capture_output=True, text=True)
    release_data = json.loads(release.stdout)
    require(release_data["tag_name"] == release_id and release_data["draft"] is False,
            "expected a published release with the exact tag")
    pages = subprocess.run(
        ["gh", "api", "--paginate", "--slurp",
         f"repos/{REPOSITORY}/releases/{release_data['id']}/assets?per_page=100"],
        check=True, capture_output=True, text=True)
    assets = [asset for page in json.loads(pages.stdout) for asset in page]
    names = [asset["name"] for asset in assets]
    path_set(names)
    require(0 < len(names) <= 10002 and all("/" not in name for name in names),
            "GitHub release assets must have unique flat filenames")
    return {
        "release_id": release_data["id"],
        "assets": {asset["name"]: {key: asset.get(key) for key in
                   ("id", "size", "updated_at", "digest")} for asset in assets},
    }


def verify_github_release(root, cosign="cosign", **expected):
    require(not root.exists() and not root.is_symlink(), "download destination must not exist")
    require(expected["kind"] == "release", "GitHub release verification does not accept fixtures")
    before = release_snapshot(expected["release_id"])
    subprocess.run([
        "gh", "release", "download", expected["release_id"], "--repo", REPOSITORY,
        "--dir", str(root),
    ], check=True)
    files, directories = inventory(root)
    require(files == set(before["assets"]) and not directories,
            "download does not match the complete GitHub asset set")
    for name, metadata in before["assets"].items():
        require((root / name).stat().st_size == metadata["size"],
                f"GitHub asset size mismatch: {name}")
    document = verify_assets(root, cosign, **expected)
    require(release_snapshot(expected["release_id"]) == before,
            "GitHub release asset set changed during verification")
    return document


def unpack(archive, root, **expected):
    require(not root.exists() and not root.is_symlink(), "unpack destination must not already exist")
    with zipfile.ZipFile(archive) as source:
        entries = {}
        directories = set()
        for info in source.infolist():
            require(info.orig_filename == info.filename, "ZIP filename was normalized by the reader")
            name = info.filename[:-1] if info.is_dir() else info.filename
            normalized_path(name)
            require(name not in entries and name not in directories, f"duplicate ZIP member: {name}")
            mode = info.external_attr >> 16
            require(stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR),
                    f"non-regular ZIP member: {name}")
            require(not info.flag_bits & 1, "encrypted ZIP members are not supported")
            if info.is_dir():
                require(stat.S_IFMT(mode) in (0, stat.S_IFDIR), "ZIP directory type/name mismatch")
                require(info.file_size == 0, "ZIP directory has content")
                directories.add(name)
            else:
                require(not stat.S_ISDIR(mode), "ZIP member type/name mismatch")
                entries[name] = info
        require(MANIFEST in entries, "ZIP is missing manifest")
        require(entries[MANIFEST].file_size <= MAX_METADATA_SIZE, "manifest is too large")
        document = load_manifest(source.read(entries[MANIFEST]), **expected)
        files, required_directories = path_set(
            [MANIFEST, *[entry["path"] for entry in document["artifacts"]]])
        require(set(entries) == files, "ZIP asset set mismatch")
        require(directories <= required_directories, "unsigned ZIP directories")
        for entry in document["artifacts"]:
            require(entries[entry["path"]].file_size == entry["size"],
                    f"ZIP payload size mismatch: {entry['path']}")
        root.mkdir(parents=True)
        for name, info in entries.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            with source.open(info) as incoming, path.open("xb") as outgoing:
                while chunk := incoming.read(1024 * 1024):
                    outgoing.write(chunk)
    return check_assets(root, signed=False, **expected)


def expectation_arguments(parser):
    parser.add_argument("--manifest-sha256", required=True,
                        help="independently reviewed digest, not calculated from untrusted input")
    parser.add_argument("--kind", choices=("release", "fixture"), default="release")
    parser.add_argument("--release-id", required=True)
    parser.add_argument("--source-commit", required=True)


def expected_from(args):
    return {key: getattr(args, key)
            for key in ("manifest_sha256", "kind", "release_id", "source_commit")}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "verify", "unpack", "github-release"):
        command = commands.add_parser(name)
        command.add_argument("--assets", required=True, type=Path)
        expectation_arguments(command)
        if name in ("verify", "github-release"):
            command.add_argument("--cosign", default="cosign")
        if name == "unpack":
            command.add_argument("--archive", required=True, type=Path)
    args = parser.parse_args()
    expected = expected_from(args)
    try:
        if args.command == "verify":
            document = verify_assets(args.assets, args.cosign, **expected)
        elif args.command == "github-release":
            document = verify_github_release(args.assets, args.cosign, **expected)
        elif args.command == "unpack":
            document = unpack(args.archive, args.assets, **expected)
        else:
            document = check_assets(args.assets, signed=False, **expected)
    except (InvalidRelease, OSError, json.JSONDecodeError, UnicodeDecodeError, zipfile.BadZipFile,
            subprocess.CalledProcessError) as error:
        print(f"release verification failed: {error}", file=sys.stderr)
        return 1
    authenticated = args.command in ("verify", "github-release")
    print(json.dumps({
        "status": "verified" if authenticated else "payloads-checked-no-signature",
        "release": document["release"], "source": document["source"],
        "manifest_sha256": expected["manifest_sha256"], "payload_count": len(document["artifacts"]),
        "certificate_identity": IDENTITY if authenticated else None,
        "certificate_oidc_issuer": ISSUER if authenticated else None,
        "bundle_sha256": file_digest(args.assets / BUNDLE) if authenticated else None,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
