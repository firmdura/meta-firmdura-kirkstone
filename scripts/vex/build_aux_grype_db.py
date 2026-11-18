#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Build an isolated, explicitly labelled test-only Grype v6 SQLite CPE fixture DB for CVE-2026-19773."""

import argparse
import hashlib
import json
import shutil
import sqlite3
import struct
import subprocess
import tempfile
from pathlib import Path

P1 = 0x9E3779B185EBCA87
P2 = 0xC2B2AE3D27D4EB4F
P3 = 0x165667B19E3779F9
P4 = 0x85EBCA77C2B2AE63
P5 = 0x27D4EB2F165667C5
M64 = 0xFFFFFFFFFFFFFFFF

XXH64_C = r"""
#include <stdint.h>
#include <stdio.h>
static inline uint64_t rotl(uint64_t x, int r) { return (x << r) | (x >> (64 - r)); }
static inline uint64_t rnd(uint64_t acc, uint64_t in) {
    return rotl(acc + in * 0xC2B2AE3D27D4EB4FULL, 31) * 0x9E3779B185EBCA87ULL;
}
static inline uint64_t mrg(uint64_t acc, uint64_t val) {
    return (acc ^ rnd(0, val)) * 0x9E3779B185EBCA87ULL + 0x85EBCA77C2B2AE63ULL;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    FILE *fp = fopen(argv[1], "rb");
    if (!fp) return 1;
    uint64_t v1 = 0x9E3779B185EBCA87ULL + 0xC2B2AE3D27D4EB4FULL;
    uint64_t v2 = 0xC2B2AE3D27D4EB4FULL, v3 = 0, v4 = 0ULL - 0x9E3779B185EBCA87ULL;
    uint64_t total = 0;
    static uint8_t buf[1 << 20];
    uint8_t rem[32];
    size_t rlen = 0, n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        total += n;
        const uint8_t *p = buf, *end = buf + n;
        if (rlen > 0) {
            while (rlen < 32 && p < end) rem[rlen++] = *p++;
            if (rlen == 32) {
                const uint64_t *w = (const uint64_t *)rem;
                v1 = rnd(v1, w[0]); v2 = rnd(v2, w[1]); v3 = rnd(v3, w[2]); v4 = rnd(v4, w[3]);
                rlen = 0;
            }
        }
        while ((size_t)(end - p) >= 32) {
            const uint64_t *w = (const uint64_t *)p;
            v1 = rnd(v1, w[0]); v2 = rnd(v2, w[1]); v3 = rnd(v3, w[2]); v4 = rnd(v4, w[3]);
            p += 32;
        }
        while (p < end) rem[rlen++] = *p++;
    }
    fclose(fp);
    uint64_t h = (total >= 32)
        ? mrg(mrg(mrg(mrg(rotl(v1, 1) + rotl(v2, 7) + rotl(v3, 12) + rotl(v4, 18), v1), v2), v3), v4)
        : 0x27D4EB2F165667C5ULL;
    h += total;
    size_t i = 0;
    for (; i + 8 <= rlen; i += 8) {
        uint64_t k = *(const uint64_t *)(rem + i);
        h = rotl(h ^ rnd(0, k), 27) * 0x9E3779B185EBCA87ULL + 0x85EBCA77C2B2AE63ULL;
    }
    if (i + 4 <= rlen) {
        uint32_t k = *(const uint32_t *)(rem + i);
        h = rotl(h ^ ((uint64_t)k * 0x9E3779B185EBCA87ULL), 23) * 0xC2B2AE3D27D4EB4FULL + 0x165667B19E3779F9ULL;
        i += 4;
    }
    for (; i < rlen; i++) {
        h = rotl(h ^ ((uint64_t)rem[i] * 0x27D4EB2F165667C5ULL), 11) * 0x9E3779B185EBCA87ULL;
    }
    h ^= h >> 33; h *= 0xC2B2AE3D27D4EB4FULL;
    h ^= h >> 29; h *= 0x165667B19E3779F9ULL;
    h ^= h >> 32;
    printf("%016llx\n", (unsigned long long)h);
    return 0;
}
"""


def _rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def _rnd64(acc, val):
    return (_rotl64((acc + val * P2) & M64, 31) * P1) & M64


def _mrg64(acc, val):
    return (((acc ^ _rnd64(0, val)) * P1) + P4) & M64


def xxh64_bytes(data):
    n = len(data)
    mv = memoryview(data)
    if n >= 32:
        v1 = (P1 + P2) & M64
        v2 = P2
        v3 = 0
        v4 = (-P1) & M64
        limit = (n // 32) * 32
        for w0, w1, w2, w3 in struct.iter_unpack("<4Q", mv[:limit]):
            v1 = _rnd64(v1, w0)
            v2 = _rnd64(v2, w1)
            v3 = _rnd64(v3, w2)
            v4 = _rnd64(v4, w3)
        h = (_rotl64(v1, 1) + _rotl64(v2, 7) + _rotl64(v3, 12) + _rotl64(v4, 18)) & M64
        for v in (v1, v2, v3, v4):
            h = _mrg64(h, v)
        idx = limit
    else:
        h = P5
        idx = 0
    h = (h + n) & M64
    while idx + 8 <= n:
        (k,) = struct.unpack_from("<Q", mv, idx)
        h = (_rotl64(h ^ _rnd64(0, k), 27) * P1 + P4) & M64
        idx += 8
    if idx + 4 <= n:
        (k,) = struct.unpack_from("<I", mv, idx)
        h = (_rotl64(h ^ ((k * P1) & M64), 23) * P2 + P3) & M64
        idx += 4
    while idx < n:
        h = (_rotl64(h ^ ((mv[idx] * P5) & M64), 11) * P1) & M64
        idx += 1
    h ^= h >> 33
    h = (h * P2) & M64
    h ^= h >> 29
    h = (h * P3) & M64
    h ^= h >> 32
    return f"{h:016x}"


def xxh64_file(path):
    if path.stat().st_size <= 8 * 1024 * 1024:
        return xxh64_bytes(path.read_bytes())
    cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
    if cc:
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "xxh64.c"
            exe = Path(td) / "xxh64"
            src.write_text(XXH64_C)
            subprocess.run([cc, "-O3", str(src), "-o", str(exe)], check=True)
            return subprocess.check_output([str(exe), str(path)], text=True).strip()
    return xxh64_bytes(path.read_bytes())

TARGET_CVE = "CVE-2026-19773"
FIXTURE_LABEL = "TEST-ONLY-AUXILIARY-CPE-FIXTURE-NOT-OFFICIAL-ANCHORE-FEED"
CPE_BLOB = json.dumps({
    "cves": [TARGET_CVE],
    "ranges": [{
        "version": {"constraint": "<= 4.2.2"},
        "fix": {"state": "not-fixed"},
    }],
}, separators=(",", ":"))


class AuxDbError(ValueError):
    """Raised when auxiliary test DB preconditions or stock DB immutability fail."""


def require(cond, msg):
    if not cond:
        raise AuxDbError(msg)


def sha256_file(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def build_auxiliary_db(*, stock_db_path, expected_stock_db_sha256, output_dir, client_version="v6.1.10"):
    require("test-only-aux" in output_dir.as_posix(),
            "output_dir must explicitly include 'test-only-aux' to prevent stock DB confusion")
    require(not output_dir.exists(), f"output_dir must not already exist: {output_dir}")
    before_sha = sha256_file(stock_db_path)
    if expected_stock_db_sha256:
        require(before_sha == expected_stock_db_sha256,
                f"stock vulnerability.db SHA-256 mismatch: expected {expected_stock_db_sha256}, got {before_sha}")

    db_subdir = output_dir / "6"
    db_subdir.mkdir(parents=True)
    aux_db = db_subdir / "vulnerability.db"
    shutil.copyfile(stock_db_path, aux_db)

    con = sqlite3.connect(aux_db)
    try:
        with con:
            vh = con.execute(
                "SELECT id FROM vulnerability_handles WHERE name=? AND provider_id='nvd'",
                (TARGET_CVE,),
            ).fetchone()
            require(vh is not None, f"{TARGET_CVE} NVD handle missing in stock DB")
            vuln_id = vh[0]

            existing = con.execute(
                "SELECT COUNT(*) FROM affected_cpe_handles WHERE vulnerability_id=?",
                (vuln_id,),
            ).fetchone()[0]
            require(existing == 0, f"stock DB already has {existing} affected_cpe_handles rows for {TARGET_CVE}")

            cpe_row = con.execute(
                "SELECT id FROM cpes WHERE part='a' AND product='libwebsockets' ORDER BY id LIMIT 1"
            ).fetchone()
            require(cpe_row is not None, "libwebsockets CPE entry missing in stock DB")
            cpe_id = cpe_row[0]

            cur = con.execute("INSERT INTO blobs (value) VALUES (?)", (CPE_BLOB,))
            blob_id = cur.lastrowid
            cur = con.execute(
                "INSERT INTO affected_cpe_handles (vulnerability_id, cpe_id, blob_id) VALUES (?, ?, ?)",
                (vuln_id, cpe_id, blob_id),
            )
            ach_id = cur.lastrowid
    finally:
        con.close()

    after_stock_sha = sha256_file(stock_db_path)
    require(after_stock_sha == before_sha, "stock vulnerability.db changed during auxiliary copy")

    aux_sha = sha256_file(aux_db)
    aux_xxh64 = xxh64_file(aux_db)
    import_meta = {
        "digest": f"xxh64:{aux_xxh64}",
        "source": FIXTURE_LABEL,
        "client_version": client_version,
    }
    (db_subdir / "import.json").write_text(json.dumps(import_meta, indent=1) + "\n")

    notice = {
        "schema_version": 1,
        "label": FIXTURE_LABEL,
        "official_anchore_feed": False,
        "purpose": "Isolated test-only CPE applicability fixture proving Grype 0.122.0 OpenVEX positive and negative controls while NIST NVD CVE-2026-19773 remains Awaiting Analysis.",
        "stock_db_sha256": before_sha,
        "aux_db_sha256": aux_sha,
        "aux_db_xxh64": f"xxh64:{aux_xxh64}",
        "inserted_row": {
            "vulnerability": TARGET_CVE,
            "vulnerability_id": vuln_id,
            "cpe_id": cpe_id,
            "blob_id": blob_id,
            "affected_cpe_handle_id": ach_id,
            "blob_value": json.loads(CPE_BLOB),
        },
    }
    (output_dir / "AUXILIARY-TEST-DB-NOTICE.json").write_text(json.dumps(notice, indent=2, sort_keys=True) + "\n")
    return notice


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--stock-db", required=True, type=Path)
    parser.add_argument("--expected-stock-db-sha256", default=None)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()
    notice = build_auxiliary_db(
        stock_db_path=args.stock_db,
        expected_stock_db_sha256=args.expected_stock_db_sha256,
        output_dir=args.output_dir,
    )
    print(json.dumps(notice, indent=2))


if __name__ == "__main__":
    main()
