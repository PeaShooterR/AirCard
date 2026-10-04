#!/usr/bin/env python3
"""Extract Apple Wallet card skin and URL metadata through AirLift."""
from __future__ import annotations

import os
import posixpath
import secrets
import sys
import tempfile
import time
from pathlib import Path

from apply_card_skin import (
    AIRLOCK_ROOT,
    AIRTRAFFIC_HOST,
    LINK_PREFIX,
    RECOVERED_PREFIX,
    SOURCE_PREFIX,
    build_archive,
    build_books,
    native,
    operation_ok,
    run_json,
    write_file,
)


def extract_file(
    udid: str,
    target: str,
    local_path: str,
    retries: int = 1,
    error_out: list[str] | None = None,
) -> bool:
    target_tail = target.lstrip("/")
    for attempt in range(1, max(1, retries) + 1):
        staged = False
        restored = False
        try:
            token = secrets.token_hex(10)
            source = f"{SOURCE_PREFIX}{token}"
            link_destination = f"{LINK_PREFIX}{token}"
            recovered = f"{RECOVERED_PREFIX}{token}"

            target_parent, target_leaf = posixpath.split(target_tail)
            if not target_parent or not target_leaf:
                raise ValueError(f"invalid extraction target: {target}")
            target_parent = f"/{target_parent}"

            link_identifier = f"../../{source}/p0/p1/p2/link"
            target_path = f"/{target_tail}"
            target_identifier = posixpath.relpath(target_path, AIRLOCK_ROOT)
            identifiers = [link_identifier, target_identifier]
            destinations = [link_destination, recovered]

            with tempfile.TemporaryDirectory(prefix="airlift-extract-") as temporary:
                work = Path(temporary)
                archive_path = work / "payload.zip"
                books_path = work / "Books.plist"
                snapshot_root = work / "books-snapshot"
                snapshot_root.mkdir()

                archive_path.write_bytes(build_archive(target_parent, b""))
                books_path.write_bytes(build_books(identifiers))

                snapshot = native("snapshot-books", udid, os.fspath(snapshot_root))
                if not operation_ok(snapshot):
                    raise RuntimeError(f"could not snapshot Books state: {snapshot}")

                stage = native(
                    "stage",
                    udid,
                    source,
                    link_destination,
                    recovered,
                    os.fspath(archive_path),
                    os.fspath(books_path),
                    os.fspath(snapshot_root),
                )
                if not operation_ok(stage):
                    raise RuntimeError(f"staging failed: {stage}")
                staged = True

                atc_cmd = [os.fspath(AIRTRAFFIC_HOST), udid]
                for identifier, destination in zip(identifiers, destinations):
                    atc_cmd.extend((identifier, destination))
                atc = run_json(atc_cmd, timeout=120)
                if atc.get("exitCode") != 0 or not atc.get("ok"):
                    raise RuntimeError(str(atc.get("error", "AirTraffic extraction failed")))

                read_res = native("read-file", udid, recovered, local_path)
                if not operation_ok(read_res):
                    raise RuntimeError(str(read_res.get("operation", {}).get("error", "Device read failed")))
                local_file = Path(local_path)
                if not local_file.is_file() or local_file.stat().st_size == 0:
                    raise RuntimeError("extracted file is empty")
                extracted_bytes = local_file.read_bytes()

                if not write_file(udid, target_parent, target_leaf, extracted_bytes):
                    raise RuntimeError("failed to restore extracted file; cleanup was skipped")
                restored = True

                finish = native(
                    "finish-write",
                    udid,
                    source,
                    link_destination,
                    recovered,
                    os.fspath(snapshot_root),
                )
                if not operation_ok(finish):
                    raise RuntimeError(f"extraction cleanup failed: {finish}")
                staged = False
            return True
        except Exception as error:
            if error_out is not None:
                error_out.append(f"attempt {attempt}: {error}")
            if staged and restored:
                try:
                    native(
                        "finish-write",
                        udid,
                        source,
                        link_destination,
                        recovered,
                        os.fspath(snapshot_root),
                    )
                except Exception:
                    pass

        if attempt < retries:
            time.sleep(0.3 * attempt)

    return False


def main() -> None:
    if len(sys.argv) < 3:
        print("Usage: extract_card_skin.py <udid> <card_hash> [output_dir]")
        return

    udid = sys.argv[1]
    card_hash = sys.argv[2]
    output = Path(sys.argv[3] if len(sys.argv) > 3 else Path.cwd()).expanduser()
    output.mkdir(parents=True, exist_ok=True)
    target_dir = f"/var/mobile/Library/Passes/Cards/{card_hash}.pkpass"

    for leaf in (
        "cardBackgroundCombined@3x.png",
        "cardBackgroundCombined@2x.png",
        "cardBackgroundCombined.pdf",
        "cardBackgroundCombined.png.urls",
        "cardBackgroundCombined.pdf.urls",
    ):
        destination = output / f"{card_hash}_{leaf}"
        errors: list[str] = []
        ok = extract_file(udid, f"{target_dir}/{leaf}", str(destination), error_out=errors)
        print(f"{leaf}: {'SUCCESS' if ok else 'FAILED'}")
        if not ok:
            for error in errors:
                print(f"  {error}")


if __name__ == "__main__":
    main()
