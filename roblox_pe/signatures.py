import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from roblox_pe.pe_reader import PEImage


@dataclass
class ScanResult:
    binary_type: str
    version: Optional[str]
    deploy_guid: Optional[str]
    channel: Optional[str]
    pdb_name: Optional[str]
    flags_sample: List[str]
    total_flags_found: int


VERSION_RE = re.compile(rb"version-[a-f0-9]{16}")
SEMVER_RE = re.compile(rb"0\.[0-9]{3}\.[0-9]\.[0-9]{5,8}")
# Roblox channel identifiers baked into telemetry strings
CHANNEL_RE = re.compile(rb"\b(LIVE|zcanary|zproject[0-9]+|zintegration[0-9]*|sdev|stage)\b")

# FVariable string definitions in engine rdata
FLAG_RE = re.compile(rb"\b(F(?:Flag|Int|String|Log|Variable)[A-Z0-9][A-Za-z0-9_]{3,63})\b")


def _extract_flags(buf: bytes, max_count: int = 50) -> Tuple[List[str], int]:
    found: Set[str] = set()
    for match in FLAG_RE.finditer(buf):
        name = match.group(1).decode("latin-1")
        # Filter out common false positives from C++ symbols or protobuf tables
        if name.endswith("_") or "__" in name:
            continue
        found.add(name)

    sorted_flags = sorted(found)
    return sorted_flags[:max_count], len(sorted_flags)


# FIXME: studio Qt binaries sometimes split string tables across .rdata and .rodata
def scan_binary(image: PEImage) -> ScanResult:
    rdata_sec = image.get_section(".rdata")
    data_sec = image.get_section(".data")
    text_sec = image.get_section(".text")

    # Prioritize scanning read-only data first so we hit version stamps faster
    scanned_chunks = []
    for sec in [rdata_sec, data_sec]:
        if sec:
            scanned_chunks.append(image.get_section_bytes(sec))

    primary_buf = b"".join(scanned_chunks)
    if not primary_buf:
        primary_buf = image.data

    binary_type = "Unknown"
    if b"RobloxStudioBeta.exe" in primary_buf or b"RobloxStudio" in primary_buf:
        binary_type = "Studio"
    elif b"RobloxPlayerBeta.exe" in primary_buf or b"RobloxPlayerBeta" in primary_buf:
        binary_type = "Player"
    elif b"RobloxCrashHandler" in primary_buf:
        binary_type = "CrashHandler"

    deploy_guid = None
    match_guid = VERSION_RE.search(primary_buf)
    if match_guid:
        deploy_guid = match_guid.group(0).decode("ascii")

    version = None
    match_ver = SEMVER_RE.search(primary_buf)
    if match_ver:
        version = match_ver.group(0).decode("ascii")

    channel = None
    match_chan = CHANNEL_RE.search(primary_buf)
    if match_chan:
        channel = match_chan.group(1).decode("ascii")

    pdb_name = None
    for entry in getattr(image.info, "debug_entries", []):
        if entry.guid_path:
            pdb_name = entry.guid_path.split("\\")[-1]
            break

    sample, total = _extract_flags(primary_buf)

    return ScanResult(
        binary_type=binary_type,
        version=version,
        deploy_guid=deploy_guid,
        channel=channel,
        pdb_name=pdb_name,
        flags_sample=sample,
        total_flags_found=total,
    )
