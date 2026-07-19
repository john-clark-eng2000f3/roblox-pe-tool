import pytest
from roblox_pe.signatures import (
    extract_version_guid,
    extract_channel_name,
    scan_pattern,
    CompiledPattern,
)


def test_extract_version_guid_present():
    # Typical format baked into Roblox binaries
    payload = b"junk data here version-4f2a1b9c8d7e6f50 and more trailing garbage"
    guid = extract_version_guid(payload)
    assert guid == "version-4f2a1b9c8d7e6f50"


def test_extract_version_guid_short_hash():
    # Old clients used 32-char hex, newer builds have 16 or 32
    payload = b"...version-a0b1c2d3e4f5061728394a5b6c7d8e9f..."
    guid = extract_version_guid(payload)
    assert guid == "version-a0b1c2d3e4f5061728394a5b6c7d8e9f"


def test_extract_version_guid_missing():
    payload = b"this binary has no version string inside it"
    guid = extract_version_guid(payload)
    assert guid is None


def test_extract_channel_name():
    data = b"--channel\x00zflag\x00LIVE\x00other"
    assert extract_channel_name(b"something LIVE something") == "LIVE"
    assert extract_channel_name(b"zchannel-sitetest3.robloxlabs.com") == "sitetest3"
    assert extract_channel_name(b"no channel here") is None


def test_scan_pattern_exact():
    pattern = CompiledPattern.from_hex("48 89 5c 24 08 57 48 83 ec 20")
    data = b"\x90\x90\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x20\xcc"
    
    matches = scan_pattern(data, pattern)
    assert matches == [2]


def test_scan_pattern_wildcards():
    # Wildcard in register displacement / stack offsets
    pattern = CompiledPattern.from_hex("48 89 5c 24 ? 48 89 74 24 ? 57")
    data = b"\x00" * 10 + b"\x48\x89\x5c\x24\x10\x48\x89\x74\x24\x18\x57" + b"\x00" * 5
    
    matches = scan_pattern(data, pattern)
    assert matches == [10]


def test_scan_pattern_empty_or_short_buffer():
    pattern = CompiledPattern.from_hex("90 90 90")
    assert scan_pattern(b"", pattern) == []
    assert scan_pattern(b"\x90\x90", pattern) == []


def test_invalid_pattern_hex():
    with pytest.raises(ValueError):
        CompiledPattern.from_hex("48 89 ZZ 24")
