import struct
import pytest
from roblox_pe.pe_reader import PEFile, PEFormatError


def make_minimal_pe(is_64bit: bool = True, sections=None) -> bytes:
    if sections is None:
        sections = [
            (b".text\x00\x00\x00", 0x1000, 0x1000, 0x200, 0x400, 0x60000020),
            (b".rdata\x00\x00", 0x800, 0x2000, 0x200, 0x600, 0x40000040),
        ]

    # DOS header (64 bytes)
    # e_magic at 0x00, e_lfanew at 0x3C pointing to 0x80
    dos_header = bytearray(0x80)
    dos_header[0:2] = b"MZ"
    struct.pack_into("<I", dos_header, 0x3C, 0x80)

    # NT Header signature
    nt_sig = b"PE\x00\x00"

    machine = 0x8664 if is_64bit else 0x14C
    num_sections = len(sections)
    time_date = 1680000000
    opt_header_size = 240 if is_64bit else 224
    chars = 0x0022  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    file_header = struct.pack(
        "<HHIIIHH",
        machine,
        num_sections,
        time_date,
        0,
        0,
        opt_header_size,
        chars,
    )

    magic = 0x20B if is_64bit else 0x10B
    entry_point = 0x1000
    image_base = 0x140000000 if is_64bit else 0x400000
    sect_align = 0x1000
    file_align = 0x200

    if is_64bit:
        # Standard PE32+ optional header fields + some extra zeroed data dirs
        opt_header = struct.pack(
            "<HBBIIIIIIQIIHH",
            magic,
            14, 0,          # Linker version
            0x1000,         # SizeOfCode
            0x1000,         # SizeOfInitializedData
            0,              # SizeOfUninitializedData
            entry_point,
            0x1000,         # BaseOfCode
            sect_align,
            file_align,
            image_base,
            0x4000,         # SizeOfImage
            0x400,          # SizeOfHeaders
            6, 0,           # OS version
        )
    else:
        opt_header = struct.pack(
            "<HBBIIIIIIIH",
            magic,
            14, 0,
            0x1000,
            0x1000,
            0,
            entry_point,
            0x1000,
            0x2000,
            sect_align,
            file_align,
            6,
        )

    # Pad optional header to declared size
    if len(opt_header) < opt_header_size:
        opt_header = opt_header.ljust(opt_header_size, b"\x00")

    # Build section table
    sec_table = bytearray()
    for name, vsize, vaddr, raw_size, raw_ptr, flags in sections:
        sec_table += struct.pack(
            "<8sIIIIIIHHI",
            name,
            vsize,
            vaddr,
            raw_size,
            raw_ptr,
            0, 0, 0, 0,     # relocs, linenos
            flags,
        )

    pe_bytes = bytes(dos_header) + nt_sig + file_header + opt_header + bytes(sec_table)

    # Pad to cover raw section data
    max_end = max((raw_ptr + raw_size for _, _, _, raw_size, raw_ptr, _ in sections), default=len(pe_bytes))
    if len(pe_bytes) < max_end:
        pe_bytes = pe_bytes.ljust(max_end, b"\x00")

    return pe_bytes


def test_parse_valid_pe64():
    raw = make_minimal_pe(is_64bit=True)
    pe = PEFile.from_bytes(raw)

    assert pe.is_64bit is True
    assert pe.machine == 0x8664
    assert len(pe.sections) == 2
    assert pe.sections[0].name == ".text"
    assert pe.sections[1].name == ".rdata"
    assert pe.optional_header["ImageBase"] == 0x140000000


def test_parse_valid_pe32():
    raw = make_minimal_pe(is_64bit=False)
    pe = PEFile.from_bytes(raw)

    assert pe.is_64bit is False
    assert pe.machine == 0x14C
    assert pe.optional_header["ImageBase"] == 0x400000


def test_parse_invalid_dos_magic():
    raw = bytearray(make_minimal_pe())
    raw[0:2] = b"XX"

    with pytest.raises(PEFormatError, match="Invalid DOS signature"):
        PEFile.from_bytes(bytes(raw))


def test_truncated_buffer():
    with pytest.raises(PEFormatError):
        PEFile.from_bytes(b"MZ\x00\x00")


def test_invalid_nt_signature_offset():
    raw = bytearray(make_minimal_pe())
    # Point e_lfanew way past end of buffer
    struct.pack_into("<I", raw, 0x3C, 0x50000)

    with pytest.raises(PEFormatError, match="out of bounds"):
        PEFile.from_bytes(bytes(raw))


def test_corrupted_nt_magic():
    raw = bytearray(make_minimal_pe())
    # Overwrite PE signature at offset 0x80
    raw[0x80:0x84] = b"NE\x00\x00"

    with pytest.raises(PEFormatError, match="Invalid NT signature"):
        PEFile.from_bytes(bytes(raw))


def test_section_lookup_by_name():
    raw = make_minimal_pe(sections=[
        (b".text\x00\x00\x00", 0x500, 0x1000, 0x200, 0x400, 0x60000020),
        (b".rodata\x00", 0x300, 0x2000, 0x200, 0x600, 0x40000040),
    ])
    pe = PEFile.from_bytes(raw)

    sec = pe.get_section(".rodata")
    assert sec is not None
    assert sec.virtual_address == 0x2000
    assert pe.get_section(".nonexistent") is None


def test_section_data_slicing():
    raw = bytearray(make_minimal_pe(sections=[
        (b".text\x00\x00\x00", 0x100, 0x1000, 0x10, 0x400, 0x60000020),
    ]))
    # Place marker bytes in the section's raw data area
    raw[0x400:0x410] = b"A" * 16

    pe = PEFile.from_bytes(bytes(raw))
    sec = pe.get_section(".text")
    assert sec.get_data(pe._raw) == b"A" * 16
