import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class SectionHeader:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_offset: int
    characteristics: int


@dataclass
class DebugEntry:
    type_id: int
    timestamp: int
    major_version: int
    minor_version: int
    size_of_data: int
    address_of_raw_data: int
    pointer_to_raw_data: int
    guid_path: Optional[str] = None


@dataclass
class PEInfo:
    is_64bit: bool
    machine: int
    timestamp: int
    entry_point: int
    image_base: int
    section_alignment: int
    file_alignment: int
    sections: List[SectionHeader]
    data_directories: Dict[str, Tuple[int, int]]
    debug_entries: List[DebugEntry]


class PEParserError(Exception):
    pass


class PEImage:
    """Minimal PE/COFF parser for extracting section maps and header timestamps."""

    DIRECTORY_NAMES = [
        "EXPORT",
        "IMPORT",
        "RESOURCE",
        "EXCEPTION",
        "SECURITY",
        "BASERELOC",
        "DEBUG",
        "ARCHITECTURE",
        "GLOBALPTR",
        "TLS",
        "LOAD_CONFIG",
        "BOUND_IMPORT",
        "IAT",
        "DELAY_IMPORT",
        "CLR_RUNTIME_HEADER",
        "RESERVED",
    ]

    def __init__(self, data: bytes):
        self.data = data
        self.info = self._parse()

    def _parse(self) -> PEInfo:
        if len(self.data) < 64:
            raise PEParserError("file too small for dos header")

        if self.data[:2] != b"MZ":
            raise PEParserError("missing MZ signature")

        (e_lfanew,) = struct.unpack_from("<I", self.data, 0x3C)
        if e_lfanew + 4 > len(self.data):
            raise PEParserError("invalid e_lfanew offset")

        if self.data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
            raise PEParserError("missing PE signature")

        coff_offset = e_lfanew + 4
        coff_hdr = self.data[coff_offset : coff_offset + 20]
        if len(coff_hdr) < 20:
            raise PEParserError("truncated coff header")

        machine, num_sections, timedate, _, _, opt_size, characteristics = struct.unpack(
            "<HHIIIHH", coff_hdr
        )

        opt_offset = coff_offset + 20
        if opt_offset + opt_size > len(self.data):
            raise PEParserError("optional header extends beyond file")

        magic = struct.unpack_from("<H", self.data, opt_offset)[0]
        is_64bit = magic == 0x20B
        if not is_64bit and magic != 0x10B:
            raise PEParserError(f"unknown optional header magic: {hex(magic)}")

        if is_64bit:
            (
                entry_point,
                _,  # base of code
                image_base,
                section_align,
                file_align,
            ) = struct.unpack_from("<IIQII", self.data, opt_offset + 16)
            num_rva_offset = opt_offset + 108
        else:
            (
                entry_point,
                _,
                _,
                image_base,
                section_align,
                file_align,
            ) = struct.unpack_from("<IIIIII", self.data, opt_offset + 16)
            num_rva_offset = opt_offset + 92

        num_rva = 0
        if opt_offset + opt_size >= num_rva_offset + 4:
            (num_rva,) = struct.unpack_from("<I", self.data, num_rva_offset)

        datadirs = {}
        dirs_start = num_rva_offset + 4
        for i in range(min(num_rva, 16)):
            dir_offset = dirs_start + (i * 8)
            if dir_offset + 8 <= opt_offset + opt_size:
                rva, size = struct.unpack_from("<II", self.data, dir_offset)
                if i < len(self.DIRECTORY_NAMES):
                    datadirs[self.DIRECTORY_NAMES[i]] = (rva, size)

        sections_offset = opt_offset + opt_size
        sections = []
        for i in range(num_sections):
            sec_hdr_offset = sections_offset + (i * 40)
            if sec_hdr_offset + 40 > len(self.data):
                break
            sec_bytes = self.data[sec_hdr_offset : sec_hdr_offset + 40]
            raw_name, virt_size, virt_addr, raw_size, raw_ptr, _, _, _, _, chars = (
                struct.unpack("<8sIIIIIIHHI", sec_bytes)
            )
            name = raw_name.rstrip(b"\x00").decode("latin-1", errors="replace")
            # print(f"dbg: section {name} raw_sz={raw_size} virt_sz={virt_size}")
            sections.append(
                SectionHeader(
                    name=name,
                    virtual_size=virt_size,
                    virtual_address=virt_addr,
                    raw_size=raw_size,
                    raw_offset=raw_ptr,
                    characteristics=chars,
                )
            )

        debug_entries = self._parse_debug_dirs(datadirs.get("DEBUG"), sections)

        return PEInfo(
            is_64bit=is_64bit,
            machine=machine,
            timestamp=timedate,
            entry_point=entry_point,
            image_base=image_base,
            section_alignment=section_align,
            file_alignment=file_align,
            sections=sections,
            data_directories=datadirs,
            debug_entries=debug_entries,
        )

    def _parse_debug_dirs(
        self, dbg_dir: Optional[Tuple[int, int]], sections: List[SectionHeader]
    ) -> List[DebugEntry]:
        if not dbg_dir or dbg_dir[1] == 0:
            return []

        rva, size = dbg_dir
        offset = self._raw_offset_for_rva(rva, sections)
        if offset is None or offset + size > len(self.data):
            return []

        entries = []
        count = size // 28
        for i in range(count):
            pos = offset + (i * 28)
            _, timedate, maj_v, min_v, type_id, sz_data, addr_raw, ptr_raw = (
                struct.unpack("<IIHHIIII", self.data[pos : pos + 28])
            )
            if type_id == 0 and sz_data == 0:
                continue

            guid_path = None
            # CodeView PDB70 entry
            if type_id == 2 and ptr_raw > 0 and ptr_raw + sz_data <= len(self.data):
                cv_data = self.data[ptr_raw : ptr_raw + sz_data]
                if len(cv_data) > 24 and cv_data[:4] == b"RSDS":
                    # PDB path is null-terminated utf-8 after 16-byte guid + 4-byte age
                    pdb_raw = cv_data[24:].split(b"\x00")[0]
                    guid_path = pdb_raw.decode("utf-8", errors="replace")

            entries.append(
                DebugEntry(
                    type_id=type_id,
                    timestamp=timedate,
                    major_version=maj_v,
                    minor_version=min_v,
                    size_of_data=sz_data,
                    address_of_raw_data=addr_raw,
                    pointer_to_raw_data=ptr_raw,
                    guid_path=guid_path,
                )
            )
        return entries

    def _raw_offset_for_rva(self, rva: int, sections: List[SectionHeader]) -> Optional[int]:
        for sec in sections:
            end = sec.virtual_address + max(sec.virtual_size, sec.raw_size)
            if sec.virtual_address <= rva < end:
                diff = rva - sec.virtual_address
                if diff < sec.raw_size:
                    return sec.raw_offset + diff
        return None

    def rva_to_offset(self, rva: int) -> Optional[int]:
        return self._raw_offset_for_rva(rva, self.info.sections)

    def get_section(self, name: str) -> Optional[SectionHeader]:
        for sec in self.info.sections:
            if sec.name == name:
                return sec
        return None

    def get_section_bytes(self, section: SectionHeader) -> bytes:
        start = section.raw_offset
        end = start + section.raw_size
        if start >= len(self.data):
            return b""
        return self.data[start : min(end, len(self.data))]
