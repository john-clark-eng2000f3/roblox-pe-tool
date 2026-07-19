"""roblox_pe - PE binary analysis helpers for Roblox executables."""

from roblox_pe.pe_reader import RobloxBinary, read_sections
from roblox_pe.signatures import extract_signatures
from roblox_pe.diff import diff_binaries

__version__ = "0.2.1"
__all__ = ["RobloxBinary", "read_sections", "extract_signatures", "diff_binaries"]
