from __future__ import annotations

import io
import struct
from typing import TYPE_CHECKING, BinaryIO

from dissect.eventlog.c_message_table import (
    _RSRC_NAME_IS_STRING,
    _RSRC_OFFSET_IS_SUBDIR,
    _RSRC_OFFSET_MASK,
    _PE_MAGIC_PE32,
    _PE_MAGIC_PE32_PLUS,
    c_message_table,
)
from dissect.eventlog.exceptions import Error

if TYPE_CHECKING:
    pass


class PEError(Error):
    """Raised when a PE file cannot be parsed."""


class ResourceNotFoundError(PEError):
    """Raised when a requested resource type or name is not present."""


class PEFile:
    """Lightweight PE resource reader built on ``dissect.cstruct``.

    Only the structures needed to locate and extract resource-section data
    are parsed; no code sections are touched.

    Parameters
    ----------
    fh:
        A seekable binary file-like object positioned at byte 0.
    """

    def __init__(self, fh: BinaryIO) -> None:
        self._fh = fh

        # ── DOS header ──────────────────────────────────────────────
        fh.seek(0)
        dos = c_message_table.IMAGE_DOS_HEADER(fh)
        if dos.e_magic != 0x5A4D:  # "MZ"
            raise PEError(f"Not a valid PE file: bad MZ magic {dos.e_magic:#06x}")

        # ── PE signature ────────────────────────────────────────────
        fh.seek(dos.e_lfanew)
        pe_sig = struct.unpack("<I", fh.read(4))[0]
        if pe_sig != 0x00004550:  # "PE\x00\x00"
            raise PEError(f"Not a valid PE file: bad PE signature {pe_sig:#010x}")

        # ── COFF file header ─────────────────────────────────────────
        self._file_header = c_message_table.IMAGE_FILE_HEADER(fh)

        # ── Optional header (32-bit or 64-bit) ──────────────────────
        opt_start = fh.tell()
        magic = struct.unpack("<H", fh.read(2))[0]
        fh.seek(opt_start)

        if magic == _PE_MAGIC_PE32:
            self._optional_header = c_message_table.IMAGE_OPTIONAL_HEADER(fh)
        elif magic == _PE_MAGIC_PE32_PLUS:
            self._optional_header = c_message_table.IMAGE_OPTIONAL_HEADER64(fh)
        else:
            raise PEError(f"Unknown PE optional header magic: {magic:#06x}")

        # ── Section table ────────────────────────────────────────────
        self._sections = [
            c_message_table.IMAGE_SECTION_HEADER(fh)
            for _ in range(self._file_header.NumberOfSections)
        ]

    # ── Public helpers ───────────────────────────────────────────────

    @property
    def resource_directory_rva(self) -> int:
        """RVA of the resource directory (DataDirectory[2].VirtualAddress)."""
        dd = self._optional_header.DataDirectory
        return dd[c_message_table.IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress

    def rva_to_offset(self, rva: int) -> int:
        """Convert a Relative Virtual Address to a raw file offset."""
        for sec in self._sections:
            va = sec.VirtualAddress
            if va <= rva < va + sec.VirtualSize:
                return rva - va + sec.PointerToRawData
        raise PEError(f"RVA {rva:#010x} does not fall within any section")

    def get_resource(self, type_id: int) -> bytes:
        """Return the raw data bytes of the first resource with the given numeric type.

        The PE resource tree is a three-level directory:
        Level 1 → type (e.g. RT_MESSAGETABLE = 11)
        Level 2 → name / ID (we take the first entry)
        Level 3 → language (we take the first entry)

        Parameters
        ----------
        type_id:
            Numeric resource type identifier (e.g. ``RT_MESSAGETABLE = 11``).

        Returns
        -------
        bytes
            Raw resource data.

        Raises
        ------
        ResourceNotFoundError
            If the resource type is not present in the binary.
        """
        rsrc_rva = self.resource_directory_rva
        if rsrc_rva == 0:
            raise ResourceNotFoundError("Binary has no resource section")
        rsrc_offset = self.rva_to_offset(rsrc_rva)

        # Level 1: type directory
        type_entry = self._find_id_entry(rsrc_offset, rsrc_offset, type_id)
        if type_entry is None:
            raise ResourceNotFoundError(f"Resource type {type_id} not found")

        subdir_offset = rsrc_offset + (type_entry & _RSRC_OFFSET_MASK)

        # Level 2: name/id directory — take the first entry
        name_entry = self._first_entry_data(rsrc_offset, subdir_offset)
        subdir_offset = rsrc_offset + (name_entry & _RSRC_OFFSET_MASK)

        # Level 3: language directory — take the first entry
        lang_entry = self._first_entry_data(rsrc_offset, subdir_offset)
        data_entry_offset = rsrc_offset + (lang_entry & _RSRC_OFFSET_MASK)

        return self._read_data_entry(rsrc_offset, data_entry_offset)

    def get_named_resource(self, name: str) -> bytes:
        """Return the raw data bytes of the first resource with the given name string.

        Parameters
        ----------
        name:
            Resource name string (matched case-insensitively).

        Returns
        -------
        bytes
            Raw resource data.

        Raises
        ------
        ResourceNotFoundError
            If a resource with that name is not present in the binary.
        """
        rsrc_rva = self.resource_directory_rva
        if rsrc_rva == 0:
            raise ResourceNotFoundError("Binary has no resource section")
        rsrc_offset = self.rva_to_offset(rsrc_rva)

        # Level 1: type directory — scan named entries
        name_entry = self._find_name_entry(rsrc_offset, rsrc_offset, name)
        if name_entry is None:
            raise ResourceNotFoundError(f"Named resource '{name}' not found")

        subdir_offset = rsrc_offset + (name_entry & _RSRC_OFFSET_MASK)

        # Level 2: first name/id sub-entry
        sub_entry = self._first_entry_data(rsrc_offset, subdir_offset)
        subdir_offset = rsrc_offset + (sub_entry & _RSRC_OFFSET_MASK)

        # Level 3: first language entry
        lang_entry = self._first_entry_data(rsrc_offset, subdir_offset)
        data_entry_offset = rsrc_offset + (lang_entry & _RSRC_OFFSET_MASK)

        return self._read_data_entry(rsrc_offset, data_entry_offset)

    # ── Internal helpers ─────────────────────────────────────────────

    def _read_resource_directory(self, offset: int) -> c_message_table.IMAGE_RESOURCE_DIRECTORY:
        self._fh.seek(offset)
        return c_message_table.IMAGE_RESOURCE_DIRECTORY(self._fh)

    def _read_entry(self, offset: int) -> c_message_table.IMAGE_RESOURCE_DIRECTORY_ENTRY:
        self._fh.seek(offset)
        return c_message_table.IMAGE_RESOURCE_DIRECTORY_ENTRY(self._fh)

    def _entry_size(self) -> int:
        return len(c_message_table.IMAGE_RESOURCE_DIRECTORY_ENTRY)

    def _dir_size(self) -> int:
        return len(c_message_table.IMAGE_RESOURCE_DIRECTORY)

    def _find_id_entry(self, rsrc_base: int, dir_offset: int, target_id: int) -> int | None:
        """Return the DataEntryOffsetOrSubdirectory value for the entry matching *target_id*."""
        directory = self._read_resource_directory(dir_offset)
        total_entries = directory.NumberOfNamedEntries + directory.NumberOfIdEntries
        entries_offset = dir_offset + self._dir_size()

        entry_sz = self._entry_size()
        for i in range(total_entries):
            entry = self._read_entry(entries_offset + i * entry_sz)
            name_or_id = entry.NameOffsetOrId
            data_or_subdir = entry.DataEntryOffsetOrSubdirectory
            # ID entries have the high bit clear
            if not (name_or_id & _RSRC_NAME_IS_STRING):
                if (name_or_id & 0xFFFF) == target_id:
                    return data_or_subdir
        return None

    def _find_name_entry(self, rsrc_base: int, dir_offset: int, target_name: str) -> int | None:
        """Return the DataEntryOffsetOrSubdirectory value for the named entry matching *target_name*."""
        directory = self._read_resource_directory(dir_offset)
        entries_offset = dir_offset + self._dir_size()
        entry_sz = self._entry_size()

        for i in range(directory.NumberOfNamedEntries):
            entry = self._read_entry(entries_offset + i * entry_sz)
            name_or_id = entry.NameOffsetOrId
            data_or_subdir = entry.DataEntryOffsetOrSubdirectory
            if name_or_id & _RSRC_NAME_IS_STRING:
                name_offset = rsrc_base + (name_or_id & _RSRC_OFFSET_MASK)
                entry_name = self._read_resource_name(name_offset)
                if entry_name.upper() == target_name.upper():
                    return data_or_subdir
        return None

    def _read_resource_name(self, offset: int) -> str:
        """Read a counted Unicode resource name string."""
        self._fh.seek(offset)
        length = struct.unpack("<H", self._fh.read(2))[0]
        raw = self._fh.read(length * 2)
        return raw.decode("utf-16-le")

    def _first_entry_data(self, rsrc_base: int, dir_offset: int) -> int:
        """Return the DataEntryOffsetOrSubdirectory of the very first entry in a directory."""
        directory = self._read_resource_directory(dir_offset)
        if directory.NumberOfNamedEntries + directory.NumberOfIdEntries == 0:
            raise ResourceNotFoundError("Empty resource sub-directory")
        entries_offset = dir_offset + self._dir_size()
        entry = self._read_entry(entries_offset)
        return entry.DataEntryOffsetOrSubdirectory

    def _read_data_entry(self, rsrc_base: int, data_entry_offset: int) -> bytes:
        """Parse an IMAGE_RESOURCE_DATA_ENTRY and return the raw resource bytes."""
        self._fh.seek(data_entry_offset)
        data_entry = c_message_table.IMAGE_RESOURCE_DATA_ENTRY(self._fh)
        raw_offset = self.rva_to_offset(data_entry.OffsetToData)
        self._fh.seek(raw_offset)
        return self._fh.read(data_entry.Size)
