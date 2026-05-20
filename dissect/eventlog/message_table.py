from __future__ import annotations

import io
import re
from pathlib import Path
from typing import BinaryIO

from dissect.eventlog.c_message_table import (
    RT_MESSAGETABLE,
    _MESSAGE_RESOURCE_UNICODE,
    c_message_table,
)
from dissect.eventlog.pe import PEFile, ResourceNotFoundError


# Regex that matches Windows message format insert sequences (%1 .. %99)
# and the literal percent escape (%%).
_INSERT_RE = re.compile(r"%%|%(\d{1,2})(?:!([^!]*)!)?")

# Language subdirectory names to probe when looking for a MUI companion file,
# in preference order.
_MUI_LANG_CANDIDATES = ("en-US", "en")


class MessageTable:
    """Parser for the ``RT_MESSAGETABLE`` (type 11) PE resource.

    After construction, :attr:`messages` exposes a mapping from the
    full 32-bit message identifier (``(Qualifiers << 16) | EventID``)
    to the raw template string exactly as stored in the resource —
    including any trailing ``\\r\\n``.

    Parameters
    ----------
    data:
        Raw bytes of the ``RT_MESSAGETABLE`` resource blob.
    """

    def __init__(self, data: bytes) -> None:
        self._messages: dict[int, str] = {}
        self._parse(data)

    # ── Public API ───────────────────────────────────────────────────

    @property
    def messages(self) -> dict[int, str]:
        """Mapping of ``full_message_id → template_string``."""
        return self._messages

    @classmethod
    def from_dll(cls, fh: BinaryIO) -> "MessageTable":
        """Construct a :class:`MessageTable` directly from a DLL/EXE file.

        Parameters
        ----------
        fh:
            Seekable binary file-like object for the PE file.
        """
        pe = PEFile(fh)
        data = pe.get_resource(RT_MESSAGETABLE)
        return cls(data)

    @classmethod
    def from_path(cls, path: str | Path) -> "MessageTable":
        """Construct a :class:`MessageTable` from a DLL/EXE/MUI path.

        If the binary at *path* has no ``RT_MESSAGETABLE`` resource (common
        for modern binaries that use the MUI architecture), this method
        automatically falls back to the companion ``.mui`` file located in
        ``<parent>\\en-US\\<filename>.mui`` (or ``en\\`` as a secondary
        candidate).

        Parameters
        ----------
        path:
            Filesystem path to the PE file.
        """
        path = Path(path)
        with open(path, "rb") as fh:
            try:
                return cls.from_dll(fh)
            except ResourceNotFoundError:
                pass

        # MUI fallback: look for <parent>/<lang>/<filename>.mui
        mui_filename = path.name + ".mui"
        for lang in _MUI_LANG_CANDIDATES:
            mui_path = path.parent / lang / mui_filename
            if mui_path.exists():
                with open(mui_path, "rb") as fh:
                    return cls.from_dll(fh)

        raise ResourceNotFoundError(
            f"No RT_MESSAGETABLE found in '{path}' or its MUI companions"
        )

    @classmethod
    def find_mui_path(cls, path: str | Path) -> Path | None:
        """Return the MUI companion path for *path* if it exists, else ``None``."""
        path = Path(path)
        mui_filename = path.name + ".mui"
        for lang in _MUI_LANG_CANDIDATES:
            candidate = path.parent / lang / mui_filename
            if candidate.exists():
                return candidate
        return None

    def format_message(self, message_id: int, *substitutions: str) -> str | None:
        """Look up *message_id* and apply insertion-string substitutions.

        Substitution syntax follows the Windows ``FormatMessage`` convention:
        ``%1`` is replaced by ``substitutions[0]``, ``%2`` by
        ``substitutions[1]``, etc.  ``%%`` becomes a literal ``%``.
        An unrecognised ``%n`` where *n* is out of range is left verbatim.

        Parameters
        ----------
        message_id:
            Full 32-bit message identifier.
        *substitutions:
            Insertion strings, positionally matching ``%1``, ``%2``, …

        Returns
        -------
        str | None
            The fully formatted message, or ``None`` if *message_id* is not
            found in this table.
        """
        template = self._messages.get(message_id)
        if template is None:
            return None
        return _apply_substitutions(template, substitutions)

    # ── Internal parsing ─────────────────────────────────────────────

    def _parse(self, data: bytes) -> None:
        buf = io.BytesIO(data)
        resource_data = c_message_table.MESSAGE_RESOURCE_DATA(buf)

        for block in resource_data.Blocks:
            current_offset = block.OffsetToEntries
            message_id = block.LowId

            while message_id <= block.HighId:
                buf.seek(current_offset)
                entry = c_message_table.MESSAGE_RESOURCE_ENTRY(buf)

                # Text starts immediately after the 4-byte entry header
                # (Length includes the header itself)
                text_length = entry.Length - 4
                raw_text = buf.read(text_length)

                is_unicode = bool(entry.Flags & _MESSAGE_RESOURCE_UNICODE)
                if is_unicode:
                    text = raw_text.decode("utf-16-le")
                else:
                    text = raw_text.decode("latin-1")

                # Remove the embedded NUL terminator(s)
                text = text.rstrip("\x00")

                self._messages[message_id] = text
                current_offset += entry.Length
                message_id += 1


# ── Standalone substitution helper ───────────────────────────────────

def _apply_substitutions(template: str, substitutions: tuple[str, ...]) -> str:
    """Replace ``%1``..``%n`` placeholders with *substitutions*.

    ``%%`` is converted to a single ``%``.  A ``%n`` whose index exceeds the
    number of supplied substitutions is left unchanged in the output.
    """
    def replacer(m: re.Match) -> str:
        if m.group(0) == "%%":
            return "%"
        idx = int(m.group(1))  # 1-based
        if 1 <= idx <= len(substitutions):
            return substitutions[idx - 1]
        return m.group(0)  # leave unresolved insert intact

    return _INSERT_RE.sub(replacer, template)

    """Parser for the ``RT_MESSAGETABLE`` (type 11) PE resource.

    After construction, :attr:`messages` exposes a mapping from the
    full 32-bit message identifier (``(Qualifiers << 16) | EventID``)
    to the raw template string exactly as stored in the resource —
    including any trailing ``\\r\\n``.

    Parameters
    ----------
    data:
        Raw bytes of the ``RT_MESSAGETABLE`` resource blob.
    """

    def __init__(self, data: bytes) -> None:
        self._messages: dict[int, str] = {}
        self._parse(data)

    # ── Public API ───────────────────────────────────────────────────

    @property
    def messages(self) -> dict[int, str]:
        """Mapping of ``full_message_id → template_string``."""
        return self._messages

    @classmethod
    def from_dll(cls, fh: BinaryIO) -> "MessageTable":
        """Construct a :class:`MessageTable` directly from a DLL/EXE file.

        Parameters
        ----------
        fh:
            Seekable binary file-like object for the PE file.
        """
        pe = PEFile(fh)
        data = pe.get_resource(RT_MESSAGETABLE)
        return cls(data)

    @classmethod
    def from_path(cls, path: str | Path) -> "MessageTable":
        """Construct a :class:`MessageTable` from a DLL/EXE path.

        Parameters
        ----------
        path:
            Filesystem path to the PE file.
        """
        with open(path, "rb") as fh:
            return cls.from_dll(fh)

    def format_message(self, message_id: int, *substitutions: str) -> str | None:
        """Look up *message_id* and apply insertion-string substitutions.

        Substitution syntax follows the Windows ``FormatMessage`` convention:
        ``%1`` is replaced by ``substitutions[0]``, ``%2`` by
        ``substitutions[1]``, etc.  ``%%`` becomes a literal ``%``.
        An unrecognised ``%n`` where *n* is out of range is left verbatim.

        Parameters
        ----------
        message_id:
            Full 32-bit message identifier.
        *substitutions:
            Insertion strings, positionally matching ``%1``, ``%2``, …

        Returns
        -------
        str | None
            The fully formatted message, or ``None`` if *message_id* is not
            found in this table.
        """
        template = self._messages.get(message_id)
        if template is None:
            return None
        return _apply_substitutions(template, substitutions)

    # ── Internal parsing ─────────────────────────────────────────────

    def _parse(self, data: bytes) -> None:
        buf = io.BytesIO(data)
        resource_data = c_message_table.MESSAGE_RESOURCE_DATA(buf)

        for block in resource_data.Blocks:
            current_offset = block.OffsetToEntries
            message_id = block.LowId

            while message_id <= block.HighId:
                buf.seek(current_offset)
                entry = c_message_table.MESSAGE_RESOURCE_ENTRY(buf)

                # Text starts immediately after the 4-byte entry header
                # (Length includes the header itself)
                text_length = entry.Length - 4
                raw_text = buf.read(text_length)

                is_unicode = bool(entry.Flags & _MESSAGE_RESOURCE_UNICODE)
                if is_unicode:
                    text = raw_text.decode("utf-16-le")
                else:
                    text = raw_text.decode("latin-1")

                # Remove the embedded NUL terminator(s)
                text = text.rstrip("\x00")

                self._messages[message_id] = text
                current_offset += entry.Length
                message_id += 1


# ── Standalone substitution helper ───────────────────────────────────

def _apply_substitutions(template: str, substitutions: tuple[str, ...]) -> str:
    """Replace ``%1``..``%n`` placeholders with *substitutions*.

    ``%%`` is converted to a single ``%``.  A ``%n`` whose index exceeds the
    number of supplied substitutions is left unchanged in the output.
    """
    def replacer(m: re.Match) -> str:
        if m.group(0) == "%%":
            return "%"
        idx = int(m.group(1))  # 1-based
        if 1 <= idx <= len(substitutions):
            return substitutions[idx - 1]
        return m.group(0)  # leave unresolved insert intact

    return _INSERT_RE.sub(replacer, template)
