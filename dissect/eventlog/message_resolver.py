from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO

from dissect.eventlog.message_table import MessageTable

if TYPE_CHECKING:
    pass


class MessageResolver:
    """Resolve Windows Event Log EventIDs to human-readable message strings.

    A resolver is constructed from one or more event message DLLs.  On
    construction each DLL's ``RT_MESSAGETABLE`` is parsed and the resulting
    ``{full_message_id: template}`` dictionaries are merged; later DLLs take
    precedence for duplicate IDs (mirrors the behaviour of the Windows Event
    Log service).

    The *full 32-bit message identifier* stored in ``RT_MESSAGETABLE`` is::

        full_id = (Qualifiers << 16) | EventID

    where *Qualifiers* and *EventID* match the values in the ``<EventID
    Qualifiers="…">…</EventID>`` element of an EVTX/EVTLOG XML record.

    Parameters
    ----------
    dll_paths:
        One or more paths to event-message DLLs (resolved in order).
    """

    def __init__(self, dll_paths: list[str | Path]) -> None:
        self._messages: dict[int, str] = {}
        for path in dll_paths:
            try:
                table = MessageTable.from_path(path)
                self._messages.update(table.messages)
            except Exception:
                # Skip DLLs that cannot be parsed (missing file, wrong format, …)
                pass

    # ── Public API ───────────────────────────────────────────────────

    @classmethod
    def from_dll_file(cls, fh: BinaryIO) -> "MessageResolver":
        """Construct a resolver from a single already-opened DLL file object.

        Parameters
        ----------
        fh:
            Seekable binary file-like object.
        """
        table = MessageTable.from_dll(fh)
        instance = cls.__new__(cls)
        instance._messages = dict(table.messages)
        return instance

    def resolve(
        self,
        event_id: int,
        qualifiers: int,
        data: list[str] | None = None,
    ) -> str | None:
        """Resolve an event to its formatted message string.

        Parameters
        ----------
        event_id:
            The numeric EventID (lower 16 bits of the full message ID).
        qualifiers:
            The Qualifiers value from the EVTX/EVT record (upper 16 bits).
        data:
            Ordered list of EventData insertion strings (``%1`` → ``data[0]``,
            ``%2`` → ``data[1]``, …).

        Returns
        -------
        str | None
            The formatted message, or ``None`` if the ID is not found.
        """
        full_id = ((qualifiers & 0xFFFF) << 16) | (event_id & 0xFFFF)
        template = self._messages.get(full_id)
        if template is None:
            return None
        from dissect.eventlog.message_table import _apply_substitutions
        return _apply_substitutions(template, tuple(data or []))

    def get_all_messages(self) -> dict[int, str]:
        """Return a copy of the raw ``{full_message_id: template}`` mapping."""
        return dict(self._messages)

    @classmethod
    def from_registry(
        cls,
        source_name: str,
        registry_plugin=None,
        os_root: str | None = None,
    ) -> "MessageResolver":
        """Construct a resolver by discovering DLL paths from the registry.

        Parameters
        ----------
        source_name:
            The EventLog source name (e.g. ``"Software Protection Platform Service"``).
        registry_plugin:
            A ``dissect.target`` ``RegistryPlugin`` for offline hive lookups.
            When ``None`` the live Windows registry is used via ``winreg``.
        os_root:
            Override for ``%SystemRoot%`` expansion (used with offline hives).
        """
        from dissect.eventlog.registry_discovery import (
            discover_event_sources_live,
            discover_event_sources_offline,
            expand_registry_path,
        )

        if registry_plugin is not None:
            sources = discover_event_sources_offline(registry_plugin)
        else:
            sources = discover_event_sources_live()

        raw_paths = sources.get(source_name, [])
        resolved = []
        for raw in raw_paths:
            for path in expand_registry_path(raw, os_root):
                p = Path(path)
                if p.exists():
                    resolved.append(p)

        return cls(resolved)
