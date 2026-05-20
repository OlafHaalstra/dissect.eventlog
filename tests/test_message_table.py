from __future__ import annotations

import io
import struct
from pathlib import Path
from typing import TYPE_CHECKING
from unittest.mock import MagicMock

import pytest

from dissect.eventlog.message_table import MessageTable, _apply_substitutions
from dissect.eventlog.message_resolver import MessageResolver
from dissect.eventlog.pe import PEFile, PEError, ResourceNotFoundError
from dissect.eventlog.registry_discovery import expand_registry_path

if TYPE_CHECKING:
    from collections.abc import Callable

# ── sxproxy.dll known message IDs ─────────────────────────────────────
# These are VSS proxy messages from C:\Windows\System32\sxproxy.dll.
# The DLL uses MUI architecture — RT_MESSAGETABLE lives in en-US\sxproxy.dll.mui.
# from_path(sxproxy.dll) auto-discovers the MUI sidecar.
#
# full_id = (Qualifiers << 16) | EventID
#   0x3001 → Qualifiers=0,      EventID=0x3001 (12289)
#   0x3002 → Qualifiers=0,      EventID=0x3002 (12290)
#   0xC0003005 → Qualifiers=0xC000 (49152), EventID=0x3005 (12293)
SXPROXY_MSG_SIMPLE     = 0x3001   # "MesEncodeIncrementalHandleCreate()\r\n"
SXPROXY_MSG_WITH_INSERT = 0x3002  # "Error during RPC serialization: (%1)\r\n"
SXPROXY_MSG_ERROR      = 0xC0003005  # "A system error prevented the operation from proceeding.\r\n"

# ── SPP known message IDs (used for the MUI-fallback test) ────────────
# EventID=16394, Qualifiers=49152  →  full_id = (0xC000 << 16) | 0x400A = 0xC000400A
SPP_MSG_OFFLINE_MIGRATION = 0xC000400A
# EventID=16384, Qualifiers=16384  →  full_id = (0x4000 << 16) | 0x4000 = 0x40004000
SPP_MSG_SCHEDULED_RESTART = 0x40004000


# ── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture()
def sxproxy_path(get_absolute_path: Callable[[str], Path]) -> Path:
    path = get_absolute_path("_data/sxproxy.dll")
    if not path.exists():
        pytest.skip("sxproxy.dll test fixture not available")
    return path


@pytest.fixture()
def sppsvc_exe_path(get_absolute_path: Callable[[str], Path]) -> Path:
    path = get_absolute_path("_data/sppsvc.exe")
    if not path.exists():
        pytest.skip("sppsvc.exe test fixture not available")
    return path


@pytest.fixture()
def sxproxy_mui_path(get_absolute_path: Callable[[str], Path]) -> Path:
    """sxproxy.dll MUI file — has RT_MESSAGETABLE directly."""
    path = get_absolute_path("_data/en-US/sxproxy.dll.mui")
    if not path.exists():
        pytest.skip("sxproxy.dll.mui test fixture not available")
    return path


@pytest.fixture()
def sppsvc_mui_path(get_absolute_path: Callable[[str], Path]) -> Path:
    path = get_absolute_path("_data/en-US/sppsvc.exe.mui")
    if not path.exists():
        pytest.skip("sppsvc.exe.mui test fixture not available")
    return path


@pytest.fixture()
def message_table(sxproxy_path: Path) -> MessageTable:
    """MessageTable loaded via from_path() — uses MUI fallback for sxproxy.dll."""
    return MessageTable.from_path(sxproxy_path)


@pytest.fixture()
def resolver(sxproxy_path: Path) -> MessageResolver:
    return MessageResolver([sxproxy_path])

class TestPEFile:
    def test_parses_valid_dll(self, sxproxy_path: Path) -> None:
        with sxproxy_path.open("rb") as fh:
            pe = PEFile(fh)
        assert pe.resource_directory_rva != 0

    def test_rejects_non_pe(self) -> None:
        fh = io.BytesIO(b"\x00" * 512)
        with pytest.raises(PEError):
            PEFile(fh)

    def test_rejects_bad_mz(self) -> None:
        fh = io.BytesIO(b"ZM" + b"\x00" * 510)
        with pytest.raises(PEError):
            PEFile(fh)

    def test_rva_to_offset_valid(self, sxproxy_path: Path) -> None:
        with sxproxy_path.open("rb") as fh:
            pe = PEFile(fh)
        rsrc_rva = pe.resource_directory_rva
        offset = pe.rva_to_offset(rsrc_rva)
        assert offset > 0

    def test_rva_to_offset_invalid(self, sxproxy_path: Path) -> None:
        with sxproxy_path.open("rb") as fh:
            pe = PEFile(fh)
        with pytest.raises(PEError):
            pe.rva_to_offset(0x7FFFFFFF)

    def test_get_resource_rt_messagetable(self, sxproxy_mui_path: Path) -> None:
        """RT_MESSAGETABLE is in the MUI file, not the base DLL."""
        with sxproxy_mui_path.open("rb") as fh:
            pe = PEFile(fh)
            data = pe.get_resource(11)  # RT_MESSAGETABLE
        assert len(data) > 0
        num_blocks = struct.unpack_from("<I", data)[0]
        assert 1 <= num_blocks <= 256

    def test_get_resource_not_found(self, sxproxy_path: Path) -> None:
        with sxproxy_path.open("rb") as fh:
            pe = PEFile(fh)
            with pytest.raises(ResourceNotFoundError):
                pe.get_resource(999)  # unlikely to exist

    def test_mui_fallback_from_exe(self, sppsvc_exe_path: Path) -> None:
        """from_path() on sppsvc.exe should automatically find the en-US/sppsvc.exe.mui sibling."""
        mt = MessageTable.from_path(sppsvc_exe_path)
        assert mt.messages.get(SPP_MSG_OFFLINE_MIGRATION) is not None


# ── MessageTable tests ─────────────────────────────────────────────────

class TestMessageTable:
    def test_from_path_returns_messages(self, message_table: MessageTable) -> None:
        assert len(message_table.messages) > 0

    def test_known_message_simple(self, message_table: MessageTable) -> None:
        msg = message_table.messages.get(SXPROXY_MSG_SIMPLE)
        assert msg is not None
        assert "MesEncodeIncrementalHandleCreate" in msg

    def test_known_message_with_insert(self, message_table: MessageTable) -> None:
        msg = message_table.messages.get(SXPROXY_MSG_WITH_INSERT)
        assert msg is not None
        assert "%1" in msg

    def test_known_message_error(self, message_table: MessageTable) -> None:
        msg = message_table.messages.get(SXPROXY_MSG_ERROR)
        assert msg is not None
        assert "system error" in msg

    def test_format_message_no_args(self, message_table: MessageTable) -> None:
        result = message_table.format_message(SXPROXY_MSG_SIMPLE)
        assert result is not None
        assert "MesEncodeIncrementalHandleCreate" in result

    def test_format_message_with_substitution(self, message_table: MessageTable) -> None:
        result = message_table.format_message(SXPROXY_MSG_WITH_INSERT, "0x80070005")
        assert result is not None
        assert "0x80070005" in result
        assert "%1" not in result

    def test_format_message_unknown_id_returns_none(self, message_table: MessageTable) -> None:
        result = message_table.format_message(0xDEADBEEF)
        assert result is None

    def test_messages_are_strings(self, message_table: MessageTable) -> None:
        for msg_id, text in message_table.messages.items():
            assert isinstance(msg_id, int)
            assert isinstance(text, str)

    def test_from_dll_file_object(self, sxproxy_mui_path: Path) -> None:
        """from_dll() reads RT_MESSAGETABLE directly — uses the MUI file."""
        with sxproxy_mui_path.open("rb") as fh:
            table = MessageTable.from_dll(fh)
        assert len(table.messages) > 0

    def test_mui_fallback_sppsvc(self, sppsvc_exe_path: Path) -> None:
        """from_path() on sppsvc.exe falls back to en-US/sppsvc.exe.mui automatically."""
        mt = MessageTable.from_path(sppsvc_exe_path)
        assert "Offline downlevel migration succeeded" in mt.messages.get(SPP_MSG_OFFLINE_MIGRATION, "")
        template = mt.messages.get(SPP_MSG_SCHEDULED_RESTART, "")
        assert "%1" in template
        assert "%2" in template


# ── _apply_substitutions unit tests ───────────────────────────────────

class TestApplySubstitutions:
    def test_single_substitution(self) -> None:
        assert _apply_substitutions("Hello %1!", ("World",)) == "Hello World!"

    def test_multiple_substitutions(self) -> None:
        result = _apply_substitutions("Restart at %1. Reason: %2.", ("2026-01-01Z", "RulesEngine"))
        assert result == "Restart at 2026-01-01Z. Reason: RulesEngine."

    def test_percent_escape(self) -> None:
        assert _apply_substitutions("100%%", ()) == "100%"

    def test_out_of_range_index_preserved(self) -> None:
        # %2 is out of range when only one substitution is supplied
        result = _apply_substitutions("%1 and %2", ("only_one",))
        assert "only_one" in result
        assert "%2" in result

    def test_no_substitutions_in_template(self) -> None:
        template = "No placeholders here.\r\n"
        assert _apply_substitutions(template, ("unused",)) == template


# ── MessageResolver tests ──────────────────────────────────────────────

class TestMessageResolver:
    def test_resolve_known_event_no_data(self, resolver: MessageResolver) -> None:
        # EventID=0x3001 (12289), Qualifiers=0 → full_id=0x3001
        result = resolver.resolve(0x3001, 0, [])
        assert result is not None
        assert "MesEncodeIncrementalHandleCreate" in result

    def test_resolve_with_data(self, resolver: MessageResolver) -> None:
        # EventID=0x3002 (12290), Qualifiers=0 → full_id=0x3002
        result = resolver.resolve(0x3002, 0, ["0x80070005"])
        assert result is not None
        assert "0x80070005" in result
        assert "%1" not in result

    def test_resolve_error_severity(self, resolver: MessageResolver) -> None:
        # EventID=0x3005 (12293), Qualifiers=0xC000 (49152) → full_id=0xC0003005
        result = resolver.resolve(0x3005, 0xC000, [])
        assert result is not None
        assert "system error" in result

    def test_resolve_unknown_event_returns_none(self, resolver: MessageResolver) -> None:
        result = resolver.resolve(0xBEEF, 0xDEAD, [])
        assert result is None

    def test_from_dll_file_object(self, sxproxy_mui_path: Path) -> None:
        """from_dll_file() reads RT_MESSAGETABLE directly — uses the MUI file."""
        with sxproxy_mui_path.open("rb") as fh:
            r = MessageResolver.from_dll_file(fh)
        assert len(r.get_all_messages()) > 0

    def test_get_all_messages_returns_copy(self, resolver: MessageResolver) -> None:
        msgs = resolver.get_all_messages()
        msgs[0] = "tampered"
        # Should not affect the resolver's internal state
        assert resolver.get_all_messages().get(0) != "tampered"

    def test_invalid_dll_silently_skipped(self, tmp_path: Path) -> None:
        bad_dll = tmp_path / "bad.dll"
        bad_dll.write_bytes(b"\x00" * 512)
        r = MessageResolver([bad_dll])
        assert len(r.get_all_messages()) == 0

    def test_missing_dll_silently_skipped(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.dll"
        r = MessageResolver([missing])
        assert len(r.get_all_messages()) == 0


# ── registry_discovery unit tests (mocked) ────────────────────────────

class TestExpandRegistryPath:
    def test_system_root_expansion_live(self) -> None:
        import os
        system_root = os.environ.get("SystemRoot", "C:\\Windows")
        result = expand_registry_path(f"%SystemRoot%\\system32\\foo.dll")
        assert result == [f"{system_root}\\system32\\foo.dll"]

    def test_custom_os_root(self) -> None:
        result = expand_registry_path(
            "%SystemRoot%\\system32\\foo.dll",
            os_root="D:\\mnt\\Windows",
        )
        assert result == ["D:\\mnt\\Windows\\system32\\foo.dll"]

    def test_semicolon_separated_paths(self) -> None:
        result = expand_registry_path(
            "%SystemRoot%\\system32\\a.dll;%SystemRoot%\\system32\\b.dll",
            os_root="C:\\Windows",
        )
        assert result == [
            "C:\\Windows\\system32\\a.dll",
            "C:\\Windows\\system32\\b.dll",
        ]

    def test_empty_string(self) -> None:
        assert expand_registry_path("") == []

    def test_no_placeholders(self) -> None:
        result = expand_registry_path("C:\\Windows\\system32\\foo.dll")
        assert result == ["C:\\Windows\\system32\\foo.dll"]


class TestDiscoverEventSourcesLive:
    def test_returns_dict(self) -> None:
        pytest.importorskip("winreg")
        from dissect.eventlog.registry_discovery import discover_event_sources_live

        result = discover_event_sources_live()
        assert isinstance(result, dict)
        # Every value is a non-empty list of strings
        for source, paths in result.items():
            assert isinstance(source, str)
            assert isinstance(paths, list)
            assert all(isinstance(p, str) for p in paths)

    def test_finds_spp_service(self) -> None:
        pytest.importorskip("winreg")
        from dissect.eventlog.registry_discovery import discover_event_sources_live

        result = discover_event_sources_live()
        assert "Software Protection Platform Service" in result


class TestDiscoverEventSourcesOffline:
    def test_uses_registry_plugin(self) -> None:
        from dissect.eventlog.registry_discovery import discover_event_sources_offline

        # Build a minimal mock that mimics the dissect.target RegistryPlugin interface
        mock_plugin = MagicMock()

        src_key = MagicMock()
        src_key.name = "MockSource"
        src_key.value.return_value.value = "%SystemRoot%\\system32\\mock.dll"
        src_key.subkeys.return_value = []

        log_key = MagicMock()
        log_key.subkeys.return_value = [src_key]

        eventlog_key = MagicMock()
        eventlog_key.subkeys.return_value = [log_key]

        mock_plugin.key.return_value = eventlog_key

        result = discover_event_sources_offline(mock_plugin)
        assert "MockSource" in result
        assert result["MockSource"] == ["%SystemRoot%\\system32\\mock.dll"]

    def test_handles_missing_eventmessagefile(self) -> None:
        from dissect.eventlog.registry_discovery import discover_event_sources_offline

        mock_plugin = MagicMock()

        src_key = MagicMock()
        src_key.name = "NoMsgFileSource"
        src_key.value.side_effect = Exception("value not found")
        src_key.subkeys.return_value = []

        log_key = MagicMock()
        log_key.subkeys.return_value = [src_key]

        eventlog_key = MagicMock()
        eventlog_key.subkeys.return_value = [log_key]

        mock_plugin.key.return_value = eventlog_key

        result = discover_event_sources_offline(mock_plugin)
        assert "NoMsgFileSource" not in result

    def test_handles_registry_access_error(self) -> None:
        from dissect.eventlog.registry_discovery import discover_event_sources_offline

        mock_plugin = MagicMock()
        mock_plugin.key.side_effect = Exception("registry not found")

        result = discover_event_sources_offline(mock_plugin)
        assert result == {}
