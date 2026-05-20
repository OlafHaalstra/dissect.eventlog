"""Extract and display WEVT_TEMPLATE provider metadata from a PE file.

The WEVT_TEMPLATE named resource is embedded in DLLs/EXEs that define Windows
event providers (via the Event Manifest / mc.exe toolchain).  It contains the
full provider schema: channels, levels, tasks, opcodes, keywords and – most
usefully – the EVNT table that maps every event ID to its metadata.

Usage
-----
    python extract_wevt.py <path-to-dll>
    python extract_wevt.py C:\\Windows\\System32\\wevtapi.dll

The EVNT table entries pair event IDs with their ``message_table_id``
(the same ID you would look up in RT_MESSAGETABLE via MessageTable) so the two
resources work together: WEVT_TEMPLATE describes *what* each event is, and
RT_MESSAGETABLE holds the human-readable message string templates.
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path

from dissect.eventlog.pe import PEFile, ResourceNotFoundError
from dissect.eventlog.wevt import wevt


def extract_wevt_from_pe(path: Path) -> wevt.CRIM:
    """Return a parsed CRIM object from the WEVT_TEMPLATE resource in *path*."""
    with path.open("rb") as fh:
        pe = PEFile(fh)
        raw = pe.get_named_resource("WEVT_TEMPLATE")
    return wevt.CRIM(io.BytesIO(raw))


def print_provider(crim: wevt.CRIM, *, show_events: bool = True) -> None:
    for provider in crim.wevt_headers():
        print(f"\nProvider  {provider.provider_id}")
        print(f"  Payload size : {provider.payload_size} bytes")
        print(f"  Type tables  : {provider.len_types}")

        for wevt_type in provider:
            sig = wevt_type.signature
            items = list(wevt_type)
            print(f"\n  [{sig}]  ({len(items)} entries)")

            if sig == "EVNT" and show_events:
                for evt in items:
                    msg_id = f"0x{evt.message_table_id:08X}" if evt.message_table_id != 0xFFFFFFFF else "(none)"
                    print(
                        f"    id={evt.id:<5}  ver={evt.version}"
                        f"  level={evt.level}  task={evt.task}"
                        f"  opcode={evt.opcode}  msg={msg_id}"
                    )
            else:
                for item in items:
                    print(f"    {item}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract WEVT_TEMPLATE provider metadata from a PE file."
    )
    parser.add_argument("dll", metavar="DLL", help="Path to a PE file containing WEVT_TEMPLATE")
    parser.add_argument(
        "--no-events",
        action="store_true",
        help="Skip printing the EVNT table (can be large)",
    )
    args = parser.parse_args()

    path = Path(args.dll)
    try:
        crim = extract_wevt_from_pe(path)
    except ResourceNotFoundError:
        print(f"No WEVT_TEMPLATE resource found in: {path}")
        raise SystemExit(1)
    except Exception as exc:  # noqa: BLE001
        print(f"Failed to parse {path}: {exc}")
        raise SystemExit(1)

    print(f"File   : {path}")
    print(f"Providers in CRIM: {len(crim.header.event_providers)}")
    print_provider(crim, show_events=not args.no_events)


if __name__ == "__main__":
    main()
