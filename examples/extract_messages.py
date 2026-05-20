#!/usr/bin/env python
"""extract_messages.py — Extract Windows Event Log message templates from DLL/EXE/MUI files.

Usage examples::

    # Extract all messages from a single DLL (with automatic MUI fallback):
    python extract_messages.py C:\\Windows\\System32\\sppsvc.exe

    # Discover all registered EventMessageFile DLLs on the live system:
    python extract_messages.py --registry

    # Discover and then extract from every registered source:
    python extract_messages.py --registry --extract

    # Output as a flat Python repr instead of JSON (useful for copy-paste):
    python extract_messages.py C:\\Windows\\System32\\en-US\\sppsvc.exe.mui --format repr
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def extract_from_path(path: str | Path) -> dict[str, str]:
    """Return ``{hex_message_id: template_string}`` for every message in *path*.

    Automatically falls back to the companion ``.mui`` file when the base
    binary has no ``RT_MESSAGETABLE`` resource.
    """
    from dissect.eventlog.message_table import MessageTable
    from dissect.eventlog.pe import ResourceNotFoundError

    mt = MessageTable.from_path(path)
    return {hex(msg_id): text for msg_id, text in sorted(mt.messages.items())}


def discover_sources() -> dict[str, list[str]]:
    """Return ``{source_name: [raw_dll_path, ...]}`` from the live registry."""
    from dissect.eventlog.registry_discovery import discover_event_sources_live

    return discover_event_sources_live()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Extract Windows Event Log message templates from DLL/EXE/MUI files.",
    )
    parser.add_argument(
        "path",
        nargs="?",
        help="Path to a DLL, EXE, or MUI file to extract messages from.",
    )
    parser.add_argument(
        "--registry",
        action="store_true",
        help="Discover all EventMessageFile DLLs from the live Windows registry.",
    )
    parser.add_argument(
        "--extract",
        action="store_true",
        help="When combined with --registry, also extract messages from every discovered DLL.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "repr"],
        default="json",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "--source",
        metavar="NAME",
        help="When used with --registry --extract, limit to a single source name.",
    )

    args = parser.parse_args(argv)

    if not args.path and not args.registry:
        parser.print_help()
        return 1

    if args.registry:
        sources = discover_sources()

        if not args.extract:
            # Just list the discovered sources and their DLL paths
            _emit(
                {name: paths for name, paths in sorted(sources.items())},
                args.format,
            )
            return 0

        # Extract messages for each source
        from dissect.eventlog.registry_discovery import expand_registry_path
        from dissect.eventlog.pe import ResourceNotFoundError

        result: dict[str, dict[str, str]] = {}
        items = (
            [(args.source, sources[args.source])]
            if args.source and args.source in sources
            else sorted(sources.items())
        )
        for source_name, raw_paths in items:
            messages: dict[str, str] = {}
            for raw in raw_paths:
                for expanded in expand_registry_path(raw):
                    p = Path(expanded)
                    try:
                        messages.update(extract_from_path(p))
                    except (FileNotFoundError, ResourceNotFoundError, Exception):
                        pass
            if messages:
                result[source_name] = messages

        _emit(result, args.format)
        return 0

    # Single DLL/MUI extraction
    try:
        messages = extract_from_path(args.path)
    except FileNotFoundError:
        print(f"error: file not found: {args.path}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    _emit(messages, args.format)
    return 0


def _emit(data: object, fmt: str) -> None:
    if fmt == "repr":
        print(repr(data))
    else:
        print(json.dumps(data, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    sys.exit(main())
