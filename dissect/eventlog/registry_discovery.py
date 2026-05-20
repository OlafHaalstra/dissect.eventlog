from __future__ import annotations

import os
import re
import sys
from pathlib import Path


# Registry key path under HKLM that holds EventLog source registrations
_EVENTLOG_KEY = r"SYSTEM\CurrentControlSet\Services\EventLog"

# Environment variable placeholders found in EventMessageFile values
_ENV_VAR_RE = re.compile(r"%([^%]+)%")


# ── Live registry discovery (Windows only) ───────────────────────────

def discover_event_sources_live() -> dict[str, list[str]]:
    """Read ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog`` from the
    live Windows registry and return a mapping of::

        {source_name: [raw_dll_path, ...]}

    The returned paths may contain environment variable placeholders such as
    ``%SystemRoot%``; use :func:`expand_registry_path` to resolve them.

    Raises
    ------
    ImportError
        When called on a non-Windows platform where ``winreg`` is unavailable.
    """
    if sys.platform != "win32":
        raise ImportError("Live registry access is only supported on Windows")

    import winreg  # noqa: PLC0415 — intentional conditional import

    result: dict[str, list[str]] = {}

    try:
        eventlog_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            _EVENTLOG_KEY,
            access=winreg.KEY_READ,
        )
    except OSError:
        return result

    with eventlog_key:
        log_count = winreg.QueryInfoKey(eventlog_key)[0]
        for log_idx in range(log_count):
            log_name = winreg.EnumKey(eventlog_key, log_idx)
            try:
                log_key = winreg.OpenKey(eventlog_key, log_name, access=winreg.KEY_READ)
            except OSError:
                continue

            with log_key:
                source_count = winreg.QueryInfoKey(log_key)[0]
                for src_idx in range(source_count):
                    source_name = winreg.EnumKey(log_key, src_idx)
                    try:
                        src_key = winreg.OpenKey(log_key, source_name, access=winreg.KEY_READ)
                    except OSError:
                        continue

                    with src_key:
                        try:
                            raw_value, _ = winreg.QueryValueEx(src_key, "EventMessageFile")
                        except OSError:
                            continue

                    paths = [p.strip() for p in raw_value.split(";") if p.strip()]
                    if paths:
                        result[source_name] = paths

    return result


# ── Offline registry discovery (dissect.target) ──────────────────────

def discover_event_sources_offline(registry_plugin) -> dict[str, list[str]]:
    """Read ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\EventLog`` from an
    offline registry hive via a ``dissect.target`` ``RegistryPlugin``.

    Parameters
    ----------
    registry_plugin:
        A ``dissect.target.plugins.os.windows.registry.RegistryPlugin``
        (or compatible) instance.

    Returns
    -------
    dict[str, list[str]]
        ``{source_name: [raw_dll_path, ...]}``
    """
    result: dict[str, list[str]] = {}

    base_key_path = f"HKLM\\{_EVENTLOG_KEY}"

    try:
        eventlog_key = registry_plugin.key(base_key_path)
    except Exception:
        return result

    for log_key in eventlog_key.subkeys():
        for src_key in log_key.subkeys():
            source_name = src_key.name
            try:
                raw_value = src_key.value("EventMessageFile").value
            except Exception:
                continue

            paths = [p.strip() for p in raw_value.split(";") if p.strip()]
            if paths:
                result[source_name] = paths

    return result


# ── Path expansion ───────────────────────────────────────────────────

def expand_registry_path(path: str, os_root: str | None = None) -> list[str]:
    """Expand environment variable placeholders in a registry path value.

    Handles the common Windows pattern ``%SystemRoot%\\system32\\foo.dll``
    as well as multiple semicolon-separated paths in a single value.

    Parameters
    ----------
    path:
        A single path string, possibly containing ``%VAR%`` placeholders.
        May contain multiple paths separated by ``';'``.
    os_root:
        Override for ``%SystemRoot%`` / ``%windir%``.  Useful when
        processing offline images where the Windows root differs from the
        analyst machine's ``%SystemRoot%``.

    Returns
    -------
    list[str]
        Expanded path strings (one per semicolon-separated component).
    """
    expanded_paths: list[str] = []

    for raw in path.split(";"):
        raw = raw.strip()
        if not raw:
            continue

        def _replace_var(m: re.Match) -> str:
            var = m.group(1).lower()
            if var in ("systemroot", "windir") and os_root is not None:
                return os_root
            # Fall back to real environment variables (live system or partial image)
            env_val = os.environ.get(m.group(1)) or os.environ.get(var)
            if env_val:
                return env_val
            return m.group(0)  # leave unexpanded if unknown

        expanded = _ENV_VAR_RE.sub(_replace_var, raw)
        expanded_paths.append(expanded)

    return expanded_paths
