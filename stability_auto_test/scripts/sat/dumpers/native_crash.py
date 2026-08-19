"""Native crash dumper.

Writes raw logcat slice + structured incident JSON.
Best-effort: tries to pull a tombstone from `/data/tombstones/` (root-only on
user builds). On failure, records `fallback_reason` and continues.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, Optional

from ..adb import Adb, AdbError
from ..detection import StabilityEvent
from ..evidence.trace_matcher import match_trace, verify_local_trace
from . import (
    base_name_for,
    build_incident_dict,
    fetch_and_write_dropbox,
    write_incident,
    write_raw_slice,
)

log = logging.getLogger(__name__)


def _recover_tombstone_from_dropbox(
    dropbox_path: Path,
    tombstone_path: Path,
    event: StabilityEvent,
) -> tuple[bool, str]:
    """Persist a verified SYSTEM_TOMBSTONE DropBox body as tombstone evidence."""
    try:
        body = dropbox_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return False, f"dropbox tombstone unreadable: {exc}"
    required_markers = ("*** *** ***", "signal ", "backtrace:")
    if not all(marker in body for marker in required_markers):
        return False, "dropbox entry is not a complete tombstone"
    try:
        tombstone_path.write_text(body, encoding="utf-8")
    except OSError as exc:
        return False, f"could not persist dropbox tombstone: {exc}"
    ok, reason = verify_local_trace(tombstone_path, event)
    if not ok:
        try:
            tombstone_path.unlink()
        except OSError:
            pass
    return ok, reason


def run(
    adb: Adb,
    event: StabilityEvent,
    incidents_dir: Path,
    *,
    pull_tombstone: bool = True,
    ctx=None,
    staging_dir: Optional[Path] = None,
    fetcher=None,
) -> Dict:
    target = staging_dir or incidents_dir
    target.mkdir(parents=True, exist_ok=True)
    base = base_name_for(event)
    slice_path = target / f"{base}.txt"
    tombstone_path = target / f"{base}.tombstone"
    json_path = target / f"{base}.json"

    slice_name = write_raw_slice(slice_path, event)
    trace_name: Optional[str] = None
    fallback: Optional[str] = None
    match_info: Dict = {
        "evidence_match_confidence": "none",
        "evidence_match_reasons": [],
        "trace_verified": False,
    }

    if pull_tombstone:
        if ctx is not None:
            ctx.check()
        match = match_trace(
            adb,
            event,
            "/data/tombstones/",
            timeout=ctx.timeout_for(30.0) if ctx is not None else 30.0,
        )
        match_info["evidence_match_confidence"] = match.confidence
        match_info["evidence_match_reasons"] = list(match.reasons)
        if not match.bound:
            fallback = "no_confident_match"
        else:
            remote = match.candidate.path
            try:
                if ctx is not None:
                    ctx.check()
                adb.pull(
                    remote,
                    str(tombstone_path),
                    check=True,
                    timeout=ctx.timeout_for(30.0) if ctx is not None else 30.0,
                )
                if tombstone_path.exists() and tombstone_path.stat().st_size > 0:
                    ok, reason = verify_local_trace(tombstone_path, event)
                    match_info["trace_verified"] = ok
                    if not ok:
                        # Verification failed: quarantine the file and drop
                        # the evidence reference (IMP-05 / T-L0-013).
                        match_info["trace_verify_reason"] = reason
                        match_info["evidence_match_confidence"] = "low"
                        quarantine = target / f"{tombstone_path.name}.unverified"
                        try:
                            tombstone_path.rename(quarantine)
                        except OSError:
                            try:
                                tombstone_path.unlink()
                            except OSError:
                                pass
                        fallback = "verification_failed"
                    else:
                        trace_name = tombstone_path.name
                else:
                    fallback = "tombstone pull produced empty file"
            except AdbError as e:
                fallback = f"tombstone pull failed: {e}"
    else:
        fallback = "tombstone pull disabled by config"

    dropbox_name = fetch_and_write_dropbox(adb, event, target, base, ctx=ctx, fetcher=fetcher)
    if pull_tombstone and trace_name is None and dropbox_name:
        ok, reason = _recover_tombstone_from_dropbox(
            target / dropbox_name,
            tombstone_path,
            event,
        )
        match_info["trace_verify_reason"] = reason
        if ok:
            trace_name = tombstone_path.name
            fallback = None
            match_info["trace_verified"] = True
            match_info["trace_source"] = "dropbox"
            match_info["evidence_match_confidence"] = "high"
            match_info["evidence_match_reasons"] = list(
                dict.fromkeys(
                    [*match_info["evidence_match_reasons"], "dropbox_tombstone_body"]
                )
            )
    incident = build_incident_dict(
        event,
        logcat_slice_file=slice_name,
        trace_file=trace_name,
        fallback_reason=fallback,
        dropbox_file=dropbox_name,
        extra_evidence=match_info,
    )
    write_incident(json_path, incident)
    log.info(
        "native_crash incident written: %s (trace=%s, dropbox=%s)",
        json_path.name,
        trace_name,
        dropbox_name,
    )
    return incident
