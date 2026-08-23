"""Build the canonical structured report (`report.json`).

Reads issue evidence from the run's output directory and returns the result
dict that all other report formats render from. Process lifecycle artifacts
may still exist for runtime orchestration, but are excluded from reporting.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..analyzers.exit_correlation import correlate_exit_info
from ..analyzers.fingerprint import ISSUE_EVENT_TYPES, group_incidents
from ..atomic_io import atomic_write_json
from ..collectors.resource_risk import correlate_resource_risk
from ..health import compute_verdict
from ..journal import (
    JOURNAL_FILENAME,
    STATUS_DETECTED,
    STATUS_DROPPED_BY_BACKPRESSURE,
    STATUS_DROPPED_BY_CAP,
    STATUS_FAILED,
    STATUS_PERSISTED,
    STATUS_TIMED_OUT,
    read_journal,
)
from ..policy import evaluate_policy, policy_from_dict

log = logging.getLogger(__name__)

SCHEMA_VERSION = "1.17"
REPORT_FILENAME = "report.json"


def _iso(ts: Optional[datetime]) -> Optional[str]:
    if ts is None:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return ts.isoformat(timespec="milliseconds").replace("T", " ").replace("+00:00", "")


def _load_incidents(incidents_dir: Path) -> List[Dict]:
    if not incidents_dir.exists():
        return []
    out: List[Dict] = []
    for json_file in sorted(incidents_dir.glob("*.json")):
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            log.warning("skipping unreadable incident %s: %s", json_file, e)
            continue
        if not isinstance(data, dict):
            continue
        if "type" not in data or "process" not in data:
            continue
        data["_source_file"] = json_file.name
        out.append(data)
    out.sort(key=lambda d: d.get("triggered_at", ""))
    return out


def _restore_evidence_file_references(incidents: List[Dict], incidents_dir: Path) -> None:
    """Reconcile incident metadata with evidence files already on disk.

    Older occurrence-sampling logic removed references after dumpers had
    already written the files, leaving valid evidence orphaned and invisible
    in HTML. The report is the disk inventory, so existing files win.
    """
    for incident in incidents:
        source_file = incident.get("_source_file")
        if not source_file:
            continue
        base = Path(str(source_file)).stem
        evidence = incident.setdefault("evidence", {})
        specs = [
            ("logcat_slice_file", f"{base}.txt"),
            ("dropbox_file", f"{base}_dropbox.txt"),
            ("context_file", f"{base}_context.txt"),
        ]
        if incident.get("type") == "native_crash":
            specs.append(("trace_file", f"{base}.tombstone"))
        elif incident.get("type") == "anr":
            specs.append(("trace_file", f"{base}.trace"))
        recovered = []
        for field, filename in specs:
            if evidence.get(field):
                continue
            if (incidents_dir / filename).is_file():
                evidence[field] = filename
                recovered.append(field)
        if recovered:
            evidence["recovered_file_references"] = recovered
            if incident.get("type") in ("java_crash", "native_crash", "anr"):
                evidence["sampled"] = False
                evidence["sample_reason"] = "full_evidence_present"


def _journal_counts(records: List[Dict]) -> Dict[str, int]:
    """Fold journal records by event_id to produce unique terminal-state counts.

    Each event_id may appear multiple times (one ``detected`` record + one or
    more terminal records).  The LAST terminal status wins per event_id so the
    pipeline identity holds:

        detected = persisted + failed + timed_out + dropped_by_cap + dropped_by_backpressure

    If an event_id appears with two different terminal statuses (e.g. timed_out
    followed by persisted) a warning is logged and only the LAST status is
    counted — the report must never double-count a single event.
    """
    detected: set = set()
    # Per-event unique terminal status (last-write-wins).
    terminal_by_event: Dict[str, str] = {}
    for rec in records:
        event_id = rec.get("event_id")
        status = rec.get("status")
        if not event_id:
            continue
        if status == STATUS_DETECTED:
            detected.add(event_id)
            continue
        if status in (
            STATUS_PERSISTED,
            STATUS_FAILED,
            STATUS_TIMED_OUT,
            STATUS_DROPPED_BY_CAP,
            STATUS_DROPPED_BY_BACKPRESSURE,
        ):
            prev = terminal_by_event.get(event_id)
            if prev is not None and prev != status:
                log.warning(
                    "journal event %s has multiple terminal states: %s → %s (using last)",
                    event_id,
                    prev,
                    status,
                )
            terminal_by_event[event_id] = status

    persisted = failed = timed_out = dropped = dropped_bp = 0
    for status in terminal_by_event.values():
        if status == STATUS_PERSISTED:
            persisted += 1
        elif status == STATUS_FAILED:
            failed += 1
        elif status == STATUS_TIMED_OUT:
            timed_out += 1
        elif status == STATUS_DROPPED_BY_CAP:
            dropped += 1
        elif status == STATUS_DROPPED_BY_BACKPRESSURE:
            dropped_bp += 1

    return {
        "detected_count": len(detected),
        "persisted_count": persisted,
        "failed_count": failed,
        "timed_out_count": timed_out,
        "dropped_by_cap_count": dropped,
        "dropped_by_backpressure_count": dropped_bp,
    }


def _issue_journal_records(records: List[Dict]) -> List[Dict]:
    """Keep pipeline accounting scoped to reportable stability issues."""
    issue_event_ids = {
        rec.get("event_id")
        for rec in records
        if rec.get("event_type") != "process_death" and rec.get("event_type") and rec.get("event_id")
    }
    return [rec for rec in records if rec.get("event_id") in issue_event_ids]


def _normalize_reportable_issue(incident: Dict) -> Optional[Dict]:
    incident_type = incident.get("type")
    if incident_type == "process_death":
        return None
    normalized = dict(incident)
    normalized["evidence"] = dict(incident.get("evidence") or {})
    if incident_type not in ISSUE_EVENT_TYPES:
        normalized["type"] = "other"
        normalized["evidence"]["original_type"] = str(incident_type or "unknown")
    evidence = incident.get("evidence") or {}
    if evidence.get("source") != "exit_info":
        return normalized
    # A generic ExitInfo "crashed" record does not prove Java/native root
    # cause. Keep confirmed ANRs and crash records that have a signature.
    if incident.get("type") == "anr":
        return normalized
    if not (
        evidence.get("exception_class")
        or evidence.get("signal")
        or evidence.get("top_frames")
    ):
        return None
    return normalized


def _placeholder_incident(
    rec: Dict,
    evidence_status: str,
    details: Optional[Dict] = None,
) -> Dict:
    src = details or rec
    evidence = {
        "evidence_status": evidence_status,
        "source": src.get("source", "logcat"),
        "reason": "incident evidence not persisted",
    }
    if rec.get("error_type"):
        evidence["error_type"] = rec["error_type"]
    if rec.get("error"):
        evidence["error"] = rec["error"]
    return {
        "event_id": src.get("event_id") or rec.get("event_id"),
        "type": src.get("event_type", "unknown"),
        "process": src.get("process", ""),
        "pid": src.get("pid", 0),
        "triggered_at": src.get("triggered_at", ""),
        "severity": src.get("severity", "error"),
        "summary": src.get("summary", ""),
        "evidence": evidence,
    }


def _build_incidents(
    incidents_dir: Path,
    journal_records: List[Dict],
) -> Tuple[List[Dict], List[str]]:
    """Merge incident JSON evidence with journal event facts.

    Journal records are authoritative for *whether* an event happened; incident
    JSON files supply evidence details. Failed/timed-out/dropped events get a
    placeholder incident so a broken dumper can never make a run look clean.

    Each event_id is folded to a single unique terminal status (last-wins).
    Returns ``(incidents, warnings)``.
    """
    loaded = _load_incidents(incidents_dir)
    by_id: Dict[str, Dict] = {}
    without_id: List[Dict] = []
    for inc in loaded:
        eid = inc.get("event_id")
        if eid:
            by_id[eid] = inc
        else:
            without_id.append(inc)

    incidents: List[Dict] = list(without_id)
    warnings: List[str] = []
    # Fold to unique terminal status per event_id (last-wins).
    terminal_by_event: Dict[str, str] = {}
    terminal_rec_by_event: Dict[str, Dict] = {}
    detected_ids: set = set()
    detected_by_id: Dict[str, Dict] = {}
    for rec in journal_records:
        event_id = rec.get("event_id")
        status = rec.get("status")
        if not event_id:
            continue
        if status == STATUS_DETECTED:
            detected_ids.add(event_id)
            detected_by_id[event_id] = rec
            continue
        terminal_by_event[event_id] = status
        terminal_rec_by_event[event_id] = rec

    for event_id, status in terminal_by_event.items():
        if status == STATUS_DROPPED_BY_CAP:
            continue  # counted in the pipeline, but not an incident

        incident = by_id.pop(event_id, None)
        if incident is None:
            # Map terminal status to a truthful evidence_status.
            if status == STATUS_PERSISTED:
                evidence_status = STATUS_PERSISTED
            elif status == STATUS_FAILED:
                evidence_status = STATUS_FAILED
            elif status == STATUS_DROPPED_BY_BACKPRESSURE:
                evidence_status = STATUS_DROPPED_BY_BACKPRESSURE
            else:
                evidence_status = STATUS_TIMED_OUT

            rec = terminal_rec_by_event[event_id]
            incident = _placeholder_incident(
                rec,
                evidence_status,
                details=detected_by_id.get(event_id),
            )
            if status not in (STATUS_PERSISTED, STATUS_DROPPED_BY_BACKPRESSURE):
                warnings.append(
                    f"incident evidence missing for {event_id} (journal status={status})"
                )
        else:
            evidence = incident.setdefault("evidence", {})
            evidence["evidence_status"] = status
        incident["event_id"] = event_id
        incidents.append(incident)

    # Leftover incident JSONs with no journal record: keep for backward
    # compatibility and mark them persisted (they did make it to disk).
    for incident in by_id.values():
        incident.setdefault("evidence", {}).setdefault("evidence_status", STATUS_PERSISTED)
        incidents.append(incident)

    # Journal entries that never reached a terminal state (e.g. process was
    # killed mid-run): surface them as failed so they cannot be silently lost.
    orphaned = detected_ids - set(terminal_by_event)
    if orphaned:
        warnings.append(f"{len(orphaned)} journal event(s) ended without a terminal status")
        for rec in journal_records:
            eid = rec.get("event_id")
            if eid in orphaned:
                placeholder = _placeholder_incident(
                    rec,
                    STATUS_FAILED,
                    details=detected_by_id.get(eid),
                )
                placeholder["evidence"]["reason"] = (
                    "journal ended before a terminal status was recorded"
                )
                incidents.append(placeholder)
                orphaned.discard(eid)

    incidents.sort(key=lambda d: d.get("triggered_at", ""))
    for i, incident in enumerate(incidents, start=1):
        incident["id"] = f"incident-{i:03d}"
    return incidents, warnings


def build(
    *,
    output_dir: Path,
    package: str,
    started_at: datetime,
    ended_at: datetime,
    device: Dict[str, Any],
    config_effective: Dict[str, Any],
    exit_code: int,
    exit_reason: str,
    bookmarks: Optional[List[Dict]] = None,
    sample_failures: Optional[Dict[str, int]] = None,
    event_pipeline: Optional[Dict[str, int]] = None,
    run_id: Optional[str] = None,
    app_metadata: Optional[Dict] = None,
    exit_info: Optional[List[Dict]] = None,
    device_events: Optional[List[Dict]] = None,
    resource_risk: Optional[List[Dict]] = None,
    self_resource: Optional[Dict] = None,
    collector_health: Optional[Dict] = None,
    collectors: Optional[Dict[str, Dict]] = None,
    policy_config: Optional[Dict] = None,
    ci_mode: bool = False,
    recovered: bool = False,
    recovered_at: Optional[str] = None,
    duration_sec: Optional[float] = None,
    phase_timings: Optional[Dict] = None,
    quota_audit: Optional[List[Dict]] = None,
    capabilities: Optional[List[Dict]] = None,
    source_mode: str = "live",
) -> Dict:
    """Build the canonical report dict.

    `duration_sec`: explicit active runtime (e.g. from `time.monotonic()`
    captured in `api.StabilityTest`). If omitted, falls back to wall-clock
    `(ended_at - started_at)` — which over-counts when the OS suspends the
    process (system sleep). Callers that care about budget fidelity should
    always pass this.
    """
    output_dir = Path(output_dir)
    incidents_dir = output_dir / "incidents"
    event_pipeline = {
        "detected_count": 0,
        "persisted_count": 0,
        "failed_count": 0,
        "timed_out_count": 0,
        "dropped_by_cap_count": 0,
        "dropped_by_backpressure_count": 0,
        **(event_pipeline or {}),
    }

    events_files = sorted(output_dir.glob("events_*.csv"))
    logcat_files = sorted(output_dir.glob("logcat_*.log"))
    journal_path = output_dir / JOURNAL_FILENAME
    journal_records, recovery_warnings = read_journal(journal_path)

    issue_journal = _issue_journal_records(journal_records)
    incidents, incident_warnings = _build_incidents(incidents_dir, issue_journal)
    # Historical runs may contain process-death JSON files. They remain on disk
    # as raw collector evidence but are no longer part of the canonical report.
    incidents = [
        normalized
        for incident in incidents
        if (normalized := _normalize_reportable_issue(incident)) is not None
    ]
    for index, incident in enumerate(incidents, start=1):
        incident["id"] = f"incident-{index:03d}"
    _restore_evidence_file_references(incidents, incidents_dir)
    # DropBox evidence counts as a supporting source for cross-source
    # traceability (spec 4.2: every source that saw the failure is listed).
    for inc in incidents:
        evidence = inc.setdefault("evidence", {})
        sources = list(evidence.get("supporting_sources") or [])
        if evidence.get("dropbox_file") and "dropbox" not in sources:
            sources.append("dropbox")
        if sources:
            evidence["supporting_sources"] = sources
    # ExitInfo is useful internally for strengthening crash/ANR evidence, but
    # process exit records are intentionally not exposed as a report statistic.
    correlate_exit_info(incidents, list(exit_info or []))
    correlate_resource_risk(incidents, list(resource_risk or []))
    issue_groups = group_incidents(incidents)
    by_type = {event_type: 0 for event_type in ISSUE_EVENT_TYPES}
    for group in issue_groups:
        event_type = group.get("type")
        if event_type in by_type:
            by_type[event_type] += int(group.get("occurrence_count", 0))
    incident_summary = {
        "record_count": sum(by_type.values()),
        "root_problem_count": len(issue_groups),
        "correlated_termination_count": 0,
        "by_type": by_type,
    }
    recovery_warnings = recovery_warnings + incident_warnings
    if issue_journal:
        event_pipeline = _journal_counts(issue_journal)
    collector_health = collector_health or {
        "health": "healthy",
        "coverage_ratio": 1.0,
        "reasons": [],
    }
    collection_health = collector_health.get("health", "healthy")
    if recovery_warnings and collection_health == "healthy":
        collection_health = "degraded"
    health_reasons = list(collector_health.get("reasons") or [])
    if recovery_warnings and "journal recovery warnings" not in health_reasons:
        health_reasons.append(f"journal recovery warnings: {len(recovery_warnings)}")
    coverage_ratio = round(float(collector_health.get("coverage_ratio", 1.0)), 4)
    verdict_result = compute_verdict(collection_health, incidents=incidents)
    verdict = verdict_result.verdict

    processes: List[Dict] = []

    policy = policy_from_dict(policy_config or {})
    policy_result = evaluate_policy(
        incidents,
        processes,
        coverage_ratio,
        policy,
    )
    policy_result["enabled"] = bool(ci_mode)

    if duration_sec is None:
        duration_sec = max(0.0, (ended_at - started_at).total_seconds())
    else:
        duration_sec = max(0.0, float(duration_sec))

    return {
        "schema_version": SCHEMA_VERSION,
        "source_mode": source_mode,
        "run": {
            "started_at": _iso(started_at),
            "ended_at": _iso(ended_at),
            "duration_sec": round(duration_sec, 3),
            "exit_code": int(exit_code),
            "exit_reason": exit_reason,
            "run_id": run_id,
            "app_version_name": (app_metadata or {}).get("app_version_name", ""),
            "app_version_code": (app_metadata or {}).get("app_version_code", ""),
            "build_id": (app_metadata or {}).get("build_id", ""),
            "git_sha": (app_metadata or {}).get("git_sha", ""),
            "recovered": bool(recovered),
            "recovered_at": recovered_at,
            "phase_timings": phase_timings or {},
            "device": device,
            "package": package,
            "config_effective": config_effective,
        },
        "processes": processes,
        "incidents": incidents,
        "incident_summary": incident_summary,
        "issue_groups": issue_groups,
        "exit_info": [],
        "device_events": list(device_events or []),
        "resource_risk": list(resource_risk or []),
        "self_resource": self_resource or {},
        "event_pipeline": event_pipeline,
        "collection_health": collection_health,
        "collection_health_reasons": health_reasons,
        "coverage_ratio": coverage_ratio,
        "verdict": verdict,
        "verdict_reason": list(verdict_result.reasons),
        "verdict_confidence": verdict_result.confidence,
        "expected_exit_count": 0,
        "collectors": collectors or {},
        "capabilities": list(capabilities or []),
        "disk_audit": list(quota_audit or []),
        "policy": policy_result,
        "recovery_warnings": recovery_warnings,
        "lifecycle_events": [],
        "bookmarks": list(bookmarks or []),
        "data_files": {
            "events": [p.name for p in events_files],
            "lifecycle": [],
            "logcat": [p.name for p in logcat_files],
            "journal": [journal_path.name] if journal_path.exists() else [],
        },
    }


def write(result: Dict, output_dir: Path) -> Path:
    path = Path(output_dir) / REPORT_FILENAME
    return atomic_write_json(path, result)
