"""Conservative, type-aware incident clustering.

The implementation follows the useful parts of TraceSim for an offline Android
report: volatile tokens are normalized, stack frames are aligned with
position/rarity weights, and fuzzy matches are admitted only when every pair in
the proposed cluster passes the threshold.  Type-specific hard gates prevent a
similar looking stack from merging different root causes.
"""

from __future__ import annotations

from collections import Counter
import hashlib
import math
import re
from typing import Dict, List, Sequence, Tuple

PRIMARY_EVENT_TYPES = ("java_crash", "native_crash", "anr")
ISSUE_EVENT_TYPES = (*PRIMARY_EVENT_TYPES, "other")
FINGERPRINT_VERSION = "sat-tracesim-v2"
DEFAULT_SIMILARITY_THRESHOLD = 0.90

_JAVA_FRAME_RE = re.compile(
    r"^(?:at\s+)?(?P<frame>[A-Za-z_][\w.$]*(?:\[[\w.]+\])?"
    r"(?:\.[A-Za-z_][\w$]*)?)(?:\((?P<file>[^)]*)\))?"
)
_ANR_FRAME_RE = re.compile(
    r"^\s*at\s+(?P<frame>[A-Za-z_][\w.$]*(?:\.[A-Za-z_][\w$]*)?)"
    r"(?:\((?P<file>[^)]*)\))?"
)
_NATIVE_FRAME_RE = re.compile(
    r"#\d+\s+pc\s+(?:0x)?[0-9a-fA-F]+\s+(?P<module>\S+\.so(?:\.[\w.]+)?)"
    r"(?:\s+\(offset\s+0x[0-9a-fA-F]+\))?"
    r"(?:\s+\((?P<symbol>.*?)(?:\+\d+|\+0x[0-9a-fA-F]+)?\))?"
)
_EXCEPTION_RE = re.compile(r"([A-Za-z_][\w.$]*(?:Exception|Error|Throwable))")
_COMPONENT_RE = re.compile(
    r"(?:cmp=|component[=: ]+|service[=: ]+|broadcast[=: ]+)"
    r"(?P<component>[\w.$-]+/[\w.$-]+)",
    re.IGNORECASE,
)


def _hash(parts: Sequence[str]) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8")).hexdigest()[:16]


def _normalize_message(value: object) -> str:
    text = str(value or "").lower()
    text = re.sub(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", "<uuid>", text)
    text = re.sub(r"\b0x[0-9a-f]+\b", "<hex>", text)
    text = re.sub(r"\b(pid|tid|uid|deviceid)\s*[=:]\s*\d+", r"\1=<n>", text)
    text = re.sub(r"(?:/data/(?:app|user|user_de)/[^\s,;:)]+)+", "<app-path>", text)
    text = re.sub(r"\b\d+(?:\.\d+)?\s*(?:ms|s|sec|seconds?)\b", "<duration>", text)
    text = re.sub(r"\b\d{3,}\b", "<n>", text)
    return re.sub(r"\s+", " ", text).strip(" :;,-")


def _normalize_java_frame(frame: str) -> str:
    match = _JAVA_FRAME_RE.match(frame.strip())
    value = match.group("frame") if match else frame.strip()
    value = re.sub(r"\.java:\d+", ".java", value)
    value = re.sub(r"\$\$ExternalSyntheticLambda\d+", "$$ExternalSyntheticLambda", value)
    value = re.sub(r"\$lambda\$\d+", "$lambda", value)
    return value


def _normalize_native_frame(frame: str) -> str:
    match = _NATIVE_FRAME_RE.search(frame.strip())
    if match:
        module = match.group("module").split("!")[-1].rsplit("/", 1)[-1]
        symbol = (match.group("symbol") or "").strip()
        symbol = re.sub(r"\s*\(BuildId:.*$", "", symbol).strip()
        symbol = re.sub(r"\+\s*(?:0x)?[0-9a-fA-F]+$", "", symbol).strip()
        return f"{module}::{symbol}" if symbol else module
    value = re.sub(r"0x[0-9a-fA-F]+", "<addr>", frame.strip())
    value = re.sub(r"\b[0-9a-fA-F]{8,}\b", "<addr>", value)
    return value


def _normalize_anr_frame(frame: str) -> str:
    match = _ANR_FRAME_RE.match(frame.strip())
    return match.group("frame") if match else _normalize_java_frame(frame)


def _top_frames(evidence: Dict, limit: int = 20) -> List[str]:
    frames = evidence.get("top_frames") or []
    if not frames:
        diagnosis = evidence.get("diagnosis") or {}
        frames = diagnosis.get("supporting_frames") or []
    return [frame for frame in frames if isinstance(frame, str)][:limit]


def _deepest_exception(incident: Dict) -> str:
    evidence = incident.get("evidence") or {}
    causes = evidence.get("cause_chain") or []
    for cause in reversed(causes):
        if isinstance(cause, dict):
            value = cause.get("exception_class") or cause.get("class")
        else:
            match = _EXCEPTION_RE.search(str(cause))
            value = match.group(1) if match else None
        if value:
            return str(value)
    value = evidence.get("exception_class")
    if value:
        return str(value)
    match = _EXCEPTION_RE.search(str(incident.get("summary") or ""))
    return match.group(1) if match else "unknown"


def _anr_type(incident: Dict) -> str:
    evidence = incident.get("evidence") or {}
    diagnosis = evidence.get("diagnosis") or {}
    typed = diagnosis.get("anr_type") or {}
    if isinstance(typed, dict) and typed.get("type"):
        return str(typed["type"]).lower()
    reason = _normalize_message(evidence.get("reason") or incident.get("summary"))
    if "input dispatch" in reason or "input_dispatch" in reason:
        return "input_dispatch"
    if "service" in reason:
        return "service"
    if "broadcast" in reason:
        return "broadcast"
    if "content provider" in reason or "content_provider" in reason:
        return "content_provider"
    return "unknown"


def _component(incident: Dict) -> str:
    evidence = incident.get("evidence") or {}
    for key in ("component", "anr_component", "reason"):
        value = evidence.get(key)
        if not value:
            continue
        match = _COMPONENT_RE.search(str(value))
        if match:
            return match.group("component").lower()
        if key != "reason" and "/" in str(value):
            return str(value).lower()
    match = _COMPONENT_RE.search(str(incident.get("summary") or ""))
    return match.group("component").lower() if match else ""


def _feature(incident: Dict) -> Dict:
    incident_type = str(incident.get("type") or "unknown")
    evidence = incident.get("evidence") or {}
    process = str(incident.get("process") or "").split(":")[0]
    raw_frames = _top_frames(evidence)
    if incident_type == "native_crash":
        frames = [_normalize_native_frame(frame) for frame in raw_frames]
    elif incident_type == "anr":
        frames = [_normalize_anr_frame(frame) for frame in raw_frames]
    else:
        frames = [_normalize_java_frame(frame) for frame in raw_frames]
    frames = [frame for frame in frames if frame]
    # Consecutive recursive frames carry no extra root-cause information.
    collapsed = [frame for i, frame in enumerate(frames) if i == 0 or frame != frames[i - 1]]
    diagnosis = evidence.get("diagnosis") or {}
    category = diagnosis.get("category") or diagnosis.get("root_cause_category") or ""
    return {
        "type": incident_type,
        "original_type": str(evidence.get("original_type") or incident_type),
        "process": process,
        "frames": collapsed,
        "exception": _deepest_exception(incident) if incident_type == "java_crash" else "",
        "subtype": str(evidence.get("subtype") or "").lower(),
        "thread": str(evidence.get("thread_category") or evidence.get("crashing_thread") or "").lower(),
        "signal": str(evidence.get("signal") or "").upper(),
        "anr_type": _anr_type(incident) if incident_type == "anr" else "",
        "component": _component(incident) if incident_type == "anr" else "",
        "diagnosis": _normalize_message(category),
        "message": _normalize_message(
            evidence.get("exception_message") or evidence.get("reason") or incident.get("summary")
        ),
    }


def _canonical_parts(feature: Dict) -> List[str]:
    incident_type = feature["type"]
    if incident_type == "java_crash":
        return ["java", feature["exception"], feature["subtype"], *feature["frames"]]
    if incident_type == "native_crash":
        return ["native", feature["signal"], *feature["frames"]]
    if incident_type == "anr":
        reason_key = feature["message"] if feature["anr_type"] == "unknown" else ""
        return [
            "anr",
            feature["anr_type"],
            feature["component"],
            feature["diagnosis"],
            reason_key,
            *feature["frames"],
        ]
    if incident_type == "other":
        return ["other", feature["original_type"], feature["message"], *feature["frames"]]
    return [incident_type, feature["process"], feature["message"]]


def fingerprint_incident(incident: Dict) -> str:
    """Return the deterministic canonical fingerprint for one incident."""
    return _hash(_canonical_parts(_feature(incident)))


def _same(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    return 1.0 if left == right else 0.0


def _hard_gate(left: Dict, right: Dict) -> bool:
    if left["type"] != right["type"] or left["type"] not in ISSUE_EVENT_TYPES:
        return False
    if left["type"] == "java_crash":
        if left["exception"] != "unknown" and right["exception"] != "unknown":
            if left["exception"] != right["exception"]:
                return False
        if left["subtype"] and right["subtype"] and left["subtype"] != right["subtype"]:
            return False
    elif left["type"] == "native_crash":
        if left["signal"] and right["signal"] and left["signal"] != right["signal"]:
            return False
    elif left["type"] == "anr":
        if left["anr_type"] != "unknown" and right["anr_type"] != "unknown":
            if left["anr_type"] != right["anr_type"]:
                return False
        if left["component"] and right["component"] and left["component"] != right["component"]:
            return False
    elif left["original_type"] != right["original_type"]:
        return False
    return True


def _frame_owner_weight(frame: str, process: str) -> float:
    package = process.split(":")[0]
    if package and frame.startswith(package):
        return 2.0
    if frame.startswith(("android.", "java.", "kotlin.", "libart.so", "libc.so")):
        return 0.35
    return 1.15


def _weighted_stack_similarity(
    left: Dict, right: Dict, document_frequency: Counter, document_count: int
) -> float:
    a, b = left["frames"], right["frames"]
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0

    def weight(frame: str, position: int, process: str) -> float:
        rarity = math.log((document_count + 1) / (document_frequency[frame] + 1)) + 1.0
        return rarity * _frame_owner_weight(frame, process) / math.sqrt(position + 1)

    wa = [weight(frame, i, left["process"]) for i, frame in enumerate(a)]
    wb = [weight(frame, i, right["process"]) for i, frame in enumerate(b)]
    previous = [0.0]
    for value in wb:
        previous.append(previous[-1] + value)
    for i, frame_a in enumerate(a, start=1):
        current = [previous[0] + wa[i - 1]]
        for j, frame_b in enumerate(b, start=1):
            delete = previous[j] + wa[i - 1]
            insert = current[j - 1] + wb[j - 1]
            substitute = previous[j - 1]
            if frame_a != frame_b:
                substitute += (wa[i - 1] + wb[j - 1]) / 2.0
            current.append(min(delete, insert, substitute))
        previous = current
    scale = max(sum(wa), sum(wb), 1e-9)
    return max(0.0, 1.0 - previous[-1] / scale)


def _message_similarity(left: str, right: str) -> float:
    if not left and not right:
        return 1.0
    if not left or not right:
        return 0.0
    a, b = set(left.split()), set(right.split())
    return len(a & b) / max(len(a | b), 1)


def _similarity(left: Dict, right: Dict, df: Counter, count: int) -> float:
    if not _hard_gate(left, right):
        return 0.0
    stack = _weighted_stack_similarity(left, right, df, count)
    if left["type"] == "java_crash":
        return (
            0.70 * stack
            + 0.10 * _same(left["exception"], right["exception"])
            + 0.05 * _same(left["subtype"], right["subtype"])
            + 0.10 * _message_similarity(left["message"], right["message"])
            + 0.05 * _same(left["thread"], right["thread"])
        )
    if left["type"] == "native_crash":
        actionable = _same(left["frames"][0] if left["frames"] else "", right["frames"][0] if right["frames"] else "")
        return 0.75 * stack + 0.15 * actionable + 0.10 * _same(left["signal"], right["signal"])
    if left["type"] == "anr":
        return (
            0.55 * stack
            + 0.20 * _same(left["anr_type"], right["anr_type"])
            + 0.15 * _same(left["component"], right["component"])
            + 0.10 * _same(left["diagnosis"], right["diagnosis"])
        )
    return (
        0.65 * stack
        + 0.25 * _message_similarity(left["message"], right["message"])
        + 0.10 * _same(left["original_type"], right["original_type"])
    )


def _evidence_quality(feature: Dict) -> int:
    quality = min(len(feature["frames"]), 4)
    if feature["type"] == "java_crash":
        quality += int(feature["exception"] != "unknown") + int(bool(feature["subtype"]))
    elif feature["type"] == "native_crash":
        quality += int(bool(feature["signal"])) + int(bool(feature["frames"]))
    elif feature["type"] == "anr":
        quality += int(feature["anr_type"] != "unknown") + int(bool(feature["component"] or feature["diagnosis"]))
    else:
        quality += int(bool(feature["original_type"])) + int(bool(feature["message"]))
    return quality


def incident_similarity(left: Dict, right: Dict) -> float:
    """Expose the pair score for diagnostics and unit tests."""
    features = [_feature(left), _feature(right)]
    df = Counter(frame for feature in features for frame in set(feature["frames"]))
    return _similarity(features[0], features[1], df, len(features))


def _occurrence_weight(incident: Dict) -> int:
    value = (incident.get("evidence") or {}).get("dedup_count", 1)
    try:
        return max(1, int(value))
    except (TypeError, ValueError):
        return 1


def _representative(
    member_indexes: List[int],
    incidents: List[Dict],
    features: List[Dict],
    scores: Dict[Tuple[int, int], float],
) -> int:
    best_quality = max(_evidence_quality(features[index]) for index in member_indexes)
    candidates = [index for index in member_indexes if _evidence_quality(features[index]) == best_quality]
    if len(candidates) == 1:
        return candidates[0]
    averages = {
        index: sum(scores.get(tuple(sorted((index, other))), 0.0) for other in member_indexes if other != index) / max(len(member_indexes) - 1, 1)
        for index in candidates
    }
    best_average = max(averages.values())
    return min(
        (index for index in candidates if averages[index] == best_average),
        key=lambda index: (str(incidents[index].get("triggered_at") or ""), str(incidents[index].get("id") or "")),
    )


def group_incidents(
    incidents: List[Dict], similarity_threshold: float = DEFAULT_SIMILARITY_THRESHOLD
) -> List[Dict]:
    """Group reportable occurrences using conservative complete-link clustering."""
    filtered = [incident for incident in incidents if incident.get("type") in ISSUE_EVENT_TYPES]
    if not filtered:
        return []
    filtered.sort(key=lambda item: (str(item.get("triggered_at") or ""), str(item.get("id") or "")))
    features = [_feature(incident) for incident in filtered]
    fingerprints = [fingerprint_incident(incident) for incident in filtered]
    df = Counter(frame for feature in features for frame in set(feature["frames"]))
    scores: Dict[Tuple[int, int], float] = {}
    clusters: List[List[int]] = []

    def pair_score(left: int, right: int) -> float:
        key = tuple(sorted((left, right)))
        if key not in scores:
            scores[key] = 1.0 if fingerprints[left] == fingerprints[right] else _similarity(features[left], features[right], df, len(features))
        return scores[key]

    for index, feature in enumerate(features):
        candidates: List[Tuple[float, float, int]] = []
        for cluster_index, members in enumerate(clusters):
            if not _hard_gate(feature, features[members[0]]):
                continue
            pair_scores = [pair_score(index, member) for member in members]
            exact = all(fingerprints[index] == fingerprints[member] for member in members)
            enough_evidence = _evidence_quality(feature) >= 5 and all(
                _evidence_quality(features[member]) >= 5 for member in members
            )
            if exact or (enough_evidence and min(pair_scores) >= similarity_threshold):
                candidates.append((min(pair_scores), sum(pair_scores) / len(pair_scores), cluster_index))
        if candidates:
            clusters[max(candidates)[2]].append(index)
        else:
            clusters.append([index])

    output: List[Dict] = []
    for members in clusters:
        representative = _representative(members, filtered, features, scores)
        occurrence_ids = [filtered[index].get("id") for index in members]
        occurrence_count = sum(_occurrence_weight(filtered[index]) for index in members)
        pair_values = [
            pair_score(left, right)
            for offset, left in enumerate(members)
            for right in members[offset + 1 :]
        ]
        timestamps = [str(filtered[index].get("triggered_at") or "") for index in members]
        affected = sorted({str(filtered[index].get("process")) for index in members if filtered[index].get("process")})
        group = {
            "fingerprint": fingerprints[representative],
            "fingerprint_version": FINGERPRINT_VERSION,
            "type": filtered[representative].get("type"),
            "occurrence_count": occurrence_count,
            "first_seen_at": min(timestamps),
            "last_seen_at": max(timestamps),
            "affected_processes": affected,
            "representative_incident_id": filtered[representative].get("id"),
            "occurrence_ids": occurrence_ids,
            "member_fingerprints": sorted({fingerprints[index] for index in members}),
            "grouping_method": "exact" if len({fingerprints[index] for index in members}) == 1 else "tracesim_complete_link",
            "grouping_confidence": round(min(pair_values) if pair_values else 1.0, 4),
            "similarity_threshold": similarity_threshold,
        }
        startup = any((filtered[index].get("evidence") or {}).get("startup_crash") for index in members)
        group["kind"] = "crash_loop" if group["type"] in ("java_crash", "native_crash") and (occurrence_count >= 3 or (occurrence_count >= 2 and startup)) else "occurrence_group"
        output.append(group)

    output.sort(key=lambda group: group["last_seen_at"] or "", reverse=True)
    return output
