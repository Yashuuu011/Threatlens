import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional


def build_synthetic_event(
    *,
    timestamp: datetime,
    source_ip: str,
    destination_ip: Optional[str],
    destination_port: Optional[int],
    username: Optional[str],
    hostname: str,
    event_type: str,
    event_category: str,
    action: str,
    status: str,
    severity: str,
    raw_log: str,
    scenario: str,
    ground_truth: str,
    expected_rule_id: Optional[str] = None,
    extra_metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Creates a normalized security event dictionary clearly labeled as synthetic."""
    ts = timestamp if timestamp.tzinfo else timestamp.replace(tzinfo=timezone.utc)
    meta: Dict[str, Any] = {
        "is_synthetic": True,
        "synthetic_label": "SYNTHETIC_SECURITY_TELEMETRY",
        "scenario": scenario,
        "ground_truth": ground_truth,  # "malicious" or "benign"
        "expected_rule_id": expected_rule_id,
    }
    if destination_port is not None:
        meta["destination_port"] = destination_port
    if extra_metadata:
        meta.update(extra_metadata)

    prefixed_raw = raw_log if raw_log.startswith("[SYNTHETIC]") else f"[SYNTHETIC] {raw_log}"

    return {
        "event_id": f"SYN-{uuid.uuid4().hex[:14].upper()}",
        "timestamp": ts.isoformat(),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "username": username,
        "hostname": hostname,
        "event_type": event_type,
        "event_category": event_category,
        "action": action,
        "status": status,
        "severity": severity,
        "raw_log": prefixed_raw,
        "metadata": meta,
        "is_synthetic": True,
    }

