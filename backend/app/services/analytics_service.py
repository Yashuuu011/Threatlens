from collections import Counter, defaultdict
import csv
from datetime import datetime, timezone
import io
from typing import Any, Dict, List, Set
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.database import ACTIVE_DB_BACKEND
from app.core.websocket import ws_manager
from app.ingestion.pipeline import serialize_event
from app.models.entities import (
    Alert,
    AlertEvidence,
    DetectionRule,
    Incident,
    SecurityEvent,
    ThreatIndicator,
)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def get_overview_dashboard_data(db: Session) -> Dict[str, Any]:
    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    total_alerts = db.query(func.count(Alert.id)).scalar() or 0
    critical_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.severity == "critical")
        .scalar()
        or 0
    )
    high_alerts = (
        db.query(func.count(Alert.id))
        .filter(Alert.severity == "high")
        .scalar()
        or 0
    )
    active_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.status.in_(["Open", "Investigating", "Contained"]))
        .scalar()
        or 0
    )
    resolved_incidents = (
        db.query(func.count(Incident.id))
        .filter(Incident.status.in_(["Resolved", "Closed"]))
        .scalar()
        or 0
    )

    # Fetch recent events for time-series and category/IP aggregations
    all_events: List[SecurityEvent] = (
        db.query(SecurityEvent)
        .order_by(SecurityEvent.timestamp.asc())
        .all()
    )
    all_alerts: List[Alert] = (
        db.query(Alert)
        .order_by(Alert.created_at.desc())
        .all()
    )

    # 1. Events over time & Authentication failure trends (bucketed by 5-minute or hour window)
    time_buckets: Dict[str, Dict[str, Any]] = {}
    cat_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    ip_fail_counter: Counter[str] = Counter()
    synthetic_count = 0

    for ev in all_events:
        ts = _as_utc(ev.timestamp)
        bucket_label = ts.strftime("%H:%M")
        if bucket_label not in time_buckets:
            time_buckets[bucket_label] = {
                "time": bucket_label,
                "events": 0,
                "auth_success": 0,
                "auth_failure": 0,
                "network_events": 0,
                "endpoint_events": 0,
                "authorization_events": 0,
            }
        b = time_buckets[bucket_label]
        b["events"] += 1
        cat_counter[ev.event_category] += 1
        ip_counter[ev.source_ip] += 1
        if ev.is_synthetic:
            synthetic_count += 1

        if ev.event_category == "Authentication":
            if ev.status == "failure":
                b["auth_failure"] += 1
                ip_fail_counter[ev.source_ip] += 1
            elif ev.status == "success":
                b["auth_success"] += 1
        elif ev.event_category == "Network":
            b["network_events"] += 1
        elif ev.event_category in ("Endpoint", "System"):
            b["endpoint_events"] += 1
        elif ev.event_category == "Authorization":
            b["authorization_events"] += 1

    events_over_time = list(time_buckets.values())[-24:]

    # 2. Alerts grouped by severity
    sev_counts: Counter[str] = Counter(a.severity for a in all_alerts)
    alerts_by_severity = [
        {"severity": "Critical", "key": "critical", "count": sev_counts.get("critical", 0)},
        {"severity": "High", "key": "high", "count": sev_counts.get("high", 0)},
        {"severity": "Medium", "key": "medium", "count": sev_counts.get("medium", 0)},
        {"severity": "Low", "key": "low", "count": sev_counts.get("low", 0)},
    ]

    # 3. Event distribution by category
    categories_order = [
        "Authentication",
        "Authorization",
        "Network",
        "Endpoint",
        "System",
        "Application",
    ]
    events_by_category = [
        {"category": cat, "count": cat_counter.get(cat, 0)}
        for cat in categories_order
    ]

    # 4. Top source IPs
    active_iocs = {
        ti.indicator_value: ti.threat_type
        for ti in db.query(ThreatIndicator).filter(ThreatIndicator.is_active.is_(True)).all()
    }
    top_source_ips = [
        {
            "source_ip": ip,
            "event_count": count,
            "failed_auths": ip_fail_counter.get(ip, 0),
            "is_known_ioc": ip in active_iocs,
            "threat_type": active_iocs.get(ip),
        }
        for ip, count in ip_counter.most_common(8)
    ]

    # 5. Recent incidents
    recent_incidents_objs: List[Incident] = (
        db.query(Incident)
        .order_by(Incident.created_at.desc())
        .limit(5)
        .all()
    )
    recent_incidents = [
        {
            "id": inc.id,
            "incident_id": inc.incident_id,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "assigned_analyst": inc.assigned_analyst,
            "linked_alert_count": len(inc.alert_links),
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
        }
        for inc in recent_incidents_objs
    ]

    # 6. Recent alerts & Latest security events
    recent_alerts = [
        {
            "id": a.id,
            "alert_id": a.alert_id,
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "rule_code": a.rule_code,
            "rule_name": a.rule_name,
            "source_ip": a.source_ip,
            "username": a.username,
            "event_count": a.event_count,
            "mitre_technique_id": a.mitre_technique_id,
            "first_seen": a.first_seen.isoformat() if a.first_seen else None,
            "last_seen": a.last_seen.isoformat() if a.last_seen else None,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in all_alerts[:10]
    ]

    latest_events_objs = list(reversed(all_events[-12:]))
    latest_events = [
        serialize_event(ev).model_dump(mode="json")
        for ev in latest_events_objs
    ]

    # 7. Detection activity timeline
    detection_timeline = [
        {
            "id": a.alert_id,
            "timestamp": (a.last_seen or a.created_at).isoformat() if (a.last_seen or a.created_at) else None,
            "rule_code": a.rule_code,
            "rule_name": a.rule_name,
            "title": a.title,
            "severity": a.severity,
            "source_ip": a.source_ip,
            "mitre_technique_id": a.mitre_technique_id,
            "event_count": a.event_count,
        }
        for a in all_alerts[:8]
    ]

    enabled_rules_count = (
        db.query(func.count(DetectionRule.id))
        .filter(DetectionRule.enabled.is_(True))
        .scalar()
        or 0
    )
    total_rules_count = db.query(func.count(DetectionRule.id)).scalar() or 0

    return {
        "metrics": {
            "total_security_events": total_events,
            "total_alerts": total_alerts,
            "critical_alerts": critical_alerts,
            "high_severity_alerts": high_alerts,
            "active_incidents": active_incidents,
            "resolved_incidents": resolved_incidents,
        },
        "events_over_time": events_over_time,
        "alerts_by_severity": alerts_by_severity,
        "events_by_category": events_by_category,
        "top_source_ips": top_source_ips,
        "auth_failure_trends": events_over_time,
        "recent_incidents": recent_incidents,
        "recent_alerts": recent_alerts,
        "latest_events": latest_events,
        "detection_timeline": detection_timeline,
        "system_health": {
            "status": "operational",
            "database_backend": ACTIVE_DB_BACKEND,
            "database_connected": True,
            "detection_engine": "active",
            "enabled_rules": enabled_rules_count,
            "total_rules": total_rules_count,
            "active_websocket_clients": len(ws_manager.active_connections),
            "checked_at": datetime.now(timezone.utc).isoformat(),
        },
        "ingestion_stats": {
            "total_ingested": total_events,
            "synthetic_events": synthetic_count,
            "organic_events": max(0, total_events - synthetic_count),
            "categories_active": len([c for c, cnt in cat_counter.items() if cnt > 0]),
            "unique_source_ips": len(ip_counter),
        },
    }


def compute_analytics_and_detection_metrics(db: Session) -> Dict[str, Any]:
    """Computes full analytical report and TP/FP/TN/FN Precision/Recall/F1 when labeled data exists."""
    overview = get_overview_dashboard_data(db)
    all_events: List[SecurityEvent] = db.query(SecurityEvent).all()
    all_alerts: List[Alert] = db.query(Alert).all()
    all_incidents: List[Incident] = db.query(Incident).order_by(Incident.created_at.desc()).all()
    all_rules: List[DetectionRule] = (
        db.query(DetectionRule).order_by(DetectionRule.rule_id.asc()).all()
    )

    # Map event_id (int) -> set of rule_codes from non-False-Positive alerts
    evidence_rows = (
        db.query(AlertEvidence.event_id, Alert.rule_code, Alert.status)
        .join(Alert, AlertEvidence.alert_id == Alert.id)
        .all()
    )
    detected_event_ids: Set[int] = set()
    event_to_rules: Dict[int, Set[str]] = defaultdict(set)
    for ev_id, rule_code, al_status in evidence_rows:
        if al_status != "False Positive":
            detected_event_ids.add(ev_id)
            event_to_rules[ev_id].add(rule_code)

    # Evaluate ground-truth labeled events (strictly factual, never fabricated)
    tp = 0
    fp = 0
    tn = 0
    fn = 0
    labeled_count = 0
    malicious_labeled_count = 0
    benign_labeled_count = 0

    rule_tp: Counter[str] = Counter()
    rule_fp: Counter[str] = Counter()
    rule_fn: Counter[str] = Counter()

    for ev in all_events:
        meta = ev.event_metadata or {}
        gt = meta.get("ground_truth")
        expected_rule = meta.get("expected_rule_id")
        if gt not in ("malicious", "benign"):
            continue

        labeled_count += 1
        was_detected = ev.id in detected_event_ids
        matched_rules = event_to_rules.get(ev.id, set())

        if gt == "malicious":
            malicious_labeled_count += 1
            if was_detected:
                tp += 1
                if expected_rule and expected_rule in matched_rules:
                    rule_tp[expected_rule] += 1
                elif matched_rules:
                    for rc in matched_rules:
                        rule_tp[rc] += 1
            else:
                fn += 1
                if expected_rule:
                    rule_fn[expected_rule] += 1
        else:  # gt == "benign"
            benign_labeled_count += 1
            if was_detected:
                fp += 1
                for rc in matched_rules:
                    rule_fp[rc] += 1
            else:
                tn += 1

    has_labeled_data = labeled_count > 0
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    accuracy: float | None = None
    false_positive_rate: float | None = None

    if has_labeled_data:
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 0.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 0.0
        if precision is not None and recall is not None and (precision + recall) > 0:
            f1_score = round(2 * (precision * recall) / (precision + recall), 4)
        else:
            f1_score = 0.0
        accuracy = round((tp + tn) / labeled_count, 4)
        false_positive_rate = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0

    # Rule frequency & performance breakdown
    total_alerts_count = len(all_alerts)
    alerts_by_rule: Counter[str] = Counter(a.rule_code for a in all_alerts)
    rule_performance: List[Dict[str, Any]] = []
    for r in all_rules:
        r_tp = rule_tp.get(r.rule_id, 0)
        r_fp = rule_fp.get(r.rule_id, 0)
        r_fn = rule_fn.get(r.rule_id, 0)
        r_prec = round(r_tp / (r_tp + r_fp), 4) if (r_tp + r_fp) > 0 else (1.0 if r_tp > 0 else None)
        r_rec = round(r_tp / (r_tp + r_fn), 4) if (r_tp + r_fn) > 0 else None
        r_f1 = (
            round(2 * r_prec * r_rec / (r_prec + r_rec), 4)
            if (r_prec is not None and r_rec is not None and (r_prec + r_rec) > 0)
            else None
        )
        alerts_gen = alerts_by_rule.get(r.rule_id, 0)
        freq_pct = round((alerts_gen / total_alerts_count) * 100, 1) if total_alerts_count > 0 else 0.0
        rule_performance.append(
            {
                "rule_id": r.rule_id,
                "rule_key": r.rule_key,
                "name": r.name,
                "severity": r.severity,
                "enabled": r.enabled,
                "mitre_tactic": r.mitre_tactic,
                "mitre_technique_id": r.mitre_technique_id,
                "mitre_technique_name": r.mitre_technique_name,
                "alerts_generated": alerts_gen,
                "frequency_percent": freq_pct,
                "true_positives": r_tp,
                "false_positives": r_fp,
                "false_negatives": r_fn,
                "precision": r_prec,
                "recall": r_rec,
                "f1_score": r_f1,
            }
        )

    most_frequent_rules = sorted(
        rule_performance,
        key=lambda x: x["alerts_generated"],
        reverse=True,
    )

    # Alert resolution breakdown
    status_counts: Counter[str] = Counter(a.status for a in all_alerts)
    resolved_count = status_counts.get("Resolved", 0)
    false_pos_count = status_counts.get("False Positive", 0)
    unresolved_count = sum(
        status_counts.get(s, 0) for s in ("New", "Acknowledged", "Investigating")
    )

    # Incident resolution statistics (computed strictly from real Incident records)
    inc_status_counts: Counter[str] = Counter(i.status for i in all_incidents)
    inc_sev_counts: Counter[str] = Counter(i.severity for i in all_incidents)
    total_inc_count = len(all_incidents)
    open_inc = inc_status_counts.get("Open", 0)
    investigating_inc = inc_status_counts.get("Investigating", 0)
    contained_inc = inc_status_counts.get("Contained", 0)
    resolved_inc = inc_status_counts.get("Resolved", 0)
    closed_inc = inc_status_counts.get("Closed", 0)
    active_inc_total = open_inc + investigating_inc + contained_inc
    completed_inc_total = resolved_inc + closed_inc
    inc_resolution_rate = (
        round(completed_inc_total / total_inc_count, 4) if total_inc_count > 0 else 0.0
    )

    resolution_durations_minutes: List[float] = []
    for inc in all_incidents:
        if inc.resolved_at and inc.created_at:
            diff_sec = (_as_utc(inc.resolved_at) - _as_utc(inc.created_at)).total_seconds()
            if diff_sec >= 0:
                resolution_durations_minutes.append(diff_sec / 60.0)

    mttr_minutes: float | None = (
        round(sum(resolution_durations_minutes) / len(resolution_durations_minutes), 2)
        if resolution_durations_minutes
        else None
    )

    incident_resolution_stats = {
        "total_incidents": total_inc_count,
        "open_incidents": open_inc,
        "investigating_incidents": investigating_inc,
        "contained_incidents": contained_inc,
        "resolved_incidents": resolved_inc,
        "closed_incidents": closed_inc,
        "active_incidents": active_inc_total,
        "completed_incidents": completed_inc_total,
        "resolution_rate": inc_resolution_rate,
        "mean_time_to_resolve_minutes": mttr_minutes,
        "status_breakdown": [
            {"status": s, "count": inc_status_counts.get(s, 0)}
            for s in ["Open", "Investigating", "Contained", "Resolved", "Closed"]
        ],
        "severity_breakdown": [
            {"severity": s.capitalize(), "key": s, "count": inc_sev_counts.get(s, 0)}
            for s in ["critical", "high", "medium", "low"]
        ],
    }

    incidents_summary = [
        {
            "id": inc.id,
            "incident_id": inc.incident_id,
            "title": inc.title,
            "severity": inc.severity,
            "status": inc.status,
            "assigned_analyst": inc.assigned_analyst,
            "linked_alert_count": len(inc.alert_links),
            "evidence_count": len(inc.evidence_references or []),
            "timeline_count": len(inc.timeline_events or []),
            "created_at": inc.created_at.isoformat() if inc.created_at else None,
            "resolved_at": inc.resolved_at.isoformat() if inc.resolved_at else None,
        }
        for inc in all_incidents
    ]

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": overview["metrics"],
        "alerts_by_severity": overview["alerts_by_severity"],
        "events_by_category": overview["events_by_category"],
        "event_trends": overview["events_over_time"],
        "events_over_time": overview["events_over_time"],
        "top_source_ips": overview["top_source_ips"],
        "auth_trends": overview["auth_failure_trends"],
        "resolved_vs_unresolved": [
            {"status": "Unresolved (Active)", "count": unresolved_count},
            {"status": "Resolved", "count": resolved_count},
            {"status": "False Positive", "count": false_pos_count},
        ],
        "alert_status_breakdown": [
            {"status": s, "count": status_counts.get(s, 0)}
            for s in ["New", "Acknowledged", "Investigating", "Resolved", "False Positive"]
        ],
        "incident_resolution_stats": incident_resolution_stats,
        "incidents_summary": incidents_summary,
        "detection_rule_frequency": most_frequent_rules,
        "most_frequent_rules": most_frequent_rules,
        "rule_performance": rule_performance,
        "detection_evaluation": {
            "has_labeled_data": has_labeled_data,
            "labeled_events_count": labeled_count,
            "malicious_events_count": malicious_labeled_count if has_labeled_data else None,
            "benign_events_count": benign_labeled_count if has_labeled_data else None,
            "true_positives": tp if has_labeled_data else None,
            "false_positives": fp if has_labeled_data else None,
            "true_negatives": tn if has_labeled_data else None,
            "false_negatives": fn if has_labeled_data else None,
            "precision": precision,
            "recall": recall,
            "f1_score": f1_score,
            "accuracy": accuracy,
            "false_positive_rate": false_positive_rate,
        },
    }


def generate_csv_report(db: Session) -> str:
    data = compute_analytics_and_detection_metrics(db)
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["ThreatLens Security Operations Analytical Report"])
    writer.writerow(["Generated At (UTC)", data["generated_at"]])
    writer.writerow([])

    writer.writerow(["--- EXECUTIVE SUMMARY METRICS ---"])
    writer.writerow(["Metric", "Value"])
    for k, v in data["summary"].items():
        writer.writerow([k, v])
    writer.writerow([])

    eval_metrics = data["detection_evaluation"]
    writer.writerow(["--- DETECTION EVALUATION METRICS (LABELED TELEMETRY) ---"])
    writer.writerow(["Has Labeled Data", eval_metrics["has_labeled_data"]])
    writer.writerow(["Labeled Events Evaluated", eval_metrics["labeled_events_count"]])
    writer.writerow(["True Positives (TP)", eval_metrics["true_positives"]])
    writer.writerow(["False Positives (FP)", eval_metrics["false_positives"]])
    writer.writerow(["True Negatives (TN)", eval_metrics["true_negatives"]])
    writer.writerow(["False Negatives (FN)", eval_metrics["false_negatives"]])
    writer.writerow(["Precision", eval_metrics["precision"]])
    writer.writerow(["Recall", eval_metrics["recall"]])
    writer.writerow(["F1 Score", eval_metrics["f1_score"]])
    writer.writerow(["Accuracy", eval_metrics["accuracy"]])
    writer.writerow([])

    inc_stats = data["incident_resolution_stats"]
    writer.writerow(["--- INCIDENT RESOLUTION STATISTICS ---"])
    writer.writerow(["Total Incidents", inc_stats["total_incidents"]])
    writer.writerow(["Open Incidents", inc_stats["open_incidents"]])
    writer.writerow(["Investigating Incidents", inc_stats["investigating_incidents"]])
    writer.writerow(["Contained Incidents", inc_stats["contained_incidents"]])
    writer.writerow(["Resolved Incidents", inc_stats["resolved_incidents"]])
    writer.writerow(["Closed Incidents", inc_stats["closed_incidents"]])
    writer.writerow(["Resolution Rate", inc_stats["resolution_rate"]])
    writer.writerow(["Mean Time To Resolve (Minutes)", inc_stats["mean_time_to_resolve_minutes"]])
    writer.writerow([])

    writer.writerow(["--- DETECTION RULE PERFORMANCE & MITRE ATT&CK MAPPING ---"])
    writer.writerow(
        [
            "Rule ID",
            "Rule Name",
            "Severity",
            "MITRE Tactic",
            "MITRE Technique",
            "Alerts Generated",
            "True Positives",
            "False Positives",
            "False Negatives",
            "Precision",
            "Recall",
            "F1 Score",
        ]
    )
    for r in data["rule_performance"]:
        writer.writerow(
            [
                r["rule_id"],
                r["name"],
                r["severity"],
                r["mitre_tactic"] or "",
                f"{r['mitre_technique_id'] or ''} {r['mitre_technique_name'] or ''}".strip(),
                r["alerts_generated"],
                r["true_positives"],
                r["false_positives"],
                r["false_negatives"],
                r["precision"],
                r["recall"],
                r["f1_score"],
            ]
        )
    writer.writerow([])

    writer.writerow(["--- TOP SOURCE IP ADDRESSES ---"])
    writer.writerow(["Source IP", "Event Count", "Failed Authentications", "Known IOC", "Threat Type"])
    for ip_row in data["top_source_ips"]:
        writer.writerow(
            [
                ip_row["source_ip"],
                ip_row["event_count"],
                ip_row["failed_auths"],
                ip_row["is_known_ioc"],
                ip_row["threat_type"] or "N/A",
            ]
        )

    return output.getvalue()


def _pdf_escape(text: str) -> str:
    return (
        str(text)
        .replace("\\", "\\\\")
        .replace("(", "\\(")
        .replace(")", "\\)")
    )


def _build_pdf_bytes_from_lines(lines: List[str]) -> bytes:
    """Builds a standards-compliant PDF 1.4 document from text lines using Courier Type1 font."""
    content_ops = ["BT", "/F1 9 Tf", "36 756 Td", "12 TL"]
    for idx, line in enumerate(lines[:58]):
        escaped = _pdf_escape(line)
        if idx == 0:
            content_ops.append(f"({escaped}) Tj")
        else:
            content_ops.append(f"T* ({escaped}) Tj")
    content_ops.append("ET")
    stream_bytes = "\n".join(content_ops).encode("latin-1", errors="replace")

    objects: List[bytes] = []
    objects.append(b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
    objects.append(b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n")
    objects.append(
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n"
    )
    objects.append(
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>\nendobj\n"
    )
    objects.append(
        f"5 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
        + stream_bytes
        + b"\nendstream\nendobj\n"
    )

    pdf_buf = io.BytesIO()
    pdf_buf.write(b"%PDF-1.4\n")
    offsets: List[int] = []
    for obj in objects:
        offsets.append(pdf_buf.tell())
        pdf_buf.write(obj)

    xref_pos = pdf_buf.tell()
    pdf_buf.write(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf_buf.write(b"0000000000 65535 f \n")
    for off in offsets:
        pdf_buf.write(f"{off:010d} 00000 n \n".encode("ascii"))

    pdf_buf.write(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return pdf_buf.getvalue()


def generate_pdf_report(db: Session) -> bytes:
    """Generates a standards-compliant PDF 1.4 analytical report without external C dependencies."""
    data = compute_analytics_and_detection_metrics(db)
    summary = data["summary"]
    eval_m = data["detection_evaluation"]
    inc_s = data["incident_resolution_stats"]

    lines: List[str] = [
        "THREATLENS - SECURITY OPERATIONS & THREAT DETECTION REPORT",
        f"Generated (UTC): {data['generated_at']}",
        "==========================================================================",
        "",
        "1. EXECUTIVE SOC TELEMETRY & INCIDENT RESOLUTION SUMMARY",
        f"   - Total Security Events Ingested : {summary['total_security_events']}",
        f"   - Total Generated Alerts         : {summary['total_alerts']} (Critical: {summary['critical_alerts']}, High: {summary['high_severity_alerts']})",
        f"   - Incidents (Active / Completed) : {inc_s['active_incidents']} Active / {inc_s['completed_incidents']} Completed (Total: {inc_s['total_incidents']})",
        f"   - Incident Resolution Rate       : {(inc_s['resolution_rate'] or 0) * 100:.1f}% | MTTR: {inc_s['mean_time_to_resolve_minutes'] if inc_s['mean_time_to_resolve_minutes'] is not None else 'N/A'} min",
        "",
        "2. DETECTION ENGINE EVALUATION (LABELED TEST TELEMETRY)",
    ]

    if eval_m["has_labeled_data"]:
        lines.extend(
            [
                f"   - Labeled Events Evaluated : {eval_m['labeled_events_count']}",
                f"   - True Positives (TP)      : {eval_m['true_positives']}    | False Positives (FP) : {eval_m['false_positives']}",
                f"   - True Negatives (TN)      : {eval_m['true_negatives']}    | False Negatives (FN) : {eval_m['false_negatives']}",
                f"   - Precision                : {(eval_m['precision'] or 0) * 100:.2f}% | Recall : {(eval_m['recall'] or 0) * 100:.2f}%",
                f"   - F1 Score                 : {(eval_m['f1_score'] or 0) * 100:.2f}% | Accuracy: {(eval_m['accuracy'] or 0) * 100:.2f}%",
            ]
        )
    else:
        lines.append("   - No labeled ground-truth telemetry currently present.")

    lines.extend(
        [
            "",
            "3. MITRE ATT&CK DETECTION RULE PERFORMANCE",
            "   Rule ID   | Technique | Severity | Alerts | TP  | FP  | FN  | F1 Score",
            "   ----------------------------------------------------------------------",
        ]
    )
    for r in data["rule_performance"]:
        f1_str = f"{r['f1_score']*100:.1f}%" if r["f1_score"] is not None else "N/A"
        tech = (r["mitre_technique_id"] or "N/A").ljust(9)
        sev = r["severity"].upper().ljust(8)
        lines.append(
            f"   {r['rule_id'].ljust(9)} | {tech} | {sev} | {str(r['alerts_generated']).ljust(6)} | "
            f"{str(r['true_positives']).ljust(3)} | {str(r['false_positives']).ljust(3)} | "
            f"{str(r['false_negatives']).ljust(3)} | {f1_str}"
        )

    lines.extend(
        [
            "",
            "4. TOP OBSERVED SOURCE IP ADDRESSES",
            "   Source IP         | Events | Auth Failures | Threat Intel Match",
            "   ---------------------------------------------------------------",
        ]
    )
    for ip_row in data["top_source_ips"][:8]:
        ioc_str = f"YES ({ip_row['threat_type']})" if ip_row["is_known_ioc"] else "No"
        lines.append(
            f"   {ip_row['source_ip'].ljust(17)} | {str(ip_row['event_count']).ljust(6)} | "
            f"{str(ip_row['failed_auths']).ljust(13)} | {ioc_str}"
        )

    return _build_pdf_bytes_from_lines(lines)


def generate_incident_report_data(db: Session, incident_identifier: str) -> Dict[str, Any]:
    """Generates a comprehensive Incident Investigation Report dictionary from PostgreSQL records."""
    from app.api.incidents import get_incident_detail

    detail = get_incident_detail(incident_identifier=incident_identifier, db=db)
    data = detail.model_dump(mode="json")
    data["report_generated_at"] = datetime.now(timezone.utc).isoformat()
    return data


def generate_incident_csv_report(db: Session, incident_identifier: str) -> str:
    """Exports a structured CSV Incident Investigation Report for a specific incident."""
    report = generate_incident_report_data(db, incident_identifier)
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow(["ThreatLens Incident Investigation Report"])
    writer.writerow(["Report Generated At (UTC)", report["report_generated_at"]])
    writer.writerow([])

    writer.writerow(["--- INCIDENT OVERVIEW ---"])
    writer.writerow(["Incident ID", report["incident_id"]])
    writer.writerow(["Title", report["title"]])
    writer.writerow(["Severity", report["severity"]])
    writer.writerow(["Status", report["status"]])
    writer.writerow(["Assigned Analyst", report.get("assigned_analyst") or "Unassigned"])
    writer.writerow(["Created By", report.get("created_by") or "soc_operator"])
    writer.writerow(["Created At", report["created_at"]])
    writer.writerow(["Resolved At", report.get("resolved_at") or "N/A"])
    writer.writerow(["Description", report["description"]])
    writer.writerow(["Resolution Summary", report.get("resolution_summary") or "N/A"])
    writer.writerow([])

    writer.writerow(["--- MITRE ATT&CK THREAT MAPPINGS ---"])
    writer.writerow(["Tactic", "Tactic ID", "Technique ID", "Technique Name", "Alert Count"])
    for m in report.get("mitre_mappings") or []:
        writer.writerow(
            [
                m.get("tactic"),
                m.get("tactic_id"),
                m.get("technique_id"),
                m.get("technique_name"),
                m.get("alert_count"),
            ]
        )
    writer.writerow([])

    writer.writerow(["--- ASSOCIATED SECURITY ALERTS ---"])
    writer.writerow(["Alert ID", "Rule Code", "Title", "Severity", "Status", "Source IP", "Username", "Events"])
    for al in report.get("related_alerts") or []:
        writer.writerow(
            [
                al.get("alert_id"),
                al.get("rule_code"),
                al.get("title"),
                al.get("severity"),
                al.get("status"),
                al.get("source_ip") or "",
                al.get("username") or "",
                al.get("event_count"),
            ]
        )
    writer.writerow([])

    writer.writerow(["--- EVIDENCE REFERENCES (CHAIN OF CUSTODY) ---"])
    writer.writerow(["Type", "Reference", "Description", "Added By", "Added At"])
    for ref in report.get("evidence_references") or []:
        writer.writerow(
            [
                ref.get("type"),
                ref.get("reference"),
                ref.get("description"),
                ref.get("added_by") or "",
                ref.get("added_at") or "",
            ]
        )
    writer.writerow([])

    writer.writerow(["--- INVESTIGATION TIMELINE ---"])
    writer.writerow(["Timestamp", "Actor", "Action", "Detail"])
    for item in report.get("timeline_events") or []:
        writer.writerow(
            [
                item.get("timestamp"),
                item.get("actor"),
                item.get("action"),
                item.get("detail"),
            ]
        )
    writer.writerow([])

    writer.writerow(["--- ANALYST INVESTIGATION NOTES ---"])
    writer.writerow(["Timestamp", "Author", "Note Type", "Content"])
    for n in report.get("notes") or []:
        writer.writerow(
            [
                n.get("created_at"),
                n.get("author"),
                n.get("note_type"),
                n.get("content"),
            ]
        )

    return output.getvalue()


def generate_incident_pdf_report(db: Session, incident_identifier: str) -> bytes:
    """Generates a standards-compliant PDF 1.4 Incident Investigation Report for a specific incident."""
    report = generate_incident_report_data(db, incident_identifier)
    lines: List[str] = [
        f"THREATLENS - INCIDENT INVESTIGATION REPORT ({report['incident_id']})",
        f"Generated (UTC): {report['report_generated_at']}",
        "==========================================================================",
        f"Title            : {report['title'][:64]}",
        f"Severity / Status: {str(report['severity']).upper()} / {report['status']}",
        f"Assigned Analyst : {report.get('assigned_analyst') or 'Unassigned'} | Created By: {report.get('created_by') or 'SOC'}",
        f"Created At (UTC) : {report['created_at']} | Resolved At: {report.get('resolved_at') or 'Active'}",
        f"Description      : {report['description'][:72]}",
        f"Resolution       : {(report.get('resolution_summary') or 'Investigation in progress')[:72]}",
        "",
        f"1. MITRE ATT&CK MAPPINGS ({len(report.get('mitre_mappings') or [])})",
    ]
    for m in (report.get("mitre_mappings") or [])[:5]:
        lines.append(
            f"   - {m.get('tactic')} ({m.get('tactic_id')}) | {m.get('technique_id')}: {m.get('technique_name')} ({m.get('alert_count')} alerts)"
        )

    lines.extend(
        [
            "",
            f"2. ASSOCIATED ALERTS ({len(report.get('related_alerts') or [])}) & CORRELATED EVENTS ({len(report.get('related_events') or [])})",
        ]
    )
    for al in (report.get("related_alerts") or [])[:6]:
        lines.append(
            f"   - {al.get('alert_id')} [{str(al.get('severity')).upper()}] {al.get('rule_code')}: {str(al.get('title'))[:45]} (src: {al.get('source_ip')})"
        )

    lines.extend(
        [
            "",
            f"3. FORENSIC EVIDENCE REFERENCES ({len(report.get('evidence_references') or [])})",
        ]
    )
    for ref in (report.get("evidence_references") or [])[:8]:
        lines.append(
            f"   - [{str(ref.get('type')).upper()}] {ref.get('reference')}: {str(ref.get('description'))[:52]}"
        )

    lines.extend(
        [
            "",
            f"4. INVESTIGATION TIMELINE ({len(report.get('timeline_events') or [])})",
        ]
    )
    for tl in (report.get("timeline_events") or [])[:8]:
        lines.append(
            f"   - {str(tl.get('timestamp'))[:19]} | {tl.get('actor')} | {tl.get('action')}: {str(tl.get('detail'))[:44]}"
        )

    lines.extend(
        [
            "",
            f"5. ANALYST NOTES ({len(report.get('notes') or [])})",
        ]
    )
    for n in (report.get("notes") or [])[:5]:
        lines.append(
            f"   - [{n.get('note_type')}] {n.get('author')}: {str(n.get('content'))[:56]}"
        )

    return _build_pdf_bytes_from_lines(lines)


