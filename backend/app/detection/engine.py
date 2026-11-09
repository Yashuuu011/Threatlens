import ipaddress
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from sqlalchemy.orm import Session

from app.core.websocket import broadcast_sync_or_async
from app.models.entities import (
    Alert,
    AlertEvidence,
    AlertStatusHistory,
    DetectionRule,
    SecurityEvent,
    ThreatIndicator,
)


def _as_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _is_internal_ip(ip_str: str, internal_cidrs: List[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        if addr.is_private or addr.is_loopback:
            return True
        for cidr in internal_cidrs:
            try:
                if addr in ipaddress.ip_network(cidr, strict=False):
                    return True
            except ValueError:
                continue
        return False
    except ValueError:
        return False


class ThreatDetectionEngine:
    """Evaluates security events against configurable SQLAlchemy detection rules."""

    def __init__(self, db: Session) -> None:
        self.db = db

    def evaluate_events(self, events: Sequence[SecurityEvent] | Iterable[SecurityEvent]) -> List[Alert]:
        event_list = sorted(list(events), key=lambda e: _as_utc(e.timestamp))
        if not event_list:
            return []

        rules: List[DetectionRule] = (
            self.db.query(DetectionRule)
            .filter(DetectionRule.enabled.is_(True))
            .order_by(DetectionRule.rule_id.asc())
            .all()
        )
        if not rules:
            return []

        rules_by_key = {r.rule_key: r for r in rules}
        active_iocs: Dict[str, ThreatIndicator] = {
            ti.indicator_value: ti
            for ti in self.db.query(ThreatIndicator)
            .filter(ThreatIndicator.is_active.is_(True))
            .all()
        }

        generated_alerts: List[Alert] = []
        seen_alert_ids: Set[int] = set()

        for event in event_list:
            for rule_key, evaluator in [
                ("brute_force", self._eval_brute_force),
                ("password_spraying", self._eval_password_spraying),
                ("login_after_failures", self._eval_login_after_failures),
                ("unusual_login", self._eval_unusual_login),
                ("privilege_escalation", self._eval_privilege_escalation),
                ("port_scanning", self._eval_port_scanning),
                ("suspicious_network", self._eval_suspicious_network),
            ]:
                rule = rules_by_key.get(rule_key)
                if not rule:
                    continue
                alert = evaluator(rule, event, active_iocs)
                if alert and alert.id not in seen_alert_ids:
                    seen_alert_ids.add(alert.id)
                    generated_alerts.append(alert)

        self.db.commit()
        if generated_alerts:
            for alert in generated_alerts:
                self.db.refresh(alert)
                broadcast_sync_or_async(
                    "alert_created",
                    {
                        "id": alert.id,
                        "alert_id": alert.alert_id,
                        "title": alert.title,
                        "severity": alert.severity,
                        "status": alert.status,
                        "rule_code": alert.rule_code,
                        "rule_name": alert.rule_name,
                        "source_ip": alert.source_ip,
                        "username": alert.username,
                        "event_count": alert.event_count,
                        "created_at": alert.created_at.isoformat() if alert.created_at else None,
                    },
                )

        return generated_alerts

    def _upsert_alert_within_window(
        self,
        rule: DetectionRule,
        dedup_key: str,
        title: str,
        description: str,
        source_ip: Optional[str],
        username: Optional[str],
        hostname: Optional[str],
        matching_events: List[SecurityEvent],
        evidence_summary: Dict[str, Any],
        primary_event: Optional[SecurityEvent] = None,
    ) -> Optional[Alert]:
        if not matching_events:
            return None

        timestamps = [_as_utc(e.timestamp) for e in matching_events]
        first_seen = min(timestamps)
        last_seen = max(timestamps)

        # Check for existing alert with same rule_code and dedup_key within active window
        candidates: List[Alert] = (
            self.db.query(Alert)
            .filter(
                Alert.rule_code == rule.rule_id,
                Alert.dedup_key == dedup_key,
            )
            .order_by(Alert.last_seen.desc())
            .all()
        )

        existing_alert: Optional[Alert] = None
        for cand in candidates:
            cand_last = _as_utc(cand.last_seen)
            if abs((last_seen - cand_last).total_seconds()) <= rule.time_window_seconds:
                existing_alert = cand
                break

        existing_event_ids: Set[int] = set()
        if existing_alert:
            if _as_utc(existing_alert.first_seen) > first_seen:
                existing_alert.first_seen = first_seen
            if _as_utc(existing_alert.last_seen) < last_seen:
                existing_alert.last_seen = last_seen
            existing_event_ids = {
                ev.event_id
                for ev in self.db.query(AlertEvidence)
                .filter(AlertEvidence.alert_id == existing_alert.id)
                .all()
            }
            new_links = 0
            for ev in matching_events:
                if ev.id not in existing_event_ids:
                    role = (
                        "compromise_event"
                        if (primary_event and ev.id == primary_event.id)
                        else "triggering_event"
                    )
                    self.db.add(
                        AlertEvidence(
                            alert_id=existing_alert.id,
                            event_id=ev.id,
                            evidence_role=role,
                            note=f"Correlated by {rule.rule_id}",
                        )
                    )
                    existing_event_ids.add(ev.id)
                    new_links += 1

            existing_alert.event_count = len(existing_event_ids)
            existing_alert.evidence_summary = evidence_summary
            self.db.flush()
            # Return None because we updated an existing in-window alert rather than creating a duplicate
            return None

        # Create new Alert
        alert_code = f"ALT-{last_seen.strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
        is_synth = any(bool(e.is_synthetic) for e in matching_events)
        new_alert = Alert(
            alert_id=alert_code,
            title=title,
            description=description,
            severity=rule.severity,
            status="New",
            rule_id_fk=rule.id,
            rule_code=rule.rule_id,
            rule_name=rule.name,
            source_ip=source_ip,
            username=username,
            hostname=hostname,
            first_seen=first_seen,
            last_seen=last_seen,
            event_count=len(matching_events),
            dedup_key=dedup_key,
            mitre_tactic=rule.mitre_tactic,
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            evidence_summary=evidence_summary,
            is_synthetic=is_synth,
        )
        self.db.add(new_alert)
        self.db.flush()

        # Record initial status history
        self.db.add(
            AlertStatusHistory(
                alert_id=new_alert.id,
                previous_status=None,
                new_status="New",
                changed_by="ThreatLens Detection Engine",
                comment=f"Automatically generated by {rule.rule_id} ({rule.name})",
            )
        )

        # Link triggering events
        linked_ids: Set[int] = set()
        for ev in matching_events:
            if ev.id in linked_ids:
                continue
            linked_ids.add(ev.id)
            role = (
                "compromise_event"
                if (primary_event and ev.id == primary_event.id)
                else "triggering_event"
            )
            self.db.add(
                AlertEvidence(
                    alert_id=new_alert.id,
                    event_id=ev.id,
                    evidence_role=role,
                    note=f"Matched {rule.rule_id} ({rule.mitre_technique_id or 'SIEM'})",
                )
            )

        self.db.flush()
        return new_alert

    # --- RULE 1: BRUTE-FORCE ATTACK ---
    def _eval_brute_force(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        active_iocs: Dict[str, ThreatIndicator],
    ) -> Optional[Alert]:
        if event.event_category != "Authentication" or event.status != "failure" or not event.username:
            return None

        ev_ts = _as_utc(event.timestamp)
        window_start = ev_ts - timedelta(seconds=rule.time_window_seconds)

        matches: List[SecurityEvent] = (
            self.db.query(SecurityEvent)
            .filter(
                SecurityEvent.event_category == "Authentication",
                SecurityEvent.status == "failure",
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.username == event.username,
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.timestamp <= ev_ts,
            )
            .order_by(SecurityEvent.timestamp.asc())
            .all()
        )

        if len(matches) < rule.threshold_count:
            return None

        dedup_key = f"bf:{event.source_ip}:{event.username}"
        title = f"Brute-Force Attack Against '{event.username}' from {event.source_ip}"
        description = (
            f"Detected {len(matches)} failed authentication attempts for account '{event.username}' "
            f"from source IP {event.source_ip} within {rule.time_window_seconds} seconds "
            f"(threshold: {rule.threshold_count})."
        )
        summary = {
            "rule_key": rule.rule_key,
            "failed_attempts": len(matches),
            "threshold": rule.threshold_count,
            "time_window_seconds": rule.time_window_seconds,
            "source_ip": event.source_ip,
            "target_username": event.username,
            "target_hostname": event.hostname,
            "event_ids": [m.event_id for m in matches],
        }
        return self._upsert_alert_within_window(
            rule=rule,
            dedup_key=dedup_key,
            title=title,
            description=description,
            source_ip=event.source_ip,
            username=event.username,
            hostname=event.hostname,
            matching_events=matches,
            evidence_summary=summary,
        )

    # --- RULE 2: PASSWORD SPRAYING ---
    def _eval_password_spraying(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        active_iocs: Dict[str, ThreatIndicator],
    ) -> Optional[Alert]:
        if event.event_category != "Authentication" or event.status != "failure" or not event.username:
            return None

        ev_ts = _as_utc(event.timestamp)
        window_start = ev_ts - timedelta(seconds=rule.time_window_seconds)

        matches: List[SecurityEvent] = (
            self.db.query(SecurityEvent)
            .filter(
                SecurityEvent.event_category == "Authentication",
                SecurityEvent.status == "failure",
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.username.isnot(None),
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.timestamp <= ev_ts,
            )
            .order_by(SecurityEvent.timestamp.asc())
            .all()
        )

        by_user: Dict[str, List[SecurityEvent]] = defaultdict(list)
        for m in matches:
            if m.username:
                by_user[m.username].append(m)

        distinct_users = list(by_user.keys())
        if len(distinct_users) < rule.threshold_count:
            return None

        max_per_user = int((rule.parameters or {}).get("max_attempts_per_user", 3))
        low_attempt_users = [u for u, evs in by_user.items() if len(evs) <= max_per_user]
        if len(low_attempt_users) < rule.threshold_count:
            return None

        dedup_key = f"spray:{event.source_ip}"
        title = f"Password Spraying Across {len(distinct_users)} Accounts from {event.source_ip}"
        description = (
            f"Source IP {event.source_ip} attempted failed logins against {len(distinct_users)} "
            f"distinct usernames ({', '.join(sorted(distinct_users)[:6])}) within "
            f"{rule.time_window_seconds}s using low per-account frequency characteristic of password spraying."
        )
        summary = {
            "rule_key": rule.rule_key,
            "source_ip": event.source_ip,
            "distinct_usernames_count": len(distinct_users),
            "targeted_usernames": sorted(distinct_users),
            "attempts_per_username": {u: len(evs) for u, evs in by_user.items()},
            "threshold_distinct_users": rule.threshold_count,
            "time_window_seconds": rule.time_window_seconds,
            "event_ids": [m.event_id for m in matches],
        }
        return self._upsert_alert_within_window(
            rule=rule,
            dedup_key=dedup_key,
            title=title,
            description=description,
            source_ip=event.source_ip,
            username=f"{len(distinct_users)} accounts ({', '.join(sorted(distinct_users)[:3])}...)",
            hostname=event.hostname,
            matching_events=matches,
            evidence_summary=summary,
        )

    # --- RULE 3: SUCCESSFUL LOGIN AFTER MULTIPLE FAILURES ---
    def _eval_login_after_failures(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        active_iocs: Dict[str, ThreatIndicator],
    ) -> Optional[Alert]:
        if event.event_category != "Authentication" or event.status != "success" or not event.username:
            return None

        ev_ts = _as_utc(event.timestamp)
        window_start = ev_ts - timedelta(seconds=rule.time_window_seconds)

        preceding_failures: List[SecurityEvent] = (
            self.db.query(SecurityEvent)
            .filter(
                SecurityEvent.event_category == "Authentication",
                SecurityEvent.status == "failure",
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.username == event.username,
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.timestamp <= ev_ts,
                SecurityEvent.id != event.id,
            )
            .order_by(SecurityEvent.timestamp.asc())
            .all()
        )

        if len(preceding_failures) < rule.threshold_count:
            return None

        all_evidence = preceding_failures + [event]
        dedup_key = f"succ_after_fail:{event.source_ip}:{event.username}"
        title = f"Successful Login After {len(preceding_failures)} Failures for '{event.username}'"
        description = (
            f"Account '{event.username}' authenticated successfully from {event.source_ip} "
            f"on host '{event.hostname or 'unknown'}' following {len(preceding_failures)} failed "
            f"authentication attempts within {rule.time_window_seconds} seconds."
        )
        summary = {
            "rule_key": rule.rule_key,
            "source_ip": event.source_ip,
            "username": event.username,
            "hostname": event.hostname,
            "preceding_failure_count": len(preceding_failures),
            "compromise_event_id": event.event_id,
            "failure_event_ids": [f.event_id for f in preceding_failures],
        }
        return self._upsert_alert_within_window(
            rule=rule,
            dedup_key=dedup_key,
            title=title,
            description=description,
            source_ip=event.source_ip,
            username=event.username,
            hostname=event.hostname,
            matching_events=all_evidence,
            evidence_summary=summary,
            primary_event=event,
        )

    # --- RULE 4: UNUSUAL LOGIN ACTIVITY ---
    def _eval_unusual_login(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        active_iocs: Dict[str, ThreatIndicator],
    ) -> Optional[Alert]:
        if event.event_category != "Authentication" or event.status != "success":
            return None

        params = rule.parameters or {}
        internal_cidrs = params.get(
            "internal_cidrs",
            ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"],
        )
        off_hours_utc = set(params.get("off_hours_utc", [0, 1, 2, 3, 4, 5, 22, 23]))

        meta = event.metadata_dict
        ev_ts = _as_utc(event.timestamp)
        is_external = not _is_internal_ip(event.source_ip, internal_cidrs)

        reasons: List[str] = []
        if event.source_ip in active_iocs:
            ioc = active_iocs[event.source_ip]
            reasons.append(f"source IP matches active threat indicator ({ioc.threat_type})")

        if meta.get("unusual_login") is True or meta.get("anomalous_pattern") is True:
            anomaly_reason = meta.get("anomaly_reason") or "telemetry flagged abnormal authentication pattern"
            reasons.append(str(anomaly_reason))

        if is_external and ev_ts.hour in off_hours_utc:
            reasons.append(f"external non-RFC1918 source IP ({event.source_ip}) authenticated during off-hours ({ev_ts.strftime('%H:%M')} UTC)")

        if is_external and meta.get("new_source_network") is True:
            reasons.append(f"first observed authentication from external network {event.source_ip}")

        if not reasons:
            return None

        dedup_key = f"unusual_login:{event.source_ip}:{event.username or 'unknown'}"
        title = f"Unusual Login Activity for '{event.username or 'unknown'}' from {event.source_ip}"
        description = (
            f"Observed unusual successful authentication for user '{event.username or 'unknown'}' "
            f"from {event.source_ip} on '{event.hostname or 'unknown'}'. "
            f"Supporting telemetry indicators (no unverified geolocation assumed): {'; '.join(reasons)}."
        )
        summary = {
            "rule_key": rule.rule_key,
            "source_ip": event.source_ip,
            "is_external_ip": is_external,
            "username": event.username,
            "hostname": event.hostname,
            "login_hour_utc": ev_ts.hour,
            "telemetry_reasons": reasons,
            "event_id": event.event_id,
        }
        return self._upsert_alert_within_window(
            rule=rule,
            dedup_key=dedup_key,
            title=title,
            description=description,
            source_ip=event.source_ip,
            username=event.username,
            hostname=event.hostname,
            matching_events=[event],
            evidence_summary=summary,
            primary_event=event,
        )

    # --- RULE 5: SUSPICIOUS PRIVILEGE ESCALATION ---
    def _eval_privilege_escalation(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        active_iocs: Dict[str, ThreatIndicator],
    ) -> Optional[Alert]:
        if event.event_category not in ("Authorization", "Endpoint", "System"):
            return None

        params = rule.parameters or {}
        suspicious_actions = set(
            params.get(
                "suspicious_actions",
                [
                    "privilege_escalation",
                    "sudo_abuse",
                    "admin_group_modification",
                    "role_elevation",
                    "unauthorized_admin_access",
                    "setuid_execution",
                    "token_manipulation",
                    "sudo_to_root",
                ],
            )
        )
        meta = event.metadata_dict
        matched_indicators: List[str] = []

        if event.event_type.lower() in suspicious_actions:
            matched_indicators.append(f"event_type={event.event_type}")
        if event.action.lower() in suspicious_actions:
            matched_indicators.append(f"action={event.action}")
        if meta.get("target_privilege") in ("root", "SYSTEM", "Domain Admins", "sudoers", "Administrator"):
            matched_indicators.append(f"target_privilege={meta.get('target_privilege')}")
        if meta.get("privilege_escalation") is True:
            matched_indicators.append("metadata.privilege_escalation=true")

        if not matched_indicators:
            return None

        ev_ts = _as_utc(event.timestamp)
        window_start = ev_ts - timedelta(seconds=rule.time_window_seconds)

        # Collect related privilege events for same user/host within window
        related = (
            self.db.query(SecurityEvent)
            .filter(
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.username == event.username,
                SecurityEvent.event_category.in_(["Authorization", "Endpoint", "System"]),
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.timestamp <= ev_ts,
            )
            .all()
        )
        priv_events = [
            e
            for e in related
            if e.event_type.lower() in suspicious_actions
            or e.action.lower() in suspicious_actions
            or e.metadata_dict.get("privilege_escalation") is True
            or e.metadata_dict.get("target_privilege") in ("root", "SYSTEM", "Domain Admins", "sudoers", "Administrator")
        ]
        if not priv_events:
            priv_events = [event]

        if len(priv_events) < rule.threshold_count:
            return None

        dedup_key = f"privesc:{event.source_ip}:{event.username or 'system'}:{event.hostname or 'host'}"
        title = f"Suspicious Privilege Escalation by '{event.username or 'unknown'}' on {event.hostname or event.source_ip}"
        description = (
            f"Detected unauthorized or suspicious privilege elevation activity by user "
            f"'{event.username or 'unknown'}' on host '{event.hostname or 'unknown'}' "
            f"(source IP: {event.source_ip}). Indicators: {', '.join(matched_indicators)}."
        )
        summary = {
            "rule_key": rule.rule_key,
            "username": event.username,
            "hostname": event.hostname,
            "source_ip": event.source_ip,
            "matched_indicators": matched_indicators,
            "command": meta.get("command") or meta.get("process_name"),
            "target_privilege": meta.get("target_privilege"),
            "event_ids": [e.event_id for e in priv_events],
        }
        return self._upsert_alert_within_window(
            rule=rule,
            dedup_key=dedup_key,
            title=title,
            description=description,
            source_ip=event.source_ip,
            username=event.username,
            hostname=event.hostname,
            matching_events=priv_events,
            evidence_summary=summary,
            primary_event=event,
        )

    # --- RULE 6: PORT SCANNING ---
    def _eval_port_scanning(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        active_iocs: Dict[str, ThreatIndicator],
    ) -> Optional[Alert]:
        if event.event_category != "Network":
            return None

        port = event.destination_port or event.metadata_dict.get("destination_port")
        if port is None:
            return None

        ev_ts = _as_utc(event.timestamp)
        window_start = ev_ts - timedelta(seconds=rule.time_window_seconds)

        net_events: List[SecurityEvent] = (
            self.db.query(SecurityEvent)
            .filter(
                SecurityEvent.event_category == "Network",
                SecurityEvent.source_ip == event.source_ip,
                SecurityEvent.timestamp >= window_start,
                SecurityEvent.timestamp <= ev_ts,
            )
            .order_by(SecurityEvent.timestamp.asc())
            .all()
        )

        ports_seen: Dict[int, SecurityEvent] = {}
        scan_events: List[SecurityEvent] = []
        for ne in net_events:
            p = ne.destination_port or ne.metadata_dict.get("destination_port")
            if p is not None:
                try:
                    p_int = int(p)
                    ports_seen[p_int] = ne
                    scan_events.append(ne)
                except (TypeError, ValueError):
                    continue

        if len(ports_seen) < rule.threshold_count:
            return None

        sorted_ports = sorted(ports_seen.keys())
        dedup_key = f"portscan:{event.source_ip}:{event.destination_ip or 'any'}"
        title = f"Port Scanning Detected from {event.source_ip} ({len(sorted_ports)} Distinct Ports)"
        description = (
            f"Source IP {event.source_ip} probed {len(sorted_ports)} distinct destination ports "
            f"on target {event.destination_ip or 'network'} within {rule.time_window_seconds} seconds "
            f"(ports: {', '.join(str(p) for p in sorted_ports[:12])})."
        )
        summary = {
            "rule_key": rule.rule_key,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "distinct_ports_count": len(sorted_ports),
            "scanned_ports": sorted_ports,
            "threshold_ports": rule.threshold_count,
            "time_window_seconds": rule.time_window_seconds,
            "event_ids": [e.event_id for e in scan_events],
        }
        return self._upsert_alert_within_window(
            rule=rule,
            dedup_key=dedup_key,
            title=title,
            description=description,
            source_ip=event.source_ip,
            username=event.username,
            hostname=event.hostname,
            matching_events=scan_events,
            evidence_summary=summary,
        )

    # --- RULE 7: SUSPICIOUS NETWORK ACTIVITY ---
    def _eval_suspicious_network(
        self,
        rule: DetectionRule,
        event: SecurityEvent,
        active_iocs: Dict[str, ThreatIndicator],
    ) -> Optional[Alert]:
        if event.event_category != "Network":
            return None

        # Avoid double-triggering on pure port_probe events that belong to Port Scanning unless C2/exfil
        if event.event_type in ("port_probe", "syn_scan"):
            return None

        params = rule.parameters or {}
        suspicious_ports = set(params.get("suspicious_ports", [4444, 1337, 6667, 9001, 31337, 5555]))
        exfil_threshold = int(params.get("exfil_bytes_threshold", 10000000))
        suspicious_types = set(
            params.get(
                "suspicious_event_types",
                [
                    "c2_beacon",
                    "data_exfiltration",
                    "suspicious_outbound",
                    "dns_tunneling",
                    "lateral_movement_smb",
                ],
            )
        )

        meta = event.metadata_dict
        port = event.destination_port or meta.get("destination_port")
        bytes_out = int(meta.get("bytes_out", 0) or 0)

        reasons: List[str] = []
        if port is not None and int(port) in suspicious_ports:
            reasons.append(f"connection to high-risk port {port}")
        if bytes_out >= exfil_threshold:
            reasons.append(f"high outbound data transfer ({bytes_out:,} bytes)")
        if event.event_type.lower() in suspicious_types or event.action.lower() in suspicious_types:
            reasons.append(f"suspicious network pattern '{event.event_type}'")
        if event.destination_ip and event.destination_ip in active_iocs:
            ioc = active_iocs[event.destination_ip]
            reasons.append(f"destination IP {event.destination_ip} matches active IOC ({ioc.threat_type})")
        if event.source_ip in active_iocs:
            ioc = active_iocs[event.source_ip]
            reasons.append(f"source IP {event.source_ip} matches active IOC ({ioc.threat_type})")

        if not reasons:
            return None

        dedup_key = f"susp_net:{event.source_ip}:{event.destination_ip or 'ext'}:{event.event_type}"
        title = f"Suspicious Network Activity ({event.event_type}) Involving {event.source_ip}"
        description = (
            f"Detected suspicious network traffic from {event.source_ip} to "
            f"{event.destination_ip or 'external host'}{f':{port}' if port else ''}. "
            f"Indicators: {'; '.join(reasons)}."
        )
        summary = {
            "rule_key": rule.rule_key,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "destination_port": port,
            "bytes_out": bytes_out,
            "protocol": meta.get("protocol", "TCP"),
            "reasons": reasons,
            "event_id": event.event_id,
        }
        return self._upsert_alert_within_window(
            rule=rule,
            dedup_key=dedup_key,
            title=title,
            description=description,
            source_ip=event.source_ip,
            username=event.username,
            hostname=event.hostname,
            matching_events=[event],
            evidence_summary=summary,
            primary_event=event,
        )
