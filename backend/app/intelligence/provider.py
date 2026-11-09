from abc import ABC, abstractmethod
from collections import defaultdict
from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List, Optional, Set
import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.entities import Alert, SecurityEvent, ThreatIndicator

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


class RuntimeProviderConfig:
    """Holds runtime-configurable external provider credentials (masked when read)."""

    def __init__(self) -> None:
        self.abuseipdb_api_key: str = settings.ABUSEIPDB_API_KEY or ""
        self.virustotal_api_key: str = settings.VIRUSTOTAL_API_KEY or ""
        self.otx_api_key: str = settings.OTX_API_KEY or ""
        self.enable_external_lookup: bool = True

    def status_summary(self) -> Dict[str, Any]:
        return {
            "enable_external_lookup": self.enable_external_lookup,
            "providers": [
                {
                    "id": "local_ioc_db",
                    "name": "ThreatLens Local IOC Database",
                    "configured": True,
                    "enabled": True,
                    "mode": "internal_postgresql",
                    "env_var": "DATABASE_URL",
                    "description": "Local PostgreSQL indicator of compromise repository and SIEM telemetry correlation.",
                },
                {
                    "id": "abuseipdb",
                    "name": "AbuseIPDB API v2",
                    "configured": bool(self.abuseipdb_api_key.strip()),
                    "enabled": self.enable_external_lookup and bool(self.abuseipdb_api_key.strip()),
                    "masked_key": _mask_key(self.abuseipdb_api_key),
                    "env_var": "ABUSEIPDB_API_KEY",
                    "endpoint": "https://api.abuseipdb.com/api/v2/check",
                    "description": "External IP abuse reports and confidence scoring via api.abuseipdb.com.",
                },
                {
                    "id": "virustotal",
                    "name": "VirusTotal API v3",
                    "configured": bool(self.virustotal_api_key.strip()),
                    "enabled": self.enable_external_lookup and bool(self.virustotal_api_key.strip()),
                    "masked_key": _mask_key(self.virustotal_api_key),
                    "env_var": "VIRUSTOTAL_API_KEY",
                    "endpoint": "https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    "description": "Multi-engine IP and domain reputation analysis via www.virustotal.com.",
                },
                {
                    "id": "alienvault_otx",
                    "name": "AlienVault OTX DirectConnect",
                    "configured": bool(self.otx_api_key.strip()),
                    "enabled": self.enable_external_lookup and bool(self.otx_api_key.strip()),
                    "masked_key": _mask_key(self.otx_api_key),
                    "env_var": "OTX_API_KEY",
                    "endpoint": "https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
                    "description": "Open Threat Exchange community pulse indicators via otx.alienvault.com.",
                },
            ],
        }


def _mask_key(key: str) -> Optional[str]:
    if not key or not key.strip():
        return None
    k = key.strip()
    if len(k) <= 8:
        return "****"
    return f"{k[:4]}...{k[-4:]}"


provider_config = RuntimeProviderConfig()


class ExternalThreatIntelProvider(ABC):
    """Abstract base class for external threat intelligence integrations."""

    provider_id: str
    provider_name: str
    env_var: str

    @abstractmethod
    def has_api_key(self) -> bool:
        raise NotImplementedError

    def is_configured(self) -> bool:
        return self.has_api_key() and provider_config.enable_external_lookup

    @abstractmethod
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        raise NotImplementedError


class AbuseIPDBProvider(ExternalThreatIntelProvider):
    provider_id = "abuseipdb"
    provider_name = "AbuseIPDB"
    env_var = "ABUSEIPDB_API_KEY"

    def has_api_key(self) -> bool:
        return bool(provider_config.abuseipdb_api_key.strip())

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not self.has_api_key():
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": False,
                "status": "not_configured",
                "message": "AbuseIPDB API key not configured. No external score fabricated.",
                "data": None,
            }
        if not provider_config.enable_external_lookup:
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": True,
                "status": "disabled",
                "message": "External lookups disabled in ThreatLens provider configuration. No external score fabricated.",
                "data": None,
            }
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 90},
                    headers={
                        "Key": provider_config.abuseipdb_api_key.strip(),
                        "Accept": "application/json",
                    },
                )
                if resp.status_code == 200:
                    body = resp.json().get("data", {})
                    return {
                        "provider_id": self.provider_id,
                        "provider": self.provider_name,
                        "configured": True,
                        "status": "ok",
                        "abuse_confidence_score": body.get("abuseConfidenceScore"),
                        "total_reports": body.get("totalReports"),
                        "country_code": body.get("countryCode"),
                        "isp": body.get("isp"),
                        "usage_type": body.get("usageType"),
                        "data": body,
                    }
                return {
                    "provider_id": self.provider_id,
                    "provider": self.provider_name,
                    "configured": True,
                    "status": "error",
                    "message": f"HTTP {resp.status_code} from AbuseIPDB",
                    "data": None,
                }
        except Exception as exc:
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": True,
                "status": "error",
                "message": f"Lookup request failed: {exc}",
                "data": None,
            }


class VirusTotalProvider(ExternalThreatIntelProvider):
    provider_id = "virustotal"
    provider_name = "VirusTotal"
    env_var = "VIRUSTOTAL_API_KEY"

    def has_api_key(self) -> bool:
        return bool(provider_config.virustotal_api_key.strip())

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not self.has_api_key():
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": False,
                "status": "not_configured",
                "message": "VirusTotal API key not configured. No external score fabricated.",
                "data": None,
            }
        if not provider_config.enable_external_lookup:
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": True,
                "status": "disabled",
                "message": "External lookups disabled in ThreatLens provider configuration. No external score fabricated.",
                "data": None,
            }
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": provider_config.virustotal_api_key.strip()},
                )
                if resp.status_code == 200:
                    attrs = resp.json().get("data", {}).get("attributes", {})
                    stats = attrs.get("last_analysis_stats", {})
                    return {
                        "provider_id": self.provider_id,
                        "provider": self.provider_name,
                        "configured": True,
                        "status": "ok",
                        "malicious_votes": stats.get("malicious", 0),
                        "suspicious_votes": stats.get("suspicious", 0),
                        "harmless_votes": stats.get("harmless", 0),
                        "as_owner": attrs.get("as_owner"),
                        "country": attrs.get("country"),
                    }
                return {
                    "provider_id": self.provider_id,
                    "provider": self.provider_name,
                    "configured": True,
                    "status": "error",
                    "message": f"HTTP {resp.status_code} from VirusTotal",
                    "data": None,
                }
        except Exception as exc:
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": True,
                "status": "error",
                "message": f"Lookup request failed: {exc}",
                "data": None,
            }


class AlienVaultOTXProvider(ExternalThreatIntelProvider):
    provider_id = "alienvault_otx"
    provider_name = "AlienVault OTX"
    env_var = "OTX_API_KEY"

    def has_api_key(self) -> bool:
        return bool(provider_config.otx_api_key.strip())

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not self.has_api_key():
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": False,
                "status": "not_configured",
                "message": "AlienVault OTX API key not configured. No external score fabricated.",
                "data": None,
            }
        if not provider_config.enable_external_lookup:
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": True,
                "status": "disabled",
                "message": "External lookups disabled in ThreatLens provider configuration. No external score fabricated.",
                "data": None,
            }
        try:
            addr = ipaddress.ip_address(ip)
            section = "IPv6" if addr.version == 6 else "IPv4"
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(
                    f"https://otx.alienvault.com/api/v1/indicators/{section}/{ip}/general",
                    headers={"X-OTX-API-KEY": provider_config.otx_api_key.strip()},
                )
                if resp.status_code == 200:
                    body = resp.json()
                    pulse_count = int((body.get("pulse_info") or {}).get("count", 0) or 0)
                    return {
                        "provider_id": self.provider_id,
                        "provider": self.provider_name,
                        "configured": True,
                        "status": "ok",
                        "pulse_count": pulse_count,
                        "country": body.get("country_name"),
                        "asn": body.get("asn"),
                        "data": body,
                    }
                return {
                    "provider_id": self.provider_id,
                    "provider": self.provider_name,
                    "configured": True,
                    "status": "error",
                    "message": f"HTTP {resp.status_code} from AlienVault OTX",
                    "data": None,
                }
        except Exception as exc:
            return {
                "provider_id": self.provider_id,
                "provider": self.provider_name,
                "configured": True,
                "status": "error",
                "message": f"Lookup request failed: {exc}",
                "data": None,
            }


class ThreatIntelligenceService:
    """Combines local PostgreSQL IOC intelligence, SIEM telemetry correlation, suspicious IP tracking, and external providers."""

    def __init__(self, db: Session) -> None:
        self.db = db
        self.external_providers: List[ExternalThreatIntelProvider] = [
            AbuseIPDBProvider(),
            VirusTotalProvider(),
            AlienVaultOTXProvider(),
        ]

    def lookup_ip_reputation(self, ip_str: str) -> Dict[str, Any]:
        ip_clean = ip_str.strip()
        try:
            addr = ipaddress.ip_address(ip_clean)
        except ValueError as exc:
            raise ValueError(f"Invalid IP address '{ip_clean}': {exc}") from exc

        normalized_ip = str(addr)
        network_classification = {
            "ip": normalized_ip,
            "version": f"IPv{addr.version}",
            "is_private": addr.is_private,
            "is_loopback": addr.is_loopback,
            "is_multicast": addr.is_multicast,
            "is_global": addr.is_global,
        }

        # 1. Local IOC match
        ioc = (
            self.db.query(ThreatIndicator)
            .filter(
                ThreatIndicator.indicator_value == normalized_ip,
                ThreatIndicator.is_active.is_(True),
            )
            .first()
        )
        local_ioc_match: Optional[Dict[str, Any]] = None
        if ioc:
            ioc.hit_count = (ioc.hit_count or 0) + 1
            ioc.last_seen = datetime.now(timezone.utc)
            self.db.commit()
            self.db.refresh(ioc)
            local_ioc_match = {
                "id": ioc.id,
                "indicator_type": ioc.indicator_type,
                "indicator_value": ioc.indicator_value,
                "threat_type": ioc.threat_type,
                "severity": ioc.severity,
                "confidence": ioc.confidence,
                "source": ioc.source,
                "description": ioc.description,
                "tags": ioc.tags or [],
                "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
                "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
                "hit_count": ioc.hit_count,
            }

        # 2. Internal SIEM Telemetry Correlation
        total_events_src = (
            self.db.query(func.count(SecurityEvent.id))
            .filter(SecurityEvent.source_ip == normalized_ip)
            .scalar()
            or 0
        )
        total_events_dst = (
            self.db.query(func.count(SecurityEvent.id))
            .filter(SecurityEvent.destination_ip == normalized_ip)
            .scalar()
            or 0
        )
        failed_auth_count = (
            self.db.query(func.count(SecurityEvent.id))
            .filter(
                SecurityEvent.source_ip == normalized_ip,
                SecurityEvent.event_category == "Authentication",
                SecurityEvent.status == "failure",
            )
            .scalar()
            or 0
        )
        related_alerts = (
            self.db.query(Alert)
            .filter(Alert.source_ip == normalized_ip)
            .order_by(Alert.created_at.desc())
            .limit(10)
            .all()
        )

        # 3. External Provider Results (only real results when configured; never fabricated)
        external_results = [p.lookup_ip(normalized_ip) for p in self.external_providers]

        # 4. Determine strict factual intelligence verdict
        verdict = "no_intelligence_match"
        verdict_summary = (
            "No matching Indicator of Compromise (IOC) found in local threat intelligence database, "
            "and no external provider reported malicious reputation."
        )
        reputation_confidence: Optional[int] = None

        if local_ioc_match:
            verdict = "confirmed_ioc_match"
            reputation_confidence = local_ioc_match["confidence"]
            verdict_summary = (
                f"Matched active IOC in {local_ioc_match['source']} "
                f"(threat type: {local_ioc_match['threat_type']}, "
                f"severity: {local_ioc_match['severity']}, "
                f"verified confidence: {local_ioc_match['confidence']}%)."
            )
        else:
            for ext in external_results:
                if ext.get("status") == "ok":
                    score = (
                        ext.get("abuse_confidence_score")
                        or ext.get("malicious_votes")
                        or ext.get("pulse_count")
                    )
                    if score and int(score) > 0:
                        verdict = "external_intel_match"
                        reputation_confidence = min(100, int(score))
                        verdict_summary = (
                            f"External provider {ext['provider']} reported positive threat indicator "
                            f"(score/votes/pulses: {score})."
                        )
                        break

        return {
            "ip": normalized_ip,
            "queried_at": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
            "verdict_summary": verdict_summary,
            "reputation_confidence": reputation_confidence,
            "network_classification": network_classification,
            "local_ioc_match": local_ioc_match,
            "internal_telemetry": {
                "events_as_source": total_events_src,
                "events_as_destination": total_events_dst,
                "failed_authentications": failed_auth_count,
                "associated_alerts_count": len(related_alerts),
                "recent_alerts": [
                    {
                        "alert_id": a.alert_id,
                        "title": a.title,
                        "severity": a.severity,
                        "status": a.status,
                        "rule_code": a.rule_code,
                        "created_at": a.created_at.isoformat() if a.created_at else None,
                    }
                    for a in related_alerts
                ],
            },
            "external_providers": external_results,
        }

    def get_suspicious_ips(
        self,
        limit: int = 50,
        search: Optional[str] = None,
        only_iocs: bool = False,
    ) -> List[Dict[str, Any]]:
        """Correlates SIEM security events, alerts, and local IOCs to track suspicious IPs without fabricated scores."""
        active_iocs: Dict[str, ThreatIndicator] = {
            ti.indicator_value: ti
            for ti in self.db.query(ThreatIndicator)
            .filter(ThreatIndicator.indicator_type == "ip")
            .all()
        }

        ip_stats: Dict[str, Dict[str, Any]] = {}

        def _ensure_ip_entry(ip_val: str) -> Dict[str, Any]:
            if ip_val not in ip_stats:
                is_priv = False
                try:
                    is_priv = ipaddress.ip_address(ip_val).is_private
                except ValueError:
                    pass
                ip_stats[ip_val] = {
                    "ip": ip_val,
                    "is_private": is_priv,
                    "events_as_source": 0,
                    "events_as_destination": 0,
                    "failed_logins": 0,
                    "alert_count": 0,
                    "highest_alert_severity": None,
                    "triggered_rules": set(),
                    "first_seen": None,
                    "last_seen": None,
                }
            return ip_stats[ip_val]

        for ip_val, ti in active_iocs.items():
            entry = _ensure_ip_entry(ip_val)
            entry["first_seen"] = ti.first_seen
            entry["last_seen"] = ti.last_seen

        all_events: List[SecurityEvent] = self.db.query(SecurityEvent).all()
        for ev in all_events:
            if ev.source_ip:
                s_entry = _ensure_ip_entry(ev.source_ip)
                s_entry["events_as_source"] += 1
                if ev.event_category == "Authentication" and ev.status == "failure":
                    s_entry["failed_logins"] += 1
                if ev.timestamp:
                    if s_entry["first_seen"] is None or ev.timestamp < s_entry["first_seen"]:
                        s_entry["first_seen"] = ev.timestamp
                    if s_entry["last_seen"] is None or ev.timestamp > s_entry["last_seen"]:
                        s_entry["last_seen"] = ev.timestamp

            if ev.destination_ip and ev.destination_ip in active_iocs:
                d_entry = _ensure_ip_entry(ev.destination_ip)
                d_entry["events_as_destination"] += 1
                if ev.timestamp:
                    if d_entry["first_seen"] is None or ev.timestamp < d_entry["first_seen"]:
                        d_entry["first_seen"] = ev.timestamp
                    if d_entry["last_seen"] is None or ev.timestamp > d_entry["last_seen"]:
                        d_entry["last_seen"] = ev.timestamp

        all_alerts: List[Alert] = self.db.query(Alert).all()
        for al in all_alerts:
            if not al.source_ip:
                continue
            a_entry = _ensure_ip_entry(al.source_ip)
            a_entry["alert_count"] += 1
            a_entry["triggered_rules"].add(al.rule_code)
            cur_sev = a_entry["highest_alert_severity"]
            if cur_sev is None or SEVERITY_RANK.get(al.severity, 0) > SEVERITY_RANK.get(cur_sev, 0):
                a_entry["highest_alert_severity"] = al.severity
            if al.last_seen:
                if a_entry["last_seen"] is None or al.last_seen > a_entry["last_seen"]:
                    a_entry["last_seen"] = al.last_seen

        results: List[Dict[str, Any]] = []
        term = search.strip().lower() if (search and search.strip()) else None

        for ip_val, entry in ip_stats.items():
            ioc = active_iocs.get(ip_val)
            is_active_ioc = bool(ioc and ioc.is_active)
            if only_iocs and not is_active_ioc:
                continue

            total_events = entry["events_as_source"] + entry["events_as_destination"]
            if is_active_ioc:
                tracking_status = "confirmed_ioc"
            elif entry["alert_count"] > 0:
                tracking_status = "alert_source"
            elif entry["failed_logins"] >= 3:
                tracking_status = "repeated_auth_failures"
            else:
                tracking_status = "active_telemetry"

            # Filter out purely benign internal IPs unless they triggered alerts, had >=2 failed logins, or are IOCs
            if (
                not is_active_ioc
                and entry["alert_count"] == 0
                and entry["failed_logins"] < 2
                and entry["is_private"]
            ):
                continue

            triggered_rules_list = sorted(entry["triggered_rules"])
            if term:
                searchable = f"{ip_val} {tracking_status} {' '.join(triggered_rules_list)} {ioc.threat_type if ioc else ''}".lower()
                if term not in searchable:
                    continue

            results.append(
                {
                    "ip": ip_val,
                    "is_private": entry["is_private"],
                    "total_events": total_events,
                    "events_as_source": entry["events_as_source"],
                    "events_as_destination": entry["events_as_destination"],
                    "failed_logins": entry["failed_logins"],
                    "alert_count": entry["alert_count"],
                    "highest_alert_severity": entry["highest_alert_severity"],
                    "triggered_rules": triggered_rules_list,
                    "first_seen": entry["first_seen"].isoformat() if entry["first_seen"] else None,
                    "last_seen": entry["last_seen"].isoformat() if entry["last_seen"] else None,
                    "is_active_ioc": is_active_ioc,
                    "ioc_id": ioc.id if ioc else None,
                    "ioc_threat_type": ioc.threat_type if ioc else None,
                    "ioc_severity": ioc.severity if ioc else None,
                    "ioc_confidence": ioc.confidence if ioc else None,
                    "ioc_source": ioc.source if ioc else None,
                    "tracking_status": tracking_status,
                }
            )

        results.sort(
            key=lambda r: (
                1 if r["is_active_ioc"] else 0,
                r["alert_count"],
                r["failed_logins"],
                r["total_events"],
            ),
            reverse=True,
        )
        return results[:limit]


