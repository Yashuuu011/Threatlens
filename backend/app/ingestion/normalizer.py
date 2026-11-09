from datetime import datetime, timezone
import re
from typing import Any, Dict, Union

SYSLOG_SSH_FAIL_RE = re.compile(
    r"sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<username>\S+)\s+from\s+(?P<source_ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)
SYSLOG_SSH_ACCEPT_RE = re.compile(
    r"sshd\[\d+\]:\s+Accepted\s+(?:password|publickey)\s+for\s+(?P<username>\S+)\s+from\s+(?P<source_ip>[0-9a-fA-F:.]+)(?:\s+port\s+(?P<port>\d+))?",
    re.IGNORECASE,
)
UFW_FIREWALL_RE = re.compile(
    r"\[UFW\s+(?P<ufw_action>BLOCK|ALLOW)\].*?SRC=(?P<source_ip>[0-9a-fA-F:.]+)\s+DST=(?P<destination_ip>[0-9a-fA-F:.]+).*?(?:DPT=(?P<destination_port>\d+))?",
    re.IGNORECASE,
)
SUDO_PRIV_RE = re.compile(
    r"sudo:\s+(?P<username>\S+)\s+:.*?USER=(?P<target_user>\S+)\s+;\s+COMMAND=(?P<command>.+)$",
    re.IGNORECASE,
)

CATEGORY_ALIASES = {
    "authentication": "Authentication",
    "auth": "Authentication",
    "login": "Authentication",
    "iam": "Authentication",
    "authorization": "Authorization",
    "authz": "Authorization",
    "privilege": "Authorization",
    "sudo": "Authorization",
    "network": "Network",
    "net": "Network",
    "firewall": "Network",
    "netflow": "Network",
    "endpoint": "Endpoint",
    "edr": "Endpoint",
    "host": "Endpoint",
    "process": "Endpoint",
    "system": "System",
    "sys": "System",
    "os": "System",
    "kernel": "System",
    "application": "Application",
    "app": "Application",
    "web": "Application",
}


def parse_raw_log_line(raw_line: str) -> Dict[str, Any]:
    """Parses unstructured Syslog/SSH, UFW Firewall, or Sudo log strings into normalized fields."""
    line = raw_line.strip()
    is_syn = line.startswith("[SYNTHETIC]")
    clean_line = line[len("[SYNTHETIC]") :].strip() if is_syn else line

    # Extract hostname if present after ISO timestamp
    parts = clean_line.split()
    hostname = parts[1] if len(parts) > 2 and ":" in parts[0] else "unknown-host"

    m_fail = SYSLOG_SSH_FAIL_RE.search(clean_line)
    if m_fail:
        return {
            "source_ip": m_fail.group("source_ip"),
            "destination_port": 22,
            "username": m_fail.group("username"),
            "hostname": hostname,
            "event_type": "ssh_auth_failure",
            "event_category": "Authentication",
            "action": "password_login",
            "status": "failure",
            "severity": "medium",
            "raw_log": line,
            "is_synthetic": is_syn,
            "metadata": {"log_format": "syslog_ssh", "source_port": m_fail.group("port")},
        }

    m_acc = SYSLOG_SSH_ACCEPT_RE.search(clean_line)
    if m_acc:
        return {
            "source_ip": m_acc.group("source_ip"),
            "destination_port": 22,
            "username": m_acc.group("username"),
            "hostname": hostname,
            "event_type": "ssh_login_success",
            "event_category": "Authentication",
            "action": "ssh_authenticate",
            "status": "success",
            "severity": "low",
            "raw_log": line,
            "is_synthetic": is_syn,
            "metadata": {"log_format": "syslog_ssh", "source_port": m_acc.group("port")},
        }

    m_ufw = UFW_FIREWALL_RE.search(clean_line)
    if m_ufw:
        act = m_ufw.group("ufw_action").upper()
        dport = int(m_ufw.group("destination_port")) if m_ufw.group("destination_port") else None
        return {
            "source_ip": m_ufw.group("source_ip"),
            "destination_ip": m_ufw.group("destination_ip"),
            "destination_port": dport,
            "hostname": hostname,
            "event_type": "firewall_traffic",
            "event_category": "Network",
            "action": "block" if act == "BLOCK" else "allow",
            "status": "blocked" if act == "BLOCK" else "allowed",
            "severity": "low",
            "raw_log": line,
            "is_synthetic": is_syn,
            "metadata": {"log_format": "ufw_firewall", "destination_port": dport},
        }

    m_sudo = SUDO_PRIV_RE.search(clean_line)
    if m_sudo:
        return {
            "source_ip": "127.0.0.1",
            "username": m_sudo.group("username"),
            "hostname": hostname,
            "event_type": "privilege_escalation",
            "event_category": "Authorization",
            "action": "sudo_command",
            "status": "success",
            "severity": "high",
            "raw_log": line,
            "is_synthetic": is_syn,
            "metadata": {
                "log_format": "sudo_audit",
                "target_privilege": m_sudo.group("target_user"),
                "command": m_sudo.group("command").strip(),
            },
        }

    raise ValueError("Unrecognized raw log format; provide structured fields or a supported syslog/UFW/sudo line.")


def normalize_raw_event_payload(raw_input: Union[Dict[str, Any], str]) -> Dict[str, Any]:
    """
    Normalizes heterogeneous log formats and vendor field aliases into the canonical
    ThreatLens SecurityEvent schema while preserving raw log evidence.
    """
    if isinstance(raw_input, str):
        return parse_raw_log_line(raw_input)

    if not isinstance(raw_input, dict):
        raise ValueError("Security event payload must be a JSON object or raw log string.")

    data = dict(raw_input)

    # If only raw_log/log/message is provided without source_ip or event_category, attempt raw log parsing first
    raw_text = data.get("raw_log") or data.get("log") or data.get("message") or data.get("raw")
    if isinstance(raw_text, str) and not (data.get("source_ip") or data.get("src_ip") or data.get("ip")):
        try:
            parsed_line = parse_raw_log_line(raw_text)
            parsed_line.update({k: v for k, v in data.items() if v is not None})
            data = parsed_line
        except ValueError:
            pass

    # Normalize field aliases
    if "source_ip" not in data:
        for alias in ("src_ip", "client_ip", "ip", "remote_addr", "sourceAddress"):
            if alias in data and data[alias] is not None:
                data["source_ip"] = data.pop(alias)
                break

    if "destination_ip" not in data:
        for alias in ("dst_ip", "dest_ip", "target_ip", "destinationAddress"):
            if alias in data and data[alias] is not None:
                data["destination_ip"] = data.pop(alias)
                break

    if "destination_port" not in data:
        for alias in ("dst_port", "dest_port", "port", "target_port", "destinationPort"):
            if alias in data and data[alias] is not None:
                data["destination_port"] = data.pop(alias)
                break

    if "username" not in data:
        for alias in ("user", "account", "actor", "userName", "uid"):
            if alias in data and data[alias] is not None:
                data["username"] = data.pop(alias)
                break

    if "hostname" not in data:
        for alias in ("host", "device", "computer", "node", "hostName"):
            if alias in data and data[alias] is not None:
                data["hostname"] = data.pop(alias)
                break

    if "event_category" not in data:
        for alias in ("category", "log_source", "domain", "eventCategory"):
            if alias in data and data[alias] is not None:
                data["event_category"] = data.pop(alias)
                break

    if "event_type" not in data:
        for alias in ("type", "event_name", "signature", "eventType"):
            if alias in data and data[alias] is not None:
                data["event_type"] = data.pop(alias)
                break

    if "action" not in data:
        for alias in ("operation", "activity", "verb", "event_action"):
            if alias in data and data[alias] is not None:
                data["action"] = data.pop(alias)
                break

    if "status" not in data:
        for alias in ("outcome", "result", "event_status"):
            if alias in data and data[alias] is not None:
                data["status"] = data.pop(alias)
                break

    if "raw_log" not in data:
        for alias in ("log", "message", "raw", "msg"):
            if alias in data and data[alias] is not None:
                data["raw_log"] = data.pop(alias)
                break

    # Normalize epoch numeric timestamps if provided
    ts = data.get("timestamp")
    if isinstance(ts, (int, float)):
        data["timestamp"] = datetime.fromtimestamp(ts, tz=timezone.utc)

    # Normalize category aliases
    cat = data.get("event_category")
    if isinstance(cat, str):
        mapped_cat = CATEGORY_ALIASES.get(cat.strip().lower())
        if mapped_cat:
            data["event_category"] = mapped_cat

    return data

