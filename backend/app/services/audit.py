from typing import Any, Dict, Optional
from sqlalchemy.orm import Session
from app.models.entities import AuditLog


def record_audit_log(
    db: Session,
    *,
    actor_username: str,
    actor_role: Optional[str],
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    status: str = "success",
    details: Optional[Dict[str, Any]] = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        actor_username=actor_username,
        actor_role=actor_role,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        ip_address=ip_address,
        status=status,
        details=details or {},
    )
    db.add(entry)
    if commit:
        db.commit()
        db.refresh(entry)
    else:
        db.flush()
    return entry

