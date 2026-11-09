from typing import Callable, Optional
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_access_token, oauth2_scheme
from app.models.entities import User
from app.services.audit import record_audit_log


def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = decode_access_token(token)
    if not payload or "sub" not in payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    username = payload["sub"]
    user = db.query(User).filter(User.username == username).first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account not found or inactive.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def get_actor_or_default(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Validates Bearer token if supplied (raising 401 on invalid token), or returns default SOC operator for local agent/UI calls."""
    if token:
        return get_current_user(token=token, db=db)
    fallback = (
        db.query(User)
        .filter(User.username == settings.INITIAL_ADMIN_USERNAME)
        .first()
    )
    if not fallback:
        fallback = db.query(User).first()
    if not fallback:
        fallback = User(
            id=0,
            username="soc_operator",
            email="soc@threatlens.local",
            full_name="SOC Operator",
            hashed_password="",
            role="admin",
            is_active=True,
        )
    return fallback


def require_roles(*allowed_roles: str) -> Callable:
    def _checker(
        request: Request,
        current_user: User = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> User:
        if current_user.role not in allowed_roles:
            record_audit_log(
                db,
                actor_username=current_user.username,
                actor_role=current_user.role,
                action="rbac_access_denied",
                resource_type="endpoint",
                resource_id=request.url.path,
                ip_address=request.client.host if request.client else None,
                status="failure",
                details={"required_roles": list(allowed_roles), "method": request.method},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{current_user.role}' is not authorized. Required: {list(allowed_roles)}",
            )
        return current_user

    return _checker


def require_actor_roles(*allowed_roles: str) -> Callable:
    """Enforces RBAC role membership when authenticated via JWT, or resolves default operator in local UI mode."""
    def _checker(
        request: Request,
        actor: User = Depends(get_actor_or_default),
        db: Session = Depends(get_db),
    ) -> User:
        if actor.role not in allowed_roles:
            record_audit_log(
                db,
                actor_username=actor.username,
                actor_role=actor.role,
                action="rbac_access_denied",
                resource_type="endpoint",
                resource_id=request.url.path,
                ip_address=request.client.host if request.client else None,
                status="failure",
                details={"required_roles": list(allowed_roles), "method": request.method},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{actor.role}' is not authorized for this action. Required: {list(allowed_roles)}",
            )
        return actor

    return _checker



