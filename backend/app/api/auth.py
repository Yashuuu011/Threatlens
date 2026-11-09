from datetime import datetime, timezone
from typing import List
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, require_roles
from app.core.config import settings
from app.core.database import get_db
from app.core.rate_limit import enforce_rate_limit
from app.core.security import create_access_token, decode_access_token, get_password_hash, oauth2_scheme, verify_password
from app.models.entities import User
from app.schemas.api_schemas import LoginRequest, TokenResponse, UserCreate, UserRead, UserUpdate
from app.services.audit import record_audit_log

router = APIRouter(prefix="/api/auth", tags=["Authentication & RBAC"])


@router.post("/login", response_model=TokenResponse)
def login(
    payload: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> TokenResponse:
    enforce_rate_limit(
        request,
        scope="auth_login",
        max_requests=settings.RATE_LIMIT_LOGIN_PER_MINUTE,
        window_seconds=60,
    )
    user = db.query(User).filter(User.username == payload.username.strip()).first()
    client_ip = request.client.host if request.client else "unknown"

    if not user or not verify_password(payload.password, user.hashed_password):
        record_audit_log(
            db,
            actor_username=payload.username.strip(),
            actor_role=None,
            action="auth_login_failed",
            resource_type="user",
            resource_id=payload.username.strip(),
            ip_address=client_ip,
            status="failure",
            details={"reason": "invalid_credentials"},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled.",
        )

    user.last_login = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)

    token = create_access_token(
        subject=user.username,
        role=user.role,
        extra_claims={"full_name": user.full_name, "user_id": user.id},
    )

    record_audit_log(
        db,
        actor_username=user.username,
        actor_role=user.role,
        action="auth_login_success",
        resource_type="user",
        resource_id=str(user.id),
        ip_address=client_ip,
        status="success",
        details={"role": user.role},
    )

    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=UserRead.model_validate(user),
    )


@router.get("/me", response_model=UserRead)
def get_me(current_user: User = Depends(get_current_user)) -> UserRead:
    return UserRead.model_validate(current_user)


@router.get("/verify")
def verify_jwt_token(
    token: str | None = Depends(oauth2_scheme),
    current_user: User = Depends(get_current_user),
) -> dict:
    claims = decode_access_token(token or "") or {}
    return {
        "valid": True,
        "claims": {
            "sub": claims.get("sub"),
            "role": claims.get("role"),
            "type": claims.get("type", "access"),
            "iat": claims.get("iat"),
            "exp": claims.get("exp"),
        },
        "user": UserRead.model_validate(current_user).model_dump(mode="json"),
    }


@router.get("/users", response_model=List[UserRead])
def list_users(
    db: Session = Depends(get_db),
) -> List[UserRead]:
    users = db.query(User).order_by(User.id.asc()).all()
    return [UserRead.model_validate(u) for u in users]


@router.post("/users", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    request: Request,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> UserRead:
    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists.",
        )
    new_user = User(
        username=payload.username.strip(),
        email=payload.email.strip(),
        full_name=payload.full_name.strip(),
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
        is_active=True,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    record_audit_log(
        db,
        actor_username=current_user.username,
        actor_role=current_user.role,
        action="user_created",
        resource_type="user",
        resource_id=str(new_user.id),
        ip_address=request.client.host if request.client else None,
        details={"created_username": new_user.username, "role": new_user.role},
    )
    return UserRead.model_validate(new_user)


@router.get("/users/{user_id}", response_model=UserRead)
def get_user(
    user_id: int,
    db: Session = Depends(get_db),
) -> UserRead:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found.",
        )
    return UserRead.model_validate(user)


@router.patch("/users/{user_id}", response_model=UserRead)
def update_user(
    user_id: int,
    payload: UserUpdate,
    request: Request,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> UserRead:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found.",
        )

    changes = {}
    if payload.email is not None:
        user.email = payload.email.strip()
        changes["email"] = user.email
    if payload.full_name is not None:
        user.full_name = payload.full_name.strip()
        changes["full_name"] = user.full_name
    if payload.password is not None:
        user.hashed_password = get_password_hash(payload.password)
        changes["password_updated"] = True
    if payload.role is not None:
        user.role = payload.role
        changes["role"] = user.role
    if payload.is_active is not None:
        user.is_active = payload.is_active
        changes["is_active"] = user.is_active

    db.commit()
    db.refresh(user)

    record_audit_log(
        db,
        actor_username=current_user.username,
        actor_role=current_user.role,
        action="user_updated",
        resource_type="user",
        resource_id=str(user.id),
        ip_address=request.client.host if request.client else None,
        details=changes,
    )
    return UserRead.model_validate(user)


@router.delete("/users/{user_id}")
def delete_user(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_roles("admin")),
    db: Session = Depends(get_db),
) -> dict:
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found.",
        )
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own active administrator account.",
        )
    deleted_username = user.username
    db.delete(user)
    db.commit()

    record_audit_log(
        db,
        actor_username=current_user.username,
        actor_role=current_user.role,
        action="user_deleted",
        resource_type="user",
        resource_id=str(user_id),
        ip_address=request.client.host if request.client else None,
        details={"deleted_username": deleted_username},
    )
    return {"deleted": True, "id": user_id, "username": deleted_username}


