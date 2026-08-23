from typing import List

from fastapi import FastAPI, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from .database import engine, get_db
from .models import Base, User, Transaction
from .schemas import UserCreate, LoginRequest, TransactionCreate, UserPublic
from .config import SECURE_MODE
from .security import (
    SECURITY_HEADERS,
    check_login_rate,
    clear_login_failures,
    record_login_failure,
    require_owner,
)
from .auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user
)

Base.metadata.create_all(bind=engine)


app = FastAPI(
    title="APICipher API",
    description="API used for security testing and risk assessment",
    version="1.0.0",
    # VULN (APC-012): interactive docs expose the full attack surface publicly.
    docs_url=None if SECURE_MODE else "/docs",
    redoc_url=None if SECURE_MODE else "/redoc",
    openapi_url=None if SECURE_MODE else "/openapi.json",
)

# VULN (APC-004): endpoints that read user data must require a credential.
AUTH_REQUIRED = [Depends(get_current_user)] if SECURE_MODE else []

# VULN (APC-005, APC-011): with no response model FastAPI serialises the whole ORM
# object, password hash included. None means "return everything" - the bug.
USER_MODEL = UserPublic if SECURE_MODE else None
USER_LIST_MODEL = List[UserPublic] if SECURE_MODE else None


if SECURE_MODE:
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        """VULN (APC-013, APC-014): responses shipped without hardening headers."""
        response = await call_next(request)
        for header, value in SECURITY_HEADERS.items():
            response.headers[header] = value
        return response


def _load_user(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()

    if not user:
        raise HTTPException(
            status_code=404,
            detail="User not found"
        )

    return user


@app.get("/profile", response_model=USER_MODEL)
def get_profile(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return _load_user(db, current_user["user_id"])


@app.get("/admin/users", response_model=USER_LIST_MODEL)
def get_all_users(
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user = _load_user(db, current_user["user_id"])

    if user.role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin access required"
        )

    return db.query(User).all()


@app.get("/")
def home():
    return {
        "message": "APICipher API is running",
        "status": "online"
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "secure_mode": SECURE_MODE
    }


@app.get("/users", response_model=USER_LIST_MODEL, dependencies=AUTH_REQUIRED)
def get_users(db: Session = Depends(get_db)):
    return db.query(User).all()


@app.post("/register")
def register_user(
    user_data: UserCreate,
    db: Session = Depends(get_db)
):
    existing_user = db.query(User).filter(
        User.username == user_data.username
    ).first()

    if existing_user:
        raise HTTPException(
            status_code=400,
            detail="Username already exists"
        )

    hashed_password = hash_password(user_data.password)

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password=hashed_password,
        role="user"
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return {
        "message": "User registered successfully",
        "user_id": new_user.id,
        "username": new_user.username
    }


@app.post("/login")
def login_user(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    # VULN (APC-010): unlimited login attempts allow offline-speed brute force.
    if SECURE_MODE:
        check_login_rate(request, login_data.username)

    user = db.query(User).filter(
        User.username == login_data.username
    ).first()

    if not user or not verify_password(login_data.password, user.password):
        if SECURE_MODE:
            record_login_failure(request, login_data.username)

        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    if SECURE_MODE:
        clear_login_failures(request, login_data.username)

    token = create_access_token(user.id)

    return {
        "access_token": token,
        "token_type": "bearer"
    }


@app.get("/users/{user_id}", response_model=USER_MODEL)
def get_user(
    user_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # VULN (APC-001): a valid token proved identity but never ownership.
    if SECURE_MODE:
        caller = _load_user(db, current_user["user_id"])

        if caller.role != "admin":
            require_owner(user_id, caller.id)

    return _load_user(db, user_id)


@app.post("/transactions")
def create_transaction(
    tx_data: TransactionCreate,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    new_tx = Transaction(
        user_id=current_user["user_id"],
        amount=tx_data.amount,
        description=tx_data.description
    )

    db.add(new_tx)
    db.commit()
    db.refresh(new_tx)

    return {
        "id": new_tx.id,
        "user_id": new_tx.user_id,
        "amount": new_tx.amount,
        "description": new_tx.description
    }


@app.get("/transactions/{transaction_id}")
def get_transaction(
    transaction_id: int,
    current_user=Depends(get_current_user),
    db: Session = Depends(get_db)
):
    tx = db.query(Transaction).filter(
        Transaction.id == transaction_id
    ).first()

    if not tx:
        raise HTTPException(
            status_code=404,
            detail="Transaction not found"
        )

    # VULN (APC-002, APC-003): any authenticated user could read any transaction.
    if SECURE_MODE:
        require_owner(tx.user_id, current_user["user_id"])

    return {
        "id": tx.id,
        "user_id": tx.user_id,
        "amount": tx.amount,
        "description": tx.description
    }
