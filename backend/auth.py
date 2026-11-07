import datetime as dt
import hashlib
import os
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import APIRouter, BackgroundTasks, Cookie, Depends, HTTPException, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session

from db import AuthSession, EmailToken, User, get_db, utcnow
from mailer import send_email

router = APIRouter(prefix="/api/auth", tags=["auth"])
hasher = PasswordHasher()
COOKIE = "vibepen_session"
SESSION_DAYS = 30
VERIFY_HOURS = 24
APP_URL = os.getenv("APP_URL", "http://localhost:8443")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


class Credentials(BaseModel):
    email: str
    password: str
    name: str = ""


class EmailBody(BaseModel):
    email: str


class TokenBody(BaseModel):
    token: str


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _user_json(user: User):
    return {"id": user.id, "email": user.email, "name": user.name}


def _start_session(response: Response, db: Session, user: User):
    token = secrets.token_urlsafe(32)
    db.add(AuthSession(
        token_hash=_hash_token(token),
        user_id=user.id,
        expires_at=utcnow() + dt.timedelta(days=SESSION_DAYS),
    ))
    db.commit()
    response.set_cookie(
        COOKIE, token, max_age=SESSION_DAYS * 86400,
        httponly=True, samesite="lax", secure=False,  # set secure=True behind HTTPS
    )


def _safe_send(to: str, subject: str, body: str):
    try:
        send_email(to, subject, body)
    except Exception as exc:  # never let a mail failure crash the request
        print(f"[mail error] could not send to {to}: {exc}")


def _queue_verification(db: Session, user: User, background: BackgroundTasks):
    db.query(EmailToken).filter_by(user_id=user.id).delete()
    token = secrets.token_urlsafe(32)
    db.add(EmailToken(
        token_hash=_hash_token(token),
        user_id=user.id,
        expires_at=utcnow() + dt.timedelta(hours=VERIFY_HOURS),
    ))
    db.commit()
    link = f"{APP_URL}/verify-email?token={token}"
    body = (
        f"Hi {user.name or 'there'},\n\n"
        f"Confirm your email to finish setting up VibePen:\n{link}\n\n"
        f"This link expires in {VERIFY_HOURS} hours. "
        "If you didn't create an account, you can ignore this message.\n"
    )
    background.add_task(_safe_send, user.email, "Confirm your VibePen email", body)


def current_user(
    token: str | None = Cookie(default=None, alias=COOKIE),
    db: Session = Depends(get_db),
) -> User:
    if not token:
        raise HTTPException(401, "Not signed in")
    sess = db.query(AuthSession).filter_by(token_hash=_hash_token(token)).first()
    if not sess or sess.expires_at < utcnow():
        raise HTTPException(401, "Session expired")
    user = db.get(User, sess.user_id)
    if not user:
        raise HTTPException(401, "Not signed in")
    return user


@router.post("/register", status_code=201)
def register(body: Credentials, background: BackgroundTasks, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(422, "Enter a valid email address")
    if len(body.password) < 8:
        raise HTTPException(422, "Password must be at least 8 characters")
    if db.query(User).filter_by(email=email).first():
        raise HTTPException(409, "An account with this email already exists")
    user = User(name=body.name.strip(), email=email, password_hash=hasher.hash(body.password))
    db.add(user)
    db.commit()
    _queue_verification(db, user, background)
    return {"email": user.email, "verification_required": True}


@router.post("/verify-email")
def verify_email(body: TokenBody, response: Response, db: Session = Depends(get_db)):
    row = db.query(EmailToken).filter_by(token_hash=_hash_token(body.token)).first()
    if not row or row.expires_at < utcnow():
        raise HTTPException(400, "This link is invalid or has expired")
    user = db.get(User, row.user_id)
    if not user:
        raise HTTPException(400, "This link is invalid or has expired")
    user.email_verified = True
    db.query(EmailToken).filter_by(user_id=user.id).delete()
    db.commit()
    _start_session(response, db, user)
    return _user_json(user)


@router.post("/resend-verification")
def resend_verification(body: EmailBody, background: BackgroundTasks, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=body.email.strip().lower()).first()
    if user and not user.email_verified:
        _queue_verification(db, user, background)
    # Same answer either way, so this can't be used to discover which emails have accounts.
    return {"ok": True}


@router.post("/login")
def login(body: Credentials, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter_by(email=body.email.strip().lower()).first()
    try:
        if not user:
            raise VerifyMismatchError()
        hasher.verify(user.password_hash, body.password)
    except VerifyMismatchError:
        raise HTTPException(401, "Invalid email or password")
    if not user.email_verified:
        raise HTTPException(403, "Please confirm your email first. Check your inbox for the link.")
    _start_session(response, db, user)
    return _user_json(user)


@router.post("/logout")
def logout(
    response: Response,
    token: str | None = Cookie(default=None, alias=COOKIE),
    db: Session = Depends(get_db),
):
    if token:
        db.query(AuthSession).filter_by(token_hash=_hash_token(token)).delete()
        db.commit()
    response.delete_cookie(COOKIE)
    return {"ok": True}


@router.get("/me")
def me(user: User = Depends(current_user)):
    return _user_json(user)