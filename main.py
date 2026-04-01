from fastapi import FastAPI, Depends, HTTPException, Header, WebSocket, WebSocketDisconnect, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from database import SessionLocal, engine
import models
import chat_models
from auth import hash_password, verify_password, create_token, decode_token, generate_otp
from email_service import send_otp_email
from chat import manager
from pydantic import BaseModel
from datetime import datetime, timedelta
from jose import JWTError
import json, os, uuid

models.Base.metadata.create_all(bind=engine)
chat_models.Base.metadata.create_all(bind=engine)

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI()
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIR), name="uploads")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_URL = os.getenv("BASE_URL", "https://rouane-chat-back.onrender.com")


# ─── helpers ──────────────────────────────────────────────────────────────────

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_current_email(authorization: str = Header(...)) -> str:
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Token invalide")
        return email
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")


def get_message_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in ["jpg", "jpeg", "png", "gif", "webp", "svg"]:
        return "image"
    if ext in ["mp3", "wav", "ogg", "m4a", "aac", "webm"]:
        return "audio"
    return "file"


def save_file(content: bytes, filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    unique_name = f"{uuid.uuid4()}.{ext}" if ext else str(uuid.uuid4())
    with open(os.path.join(UPLOAD_DIR, unique_name), "wb") as f:
        f.write(content)
    return f"{BASE_URL}/uploads/{unique_name}"


def serialize_message(m):
    return {
        "id": m.id,
        "sender_email": m.sender_email,
        "receiver_email": m.receiver_email,
        "group_id": m.group_id,
        "content": m.content,
        "message_type": m.message_type,
        "file_url": m.file_url,
        "file_name": m.file_name,
        "file_size": m.file_size,
        "created_at": m.created_at.isoformat(),
        "edited_at": m.edited_at.isoformat() if m.edited_at else None,
        "deleted": m.deleted,
        "read": m.read,
    }


def is_blocked(db, email_a: str, email_b: str) -> bool:
    return db.query(models.Block).filter(
        or_(
            and_(models.Block.blocker_email == email_a, models.Block.blocked_email == email_b),
            and_(models.Block.blocker_email == email_b, models.Block.blocked_email == email_a),
        )
    ).first() is not None


def are_friends(db, email_a: str, email_b: str) -> bool:
    return db.query(models.FriendRequest).filter(
        or_(
            and_(models.FriendRequest.sender_email == email_a, models.FriendRequest.receiver_email == email_b),
            and_(models.FriendRequest.sender_email == email_b, models.FriendRequest.receiver_email == email_a),
        ),
        models.FriendRequest.status == "accepted"
    ).first() is not None


# ─── schemas ──────────────────────────────────────────────────────────────────

class RegisterSchema(BaseModel):
    email: str
    password: str

class LoginSchema(BaseModel):
    email: str
    password: str

class OTPVerifySchema(BaseModel):
    email: str
    code: str
    purpose: str

class ForgotPasswordSchema(BaseModel):
    email: str

class ResetPasswordSchema(BaseModel):
    email: str
    code: str
    new_password: str

class ResendOTPSchema(BaseModel):
    email: str
    purpose: str

class EditMessageSchema(BaseModel):
    content: str

class FriendRequestSchema(BaseModel):
    receiver_email: str

class RespondFriendSchema(BaseModel):
    action: str  # "accept" | "decline"

class BlockSchema(BaseModel):
    email: str

class CreateGroupSchema(BaseModel):
    name: str
    members: list[str]

class AddMemberSchema(BaseModel):
    email: str

class UpdateProfileSchema(BaseModel):
    display_name: str | None = None
    bio: str | None = None

class CreateStorySchema(BaseModel):
    story_type: str   # image | video | text
    content: str | None = None
    bg_color: str | None = None
    file_url: str | None = None

class SendMessageSchema(BaseModel):
    to: str
    content: str


# ─── auth routes ──────────────────────────────────────────────────────────────

@app.post("/register")
def register(data: RegisterSchema, db: Session = Depends(get_db)):
    try:
        existing = db.query(models.User).filter(models.User.email == data.email).first()
        if existing and existing.is_verified:
            raise HTTPException(status_code=400, detail="Cet email est déjà utilisé")
        if existing and not existing.is_verified:
            existing.password = hash_password(data.password)
            db.commit()
        else:
            new_user = models.User(email=data.email, password=hash_password(data.password))
            db.add(new_user)
            db.commit()
        db.query(models.OTPCode).filter(
            models.OTPCode.email == data.email,
            models.OTPCode.purpose == "register"
        ).delete()
        db.commit()
        otp = generate_otp()
        db.add(models.OTPCode(
            email=data.email, code=otp, purpose="register",
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        ))
        db.commit()
        send_otp_email(data.email, otp, "register")
        return {"message": "Code OTP envoyé par email."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/verify-otp")
def verify_otp(data: OTPVerifySchema, db: Session = Depends(get_db)):
    otp_entry = db.query(models.OTPCode).filter(
        models.OTPCode.email == data.email,
        models.OTPCode.code == data.code,
        models.OTPCode.purpose == data.purpose,
        models.OTPCode.used == False
    ).first()
    if not otp_entry:
        raise HTTPException(status_code=400, detail="Code OTP invalide")
    if otp_entry.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Code OTP expiré")
    if data.purpose == "register":
        otp_entry.used = True
        user = db.query(models.User).filter(models.User.email == data.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        user.is_verified = True
        db.commit()
        token = create_token({"sub": user.email})
        return {"message": "Compte vérifié", "access_token": token, "token_type": "bearer"}
    otp_entry.used = True
    db.commit()
    return {"message": "Code vérifié"}


@app.post("/resend-otp")
def resend_otp(data: ResendOTPSchema, db: Session = Depends(get_db)):
    db.query(models.OTPCode).filter(
        models.OTPCode.email == data.email,
        models.OTPCode.purpose == data.purpose
    ).delete()
    db.commit()
    otp = generate_otp()
    db.add(models.OTPCode(
        email=data.email, code=otp, purpose=data.purpose,
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    ))
    db.commit()
    send_otp_email(data.email, otp, data.purpose)
    return {"message": "Nouveau code généré."}


@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user or not verify_password(data.password, user.password):
        raise HTTPException(status_code=401, detail="Email ou mot de passe invalide")
    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Compte non vérifié.")
    token = create_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}


@app.post("/forgot-password")
def forgot_password(data: ForgotPasswordSchema, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Aucun compte associé à cet email")
    db.query(models.OTPCode).filter(
        models.OTPCode.email == data.email,
        models.OTPCode.purpose == "reset"
    ).delete()
    db.commit()
    otp = generate_otp()
    db.add(models.OTPCode(
        email=data.email, code=otp, purpose="reset",
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    ))
    db.commit()
    send_otp_email(data.email, otp, "reset")
    return {"message": "Code généré."}


@app.post("/reset-password")
def reset_password(data: ResetPasswordSchema, db: Session = Depends(get_db)):
    otp_entry = db.query(models.OTPCode).filter(
        models.OTPCode.email == data.email,
        models.OTPCode.code == data.code,
        models.OTPCode.purpose == "reset",
        models.OTPCode.used == False
    ).first()
    if not otp_entry:
        raise HTTPException(status_code=400, detail="Code OTP invalide")
    if otp_entry.expires_at < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Code OTP expiré")
    otp_entry.used = True
    user = db.query(models.User).filter(models.User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    user.password = hash_password(data.new_password)
    db.commit()
    return {"message": "Mot de passe réinitialisé avec succès"}


# ─── user / profile routes ────────────────────────────────────────────────────

@app.get("/me")
def get_me(current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == current_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    return {
        "email": user.email,
        "is_verified": user.is_verified,
        "display_name": user.display_name,
        "bio": user.bio,
        "avatar_url": user.avatar_url,
    }


@app.put("/profile")
def update_profile(data: UpdateProfileSchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == current_email).first()
    if not user:
        raise HTTPException(status_code=404, detail="Utilisateur introuvable")
    if data.display_name is not None:
        user.display_name = data.display_name
    if data.bio is not None:
        user.bio = data.bio
    db.commit()
    db.refresh(user)
    return {"email": user.email, "display_name": user.display_name, "bio": user.bio, "avatar_url": user.avatar_url}


@app.post("/profile/avatar")
async def upload_avatar(file: UploadFile = File(...), current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image trop volumineuse (max 5MB)")
    url = save_file(content, file.filename)
    user = db.query(models.User).filter(models.User.email == current_email).first()
    user.avatar_url = url
    db.commit()
    return {"avatar_url": url}


@app.get("/users/search")
def search_users(q: str = "", current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    """Search users to add as friends (excluding existing friends and blocked)."""
    blocked_emails = set()
    blocks = db.query(models.Block).filter(
        or_(models.Block.blocker_email == current_email, models.Block.blocked_email == current_email)
    ).all()
    for b in blocks:
        blocked_emails.add(b.blocker_email)
        blocked_emails.add(b.blocked_email)
    blocked_emails.discard(current_email)

    friend_emails = set()
    friends = db.query(models.FriendRequest).filter(
        or_(
            models.FriendRequest.sender_email == current_email,
            models.FriendRequest.receiver_email == current_email,
        ),
        models.FriendRequest.status == "accepted"
    ).all()
    for f in friends:
        friend_emails.add(f.sender_email)
        friend_emails.add(f.receiver_email)
    friend_emails.discard(current_email)

    pending_sent = set()
    sent = db.query(models.FriendRequest).filter(
        models.FriendRequest.sender_email == current_email,
        models.FriendRequest.status == "pending"
    ).all()
    for s in sent:
        pending_sent.add(s.receiver_email)

    users = db.query(models.User).filter(
        models.User.email != current_email,
        models.User.is_verified == True,
        models.User.email.notin_(blocked_emails),
        models.User.email.notin_(friend_emails),
    ).all()

    results = []
    for u in users:
        if q.lower() in u.email.lower() or (u.display_name and q.lower() in u.display_name.lower()):
            results.append({
                "email": u.email,
                "display_name": u.display_name,
                "avatar_url": u.avatar_url,
                "request_sent": u.email in pending_sent,
            })
    return results


@app.get("/users")
def get_users(current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    users = db.query(models.User).filter(
        models.User.email != current_email,
        models.User.is_verified == True
    ).all()

    return [
        {
            "email": u.email,
            "display_name": u.display_name,
            "avatar_url": u.avatar_url,
        }
        for u in users
    ]


@app.get("/friends")
def get_friends(current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    online = manager.get_online()
    friends = db.query(models.FriendRequest).filter(
        or_(
            models.FriendRequest.sender_email == current_email,
            models.FriendRequest.receiver_email == current_email,
        ),
        models.FriendRequest.status == "accepted"
    ).all()
    result = []
    for f in friends:
        email = f.receiver_email if f.sender_email == current_email else f.sender_email
        user = db.query(models.User).filter(models.User.email == email).first()
        if user:
            result.append({
                "email": user.email,
                "display_name": user.display_name,
                "avatar_url": user.avatar_url,
                "online": email in online,
            })
    return result


# ─── friend request routes ────────────────────────────────────────────────────

@app.post("/friend-request")
async def send_friend_request(data: FriendRequestSchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    if data.receiver_email == current_email:
        raise HTTPException(status_code=400, detail="Impossible de s'ajouter soi-même")
    if is_blocked(db, current_email, data.receiver_email):
        raise HTTPException(status_code=403, detail="Action impossible")
    existing = db.query(models.FriendRequest).filter(
        or_(
            and_(models.FriendRequest.sender_email == current_email, models.FriendRequest.receiver_email == data.receiver_email),
            and_(models.FriendRequest.sender_email == data.receiver_email, models.FriendRequest.receiver_email == current_email),
        )
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Demande déjà existante")
    req = models.FriendRequest(sender_email=current_email, receiver_email=data.receiver_email)
    db.add(req)
    db.commit()
    db.refresh(req)
    # Notify receiver via WebSocket
    await manager.send_to(data.receiver_email, {"type": "friend_request", "from": current_email, "request_id": req.id})
    return {"message": "Demande envoyée"}


@app.get("/friend-requests/pending")
def get_pending_requests(current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    reqs = db.query(models.FriendRequest).filter(
        models.FriendRequest.receiver_email == current_email,
        models.FriendRequest.status == "pending"
    ).all()
    result = []
    for r in reqs:
        user = db.query(models.User).filter(models.User.email == r.sender_email).first()
        result.append({
            "id": r.id,
            "sender_email": r.sender_email,
            "display_name": user.display_name if user else None,
            "avatar_url": user.avatar_url if user else None,
            "created_at": r.created_at.isoformat(),
        })
    return result


@app.put("/friend-request/{req_id}")
async def respond_friend_request(req_id: int, data: RespondFriendSchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    req = db.query(models.FriendRequest).filter(models.FriendRequest.id == req_id).first()
    if not req or req.receiver_email != current_email:
        raise HTTPException(status_code=404, detail="Demande introuvable")
    if data.action == "accept":
        req.status = "accepted"
        db.commit()
        await manager.send_to(req.sender_email, {"type": "friend_accepted", "by": current_email})
        return {"message": "Demande acceptée"}
    elif data.action == "decline":
        req.status = "declined"
        db.commit()
        return {"message": "Demande refusée"}
    raise HTTPException(status_code=400, detail="Action invalide")


@app.delete("/friend/{email}")
async def remove_friend(email: str, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    req = db.query(models.FriendRequest).filter(
        or_(
            and_(models.FriendRequest.sender_email == current_email, models.FriendRequest.receiver_email == email),
            and_(models.FriendRequest.sender_email == email, models.FriendRequest.receiver_email == current_email),
        ),
        models.FriendRequest.status == "accepted"
    ).first()
    if not req:
        raise HTTPException(status_code=404, detail="Ami introuvable")
    db.delete(req)
    db.commit()
    return {"message": "Ami supprimé"}


# ─── block routes ─────────────────────────────────────────────────────────────

@app.post("/block")
def block_user(data: BlockSchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    existing = db.query(models.Block).filter(
        models.Block.blocker_email == current_email,
        models.Block.blocked_email == data.email
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Déjà bloqué")
    db.add(models.Block(blocker_email=current_email, blocked_email=data.email))
    # Also remove friendship if any
    db.query(models.FriendRequest).filter(
        or_(
            and_(models.FriendRequest.sender_email == current_email, models.FriendRequest.receiver_email == data.email),
            and_(models.FriendRequest.sender_email == data.email, models.FriendRequest.receiver_email == current_email),
        )
    ).delete()
    db.commit()
    return {"message": "Utilisateur bloqué"}


@app.delete("/block/{email}")
def unblock_user(email: str, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    block = db.query(models.Block).filter(
        models.Block.blocker_email == current_email,
        models.Block.blocked_email == email
    ).first()
    if not block:
        raise HTTPException(status_code=404, detail="Non bloqué")
    db.delete(block)
    db.commit()
    return {"message": "Utilisateur débloqué"}


@app.get("/blocked")
def get_blocked(current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    blocks = db.query(models.Block).filter(models.Block.blocker_email == current_email).all()
    return [{"email": b.blocked_email} for b in blocks]


# ─── message routes ───────────────────────────────────────────────────────────

@app.get("/messages/{other_email}")
def get_messages(other_email: str, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    if is_blocked(db, current_email, other_email):
        raise HTTPException(status_code=403, detail="Impossible de voir ces messages")
    msgs = db.query(chat_models.Message).filter(
        or_(
            and_(chat_models.Message.sender_email == current_email, chat_models.Message.receiver_email == other_email),
            and_(chat_models.Message.sender_email == other_email, chat_models.Message.receiver_email == current_email)
        )
    ).order_by(chat_models.Message.created_at.asc()).all()
    for m in msgs:
        if m.receiver_email == current_email and not m.read:
            m.read = True
    db.commit()
    return [serialize_message(m) for m in msgs]


@app.delete("/conversation/{other_email}")
def delete_conversation(other_email: str, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    """Soft-delete all messages in a conversation (only for current user's side)."""
    db.query(chat_models.Message).filter(
        or_(
            and_(chat_models.Message.sender_email == current_email, chat_models.Message.receiver_email == other_email),
            and_(chat_models.Message.sender_email == other_email, chat_models.Message.receiver_email == current_email)
        )
    ).delete()
    db.commit()
    return {"message": "Conversation supprimée"}


@app.get("/unread-counts")
def get_unread_counts(current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    msgs = db.query(chat_models.Message).filter(
        chat_models.Message.receiver_email == current_email,
        chat_models.Message.read == False,
        chat_models.Message.deleted == False
    ).all()
    counts = {}
    for m in msgs:
        counts[m.sender_email] = counts.get(m.sender_email, 0) + 1
    return counts


@app.put("/messages/{message_id}")
async def edit_message(message_id: int, data: EditMessageSchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    msg = db.query(chat_models.Message).filter(chat_models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message introuvable")
    if msg.sender_email != current_email:
        raise HTTPException(status_code=403, detail="Non autorisé")
    if msg.message_type != "text":
        raise HTTPException(status_code=400, detail="Seuls les messages texte peuvent être modifiés")
    msg.content = data.content
    msg.edited_at = datetime.utcnow()
    db.commit()
    db.refresh(msg)
    packet = {"type": "message_edited", **serialize_message(msg)}
    target = msg.receiver_email if msg.receiver_email else None
    if target:
        await manager.send_to(target, packet)
    await manager.send_to(msg.sender_email, packet)
    return serialize_message(msg)


@app.delete("/messages/{message_id}")
async def delete_message(message_id: int, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    msg = db.query(chat_models.Message).filter(chat_models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Message introuvable")
    if msg.sender_email != current_email:
        raise HTTPException(status_code=403, detail="Non autorisé")
    msg.deleted = True
    msg.content = None
    db.commit()
    packet = {"type": "message_deleted", "id": message_id, "sender_email": current_email, "receiver_email": msg.receiver_email, "group_id": msg.group_id}
    if msg.receiver_email:
        await manager.send_to(msg.receiver_email, packet)
    await manager.send_to(msg.sender_email, packet)
    return {"message": "Message supprimé"}


@app.post("/send-message")
async def send_message_http(data: SendMessageSchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    if is_blocked(db, current_email, data.to):
        raise HTTPException(status_code=403, detail="Impossible d'envoyer un message")
    if not are_friends(db, current_email, data.to):
        raise HTTPException(status_code=403, detail="Vous n'êtes pas amis")
    msg = chat_models.Message(
        sender_email=current_email,
        receiver_email=data.to,
        content=data.content,
        message_type="text",
        created_at=datetime.utcnow()
    )
    db.add(msg)
    db.commit()
    db.refresh(msg)
    packet = {"type": "message", **serialize_message(msg)}
    await manager.send_to(data.to, packet)
    await manager.send_to(current_email, packet)
    return serialize_message(msg)


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    receiver: str = Form(None),
    group_id: int = Form(None),
    authorization: str = Header(...),
    db: Session = Depends(get_db)
):
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        sender_email = payload.get("sub")
        if not sender_email:
            raise HTTPException(status_code=401, detail="Token invalide")
        if receiver and is_blocked(db, sender_email, receiver):
            raise HTTPException(status_code=403, detail="Impossible d'envoyer un fichier")
        content = await file.read()
        if len(content) > 20 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Fichier trop volumineux (max 20MB)")
        file_url = save_file(content, file.filename)
        msg_type = get_message_type(file.filename)
        msg = chat_models.Message(
            sender_email=sender_email,
            receiver_email=receiver,
            group_id=group_id,
            content=None,
            message_type=msg_type,
            file_url=file_url,
            file_name=file.filename,
            file_size=len(content),
            created_at=datetime.utcnow()
        )
        db.add(msg)
        db.commit()
        db.refresh(msg)
        packet = {"type": "message", **serialize_message(msg)}
        if receiver:
            await manager.send_to(receiver, packet)
        elif group_id:
            members = db.query(models.GroupMember).filter(models.GroupMember.group_id == group_id).all()
            for m in members:
                await manager.send_to(m.email, packet)
        await manager.send_to(sender_email, packet)
        return {"message": "Fichier envoyé", "file_url": file_url}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ─── group routes ─────────────────────────────────────────────────────────────

@app.post("/groups")
def create_group(data: CreateGroupSchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    group = models.Group(name=data.name, created_by=current_email)
    db.add(group)
    db.commit()
    db.refresh(group)
    # Add creator as admin
    db.add(models.GroupMember(group_id=group.id, email=current_email, role="admin"))
    for email in data.members:
        if email != current_email:
            db.add(models.GroupMember(group_id=group.id, email=email, role="member"))
    db.commit()
    return {"id": group.id, "name": group.name, "created_by": group.created_by}


@app.get("/groups")
def get_groups(current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    memberships = db.query(models.GroupMember).filter(models.GroupMember.email == current_email).all()
    result = []
    for m in memberships:
        group = db.query(models.Group).filter(models.Group.id == m.group_id).first()
        if group:
            member_count = db.query(models.GroupMember).filter(models.GroupMember.group_id == group.id).count()
            result.append({
                "id": group.id,
                "name": group.name,
                "avatar_url": group.avatar_url,
                "created_by": group.created_by,
                "member_count": member_count,
                "role": m.role,
            })
    return result


@app.get("/groups/{group_id}/messages")
def get_group_messages(group_id: int, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    member = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id,
        models.GroupMember.email == current_email
    ).first()
    if not member:
        raise HTTPException(status_code=403, detail="Non membre de ce groupe")
    msgs = db.query(chat_models.Message).filter(
        chat_models.Message.group_id == group_id
    ).order_by(chat_models.Message.created_at.asc()).all()
    return [serialize_message(m) for m in msgs]


@app.post("/groups/{group_id}/members")
def add_group_member(group_id: int, data: AddMemberSchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    admin = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id,
        models.GroupMember.email == current_email,
        models.GroupMember.role == "admin"
    ).first()
    if not admin:
        raise HTTPException(status_code=403, detail="Vous n'êtes pas admin de ce groupe")
    existing = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id,
        models.GroupMember.email == data.email
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Déjà membre")
    db.add(models.GroupMember(group_id=group_id, email=data.email, role="member"))
    db.commit()
    return {"message": "Membre ajouté"}


@app.delete("/groups/{group_id}/members/{email}")
def remove_group_member(group_id: int, email: str, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    admin = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id,
        models.GroupMember.email == current_email,
        models.GroupMember.role == "admin"
    ).first()
    if not admin and current_email != email:
        raise HTTPException(status_code=403, detail="Non autorisé")
    member = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id,
        models.GroupMember.email == email
    ).first()
    if not member:
        raise HTTPException(status_code=404, detail="Membre introuvable")
    db.delete(member)
    db.commit()
    return {"message": "Membre retiré"}


@app.get("/groups/{group_id}/members")
def get_group_members(group_id: int, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    member = db.query(models.GroupMember).filter(
        models.GroupMember.group_id == group_id,
        models.GroupMember.email == current_email
    ).first()
    if not member:
        raise HTTPException(status_code=403, detail="Non membre de ce groupe")
    members = db.query(models.GroupMember).filter(models.GroupMember.group_id == group_id).all()
    result = []
    for m in members:
        user = db.query(models.User).filter(models.User.email == m.email).first()
        result.append({
            "email": m.email,
            "display_name": user.display_name if user else None,
            "avatar_url": user.avatar_url if user else None,
            "role": m.role,
        })
    return result


# ─── story routes ─────────────────────────────────────────────────────────────

@app.post("/stories")
def create_story(data: CreateStorySchema, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    story = models.Story(
        author_email=current_email,
        story_type=data.story_type,
        content=data.content,
        file_url=data.file_url,
        bg_color=data.bg_color,
        expires_at=datetime.utcnow() + timedelta(hours=24)
    )
    db.add(story)
    db.commit()
    db.refresh(story)
    return {"id": story.id, "message": "Story publiée"}


@app.post("/stories/upload")
async def upload_story_media(file: UploadFile = File(...), authorization: str = Header(...)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        if not payload.get("sub"):
            raise HTTPException(status_code=401, detail="Token invalide")
        content = await file.read()
        if len(content) > 50 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Fichier trop volumineux (max 50MB)")
        url = save_file(content, file.filename)
        return {"file_url": url}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/stories")
def get_stories(current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    """Get active stories from friends."""
    friends_emails = set()
    friends = db.query(models.FriendRequest).filter(
        or_(
            models.FriendRequest.sender_email == current_email,
            models.FriendRequest.receiver_email == current_email,
        ),
        models.FriendRequest.status == "accepted"
    ).all()
    for f in friends:
        friends_emails.add(f.sender_email)
        friends_emails.add(f.receiver_email)
    friends_emails.add(current_email)
    friends_emails.discard(current_email)

    # Include own stories + friends' stories
    visible_emails = friends_emails | {current_email}
    now = datetime.utcnow()
    stories = db.query(models.Story).filter(
        models.Story.author_email.in_(visible_emails),
        models.Story.expires_at > now
    ).order_by(models.Story.created_at.desc()).all()

    viewed_ids = set(
        v.story_id for v in db.query(models.StoryView).filter(
            models.StoryView.viewer_email == current_email
        ).all()
    )

    result = []
    for s in stories:
        user = db.query(models.User).filter(models.User.email == s.author_email).first()
        result.append({
            "id": s.id,
            "author_email": s.author_email,
            "display_name": user.display_name if user else None,
            "avatar_url": user.avatar_url if user else None,
            "story_type": s.story_type,
            "content": s.content,
            "file_url": s.file_url,
            "bg_color": s.bg_color,
            "expires_at": s.expires_at.isoformat(),
            "created_at": s.created_at.isoformat(),
            "viewed": s.id in viewed_ids,
        })
    return result


@app.post("/stories/{story_id}/view")
def mark_story_viewed(story_id: int, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    existing = db.query(models.StoryView).filter(
        models.StoryView.story_id == story_id,
        models.StoryView.viewer_email == current_email
    ).first()
    if not existing:
        db.add(models.StoryView(story_id=story_id, viewer_email=current_email))
        db.commit()
    return {"message": "Vue enregistrée"}


@app.delete("/stories/{story_id}")
def delete_story(story_id: int, current_email: str = Depends(get_current_email), db: Session = Depends(get_db)):
    story = db.query(models.Story).filter(models.Story.id == story_id).first()
    if not story or story.author_email != current_email:
        raise HTTPException(status_code=404, detail="Story introuvable")
    db.delete(story)
    db.commit()
    return {"message": "Story supprimée"}


# ─── WebSocket ────────────────────────────────────────────────────────────────

@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    db = SessionLocal()
    email = None
    try:
        try:
            payload = decode_token(token)
            email = payload.get("sub")
            if not email:
                await websocket.close(code=1008)
                return
        except JWTError:
            await websocket.close(code=1008)
            return

        await manager.connect(websocket, email)
        await manager.broadcast_online()

        while True:
            raw = await websocket.receive_text()
            try:
                data = json.loads(raw)
            except Exception:
                continue

            msg_type = data.get("type")

            # ── Direct text message ──
            if msg_type == "message":
                receiver = data.get("to", "").strip()
                content = data.get("content", "").strip()
                if not receiver or not content:
                    continue
                if is_blocked(db, email, receiver):
                    continue
                if not are_friends(db, email, receiver):
                    continue
                msg = chat_models.Message(
                    sender_email=email,
                    receiver_email=receiver,
                    content=content,
                    message_type="text",
                    created_at=datetime.utcnow()
                )
                db.add(msg)
                db.commit()
                db.refresh(msg)
                packet = {"type": "message", **serialize_message(msg)}
                await manager.send_to(receiver, packet)
                await manager.send_to(email, packet)

            # ── Group text message ──
            elif msg_type == "group_message":
                group_id = data.get("group_id")
                content = data.get("content", "").strip()
                if not group_id or not content:
                    continue
                member = db.query(models.GroupMember).filter(
                    models.GroupMember.group_id == group_id,
                    models.GroupMember.email == email
                ).first()
                if not member:
                    continue
                msg = chat_models.Message(
                    sender_email=email,
                    group_id=group_id,
                    content=content,
                    message_type="text",
                    created_at=datetime.utcnow()
                )
                db.add(msg)
                db.commit()
                db.refresh(msg)
                packet = {"type": "message", **serialize_message(msg)}
                members = db.query(models.GroupMember).filter(models.GroupMember.group_id == group_id).all()
                for m in members:
                    await manager.send_to(m.email, packet)

            # ── WebRTC signaling ──
            elif msg_type in ("call_offer", "call_answer", "call_ice", "call_end", "call_reject"):
                target = data.get("to")
                if target:
                    await manager.send_to(target, {**data, "from": email})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WS error ({email}): {e}")
    finally:
        if email:
            manager.disconnect(email)
            await manager.broadcast_online()
        db.close()