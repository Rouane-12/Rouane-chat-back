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
import json
import os
import uuid

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


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_message_type(filename: str) -> str:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext in ["jpg", "jpeg", "png", "gif", "webp", "svg"]:
        return "image"
    if ext in ["mp3", "wav", "ogg", "m4a", "aac", "webm"]:
        return "audio"
    return "file"


def serialize_message(m):
    return {
        "id": m.id,
        "sender_email": m.sender_email,
        "receiver_email": m.receiver_email,
        "content": m.content,
        "message_type": m.message_type,
        "file_url": m.file_url,
        "file_name": m.file_name,
        "file_size": m.file_size,
        "created_at": m.created_at.isoformat(),
        "edited_at": m.edited_at.isoformat() if m.edited_at else None,
        "deleted": m.deleted,
        "read": m.read
    }


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
        otp_entry = models.OTPCode(
            email=data.email,
            code=otp,
            purpose="register",
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )
        db.add(otp_entry)
        db.commit()
        send_otp_email(data.email, otp, "register")
        return {"message": "Code OTP envoyé par email."}
    except HTTPException:
        raise
    except Exception as e:
        print("ERREUR REGISTER:", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/verify-otp")
def verify_otp(data: OTPVerifySchema, db: Session = Depends(get_db)):
    try:
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
            db.commit()
            user = db.query(models.User).filter(models.User.email == data.email).first()
            if not user:
                raise HTTPException(status_code=404, detail="Utilisateur introuvable")
            user.is_verified = True
            db.commit()
            token = create_token({"sub": user.email})
            return {"message": "Compte vérifié", "access_token": token, "token_type": "bearer"}
        return {"message": "Code vérifié"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/resend-otp")
def resend_otp(data: ResendOTPSchema, db: Session = Depends(get_db)):
    try:
        db.query(models.OTPCode).filter(
            models.OTPCode.email == data.email,
            models.OTPCode.purpose == data.purpose
        ).delete()
        db.commit()
        otp = generate_otp()
        otp_entry = models.OTPCode(
            email=data.email,
            code=otp,
            purpose=data.purpose,
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )
        db.add(otp_entry)
        db.commit()
        send_otp_email(data.email, otp, data.purpose)
        return {"message": "Nouveau code généré."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/login")
def login(data: LoginSchema, db: Session = Depends(get_db)):
    try:
        user = db.query(models.User).filter(models.User.email == data.email).first()
        if not user or not verify_password(data.password, user.password):
            raise HTTPException(status_code=401, detail="Email ou mot de passe invalide")
        if not user.is_verified:
            raise HTTPException(status_code=403, detail="Compte non vérifié.")
        token = create_token({"sub": user.email})
        return {"access_token": token, "token_type": "bearer"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/forgot-password")
def forgot_password(data: ForgotPasswordSchema, db: Session = Depends(get_db)):
    try:
        user = db.query(models.User).filter(models.User.email == data.email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Aucun compte associé à cet email")
        db.query(models.OTPCode).filter(
            models.OTPCode.email == data.email,
            models.OTPCode.purpose == "reset"
        ).delete()
        db.commit()
        otp = generate_otp()
        otp_entry = models.OTPCode(
            email=data.email,
            code=otp,
            purpose="reset",
            expires_at=datetime.utcnow() + timedelta(minutes=10)
        )
        db.add(otp_entry)
        db.commit()
        send_otp_email(data.email, otp, "reset")
        return {"message": "Code généré."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/reset-password")
def reset_password(data: ResetPasswordSchema, db: Session = Depends(get_db)):
    try:
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
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/me")
def get_me(authorization: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        email = payload.get("sub")
        if not email:
            raise HTTPException(status_code=401, detail="Token invalide")
        user = db.query(models.User).filter(models.User.email == email).first()
        if not user:
            raise HTTPException(status_code=404, detail="Utilisateur introuvable")
        return {"email": user.email, "is_verified": user.is_verified}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/users")
def get_users(authorization: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        current_email = payload.get("sub")
        if not current_email:
            raise HTTPException(status_code=401, detail="Token invalide")
        users = db.query(models.User).filter(
            models.User.email != current_email,
            models.User.is_verified == True
        ).all()
        online = manager.get_online()
        return [{"email": u.email, "online": u.email in online} for u in users]
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/messages/{other_email}")
def get_messages(other_email: str, authorization: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        current_email = payload.get("sub")
        if not current_email:
            raise HTTPException(status_code=401, detail="Token invalide")
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
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/unread-counts")
def get_unread_counts(authorization: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        current_email = payload.get("sub")
        if not current_email:
            raise HTTPException(status_code=401, detail="Token invalide")
        msgs = db.query(chat_models.Message).filter(
            chat_models.Message.receiver_email == current_email,
            chat_models.Message.read == False,
            chat_models.Message.deleted == False
        ).all()
        counts = {}
        for m in msgs:
            counts[m.sender_email] = counts.get(m.sender_email, 0) + 1
        return counts
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/messages/{message_id}")
async def edit_message(message_id: int, data: EditMessageSchema, authorization: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        current_email = payload.get("sub")
        if not current_email:
            raise HTTPException(status_code=401, detail="Token invalide")
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
        await manager.send_to(msg.receiver_email, packet)
        await manager.send_to(msg.sender_email, packet)
        return serialize_message(msg)
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/messages/{message_id}")
async def delete_message(message_id: int, authorization: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        current_email = payload.get("sub")
        if not current_email:
            raise HTTPException(status_code=401, detail="Token invalide")
        msg = db.query(chat_models.Message).filter(chat_models.Message.id == message_id).first()
        if not msg:
            raise HTTPException(status_code=404, detail="Message introuvable")
        if msg.sender_email != current_email:
            raise HTTPException(status_code=403, detail="Non autorisé")
        msg.deleted = True
        msg.content = None
        db.commit()
        db.refresh(msg)
        packet = {"type": "message_deleted", "id": message_id, "sender_email": current_email, "receiver_email": msg.receiver_email}
        await manager.send_to(msg.receiver_email, packet)
        await manager.send_to(msg.sender_email, packet)
        return {"message": "Message supprimé"}
    except JWTError:
        raise HTTPException(status_code=401, detail="Token invalide ou expiré")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/upload")
async def upload_file(file: UploadFile = File(...), receiver: str = Form(...), authorization: str = Header(...)):
    db = SessionLocal()
    try:
        token = authorization.replace("Bearer ", "")
        payload = decode_token(token)
        sender_email = payload.get("sub")
        if not sender_email:
            raise HTTPException(status_code=401, detail="Token invalide")
        content = await file.read()
        if len(content) > 20 * 1024 * 1024:
            raise HTTPException(status_code=400, detail="Fichier trop volumineux (max 20MB)")
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        unique_name = f"{uuid.uuid4()}.{ext}" if ext else str(uuid.uuid4())
        with open(os.path.join(UPLOAD_DIR, unique_name), "wb") as f:
            f.write(content)
        msg_type = get_message_type(file.filename)
        file_url = f"http://localhost:8000/uploads/{unique_name}"
        msg = chat_models.Message(
            sender_email=sender_email,
            receiver_email=receiver,
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
        await manager.send_to(receiver, packet)
        await manager.send_to(sender_email, packet)
        return {"message": "Fichier envoyé", "file_url": file_url}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        db.close()


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

            if data.get("type") != "message":
                continue

            receiver = data.get("to", "").strip()
            content = data.get("content", "").strip()
            if not receiver or not content:
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

    except WebSocketDisconnect:
        pass
    except Exception as e:
        print(f"WS error ({email}): {e}")
    finally:
        if email:
            manager.disconnect(email)
            await manager.broadcast_online()
        db.close()