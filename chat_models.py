from sqlalchemy import Column, Integer, String, DateTime, Boolean
from datetime import datetime
from database import Base


class Message(Base):
    __tablename__ = "messages"

    id = Column(Integer, primary_key=True, index=True)
    sender_email = Column(String, index=True)
    receiver_email = Column(String, index=True)
    content = Column(String, nullable=True)
    message_type = Column(String, default="text")
    file_url = Column(String, nullable=True)
    file_name = Column(String, nullable=True)
    file_size = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    edited_at = Column(DateTime, nullable=True)
    deleted = Column(Boolean, default=False)
    read = Column(Boolean, default=False)