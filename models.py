from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from datetime import datetime
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)
    is_verified = Column(Boolean, default=False)
    display_name = Column(String, nullable=True)
    bio = Column(String, nullable=True)
    avatar_url = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class OTPCode(Base):
    __tablename__ = "otp_codes"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, index=True)
    code = Column(String)
    purpose = Column(String)  # "register" | "reset"
    expires_at = Column(DateTime)
    used = Column(Boolean, default=False)


class FriendRequest(Base):
    __tablename__ = "friend_requests"

    id = Column(Integer, primary_key=True, index=True)
    sender_email = Column(String, index=True)
    receiver_email = Column(String, index=True)
    status = Column(String, default="pending")  # pending | accepted | declined
    created_at = Column(DateTime, default=datetime.utcnow)


class Block(Base):
    __tablename__ = "blocks"

    id = Column(Integer, primary_key=True, index=True)
    blocker_email = Column(String, index=True)
    blocked_email = Column(String, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class Group(Base):
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String)
    avatar_url = Column(String, nullable=True)
    created_by = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)


class GroupMember(Base):
    __tablename__ = "group_members"

    id = Column(Integer, primary_key=True, index=True)
    group_id = Column(Integer, ForeignKey("groups.id"))
    email = Column(String, index=True)
    role = Column(String, default="member")  
    joined_at = Column(DateTime, default=datetime.utcnow)


class Story(Base):
    __tablename__ = "stories"

    id = Column(Integer, primary_key=True, index=True)
    author_email = Column(String, index=True)
    story_type = Column(String)  
    content = Column(Text, nullable=True)       
    file_url = Column(String, nullable=True)    
    bg_color = Column(String, nullable=True)    
    expires_at = Column(DateTime)               
    created_at = Column(DateTime, default=datetime.utcnow)


class StoryView(Base):
    __tablename__ = "story_views"

    id = Column(Integer, primary_key=True, index=True)
    story_id = Column(Integer, ForeignKey("stories.id"))
    viewer_email = Column(String)
    viewed_at = Column(DateTime, default=datetime.utcnow)