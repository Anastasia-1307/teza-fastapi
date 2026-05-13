from sqlalchemy import Column, String, DateTime, Text, ForeignKey, Integer, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime, timedelta
from database import Base
import uuid

class User(Base):
    __tablename__ = "users"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, unique=True, nullable=False)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    role = Column(String, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    passwords = relationship("Password", back_populates="user")
    refresh_tokens = relationship("RefreshToken", back_populates="user")
    categories = relationship("Category", back_populates="user")
    user_logs = relationship("UserLog", back_populates="user")
    persistent_refresh_tokens = relationship("PersistentRefreshToken", back_populates="user")

class Category(Base):
    __tablename__ = "categories"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String, nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    user = relationship("User", back_populates="categories")
    passwords = relationship("Password", back_populates="category")

class Password(Base):
    __tablename__ = "passwords"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    site_name = Column(String, nullable=False)
    url = Column(String)
    login = Column(String, nullable=False)
    password_encrypted = Column(String, nullable=False)
    description = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    category_id = Column(UUID(as_uuid=True), ForeignKey("categories.id"))
    user = relationship("User", back_populates="passwords")
    category = relationship("Category", back_populates="passwords")

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    token_hash = Column(String, unique=True, nullable=False)  # Hashed refresh token for security
    token_jti = Column(String, unique=True, nullable=False)  # JWT ID for blacklisting
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    user = relationship("User", back_populates="refresh_tokens")
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)

class BlacklistedToken(Base):
    __tablename__ = "blacklisted_tokens"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    jti = Column(String, unique=True, nullable=False)  # JWT ID
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class UserLog(Base):
    __tablename__ = "user_logs"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    action = Column(String, nullable=False)  # login, logout, register, password_created, password_updated, etc.
    ip_address = Column(String)  # IP address of the request
    user_agent = Column(Text)  # User agent string
    details = Column(Text)  # Additional details about the action
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="user_logs")

class IPAddressBlocked(Base):
    __tablename__ = "ip_address_blocked"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    ip_address = Column(String(45), nullable=False)  # IPv4 or IPv6
    blocked_at = Column(DateTime, default=datetime.utcnow)
    block_duration = Column(Integer, nullable=False)  # Duration in milliseconds
    is_active = Column(Boolean, default=True)
    username = Column(String(50))  # Username that triggered block
    failed_attempts = Column(Integer, default=1)
    expires_at = Column(DateTime)  # When block expires

class PersistentRefreshToken(Base):
    __tablename__ = "persistent_refresh_tokens"
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token_hash = Column(String, nullable=False)  # Hashed refresh token for security
    created_at = Column(DateTime, default=datetime.utcnow)
    last_used = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False, default=datetime.utcnow() + timedelta(days=30))  # 30 days from creation
    is_active = Column(Boolean, default=True)
    user = relationship("User", back_populates="persistent_refresh_tokens")