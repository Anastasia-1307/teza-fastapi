from pydantic import BaseModel, constr, Field, ConfigDict, field_validator
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any

class Role(str, Enum):
    user = "user"
    admin = "admin"

class Register(BaseModel):
    username: str = Field(min_length=8, max_length=30, pattern=r"^[a-zA-Z0-9]{8,30}$")
    email: str = Field(min_length=2, max_length=320, pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")
    password: str = Field(min_length=8, max_length=30)
    role: Role = Role.user
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '*&#@$%!\\-_ ' for c in v):
            raise ValueError('Password must contain at least one special character (*&#@$%!\\-_ )')
        return v

class Login(BaseModel):
    username: str = Field(min_length=8, max_length=30, pattern=r"^[a-zA-Z0-9]{8,30}$")
    password: str = Field(min_length=8, max_length=30)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '*&#@$%!\\-_ ' for c in v):
            raise ValueError('Password must contain at least one special character (*&#@$%!\\-_ )')
        return v
   
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class UserResponse(BaseModel):
    id: str
    username: str
    role: Role
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class UserLogResponse(BaseModel):
    id: str
    user_id: str
    action: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    details: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

class CategoryCreate(BaseModel):
    name: constr(min_length=1, max_length=50)

class CategoryResponse(BaseModel):
    id: str
    name: str
    user_id: str

    model_config = ConfigDict(from_attributes=True)

class PasswordCreate(BaseModel):
    site_name: constr(min_length=1, max_length=100)
    url: Optional[constr(max_length=255)] = None
    login: constr(min_length=1, max_length=100)
    password: constr(min_length=1, max_length=255)
    description: Optional[constr(max_length=500)] = None
    category_id: Optional[str] = None


class PasswordResponse(BaseModel):
    id: str
    site_name: str
    url: Optional[str] = None
    login: str
    password_encrypted: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    user_id: str
    category_id: Optional[str] = None
    category_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class PasswordDecryptResponse(BaseModel):
    id: str
    site_name: str
    url: Optional[str] = None
    login: str
    password: str
    description: Optional[str] = None
    created_at: datetime
    updated_at: datetime
    user_id: str
    category_id: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)

class IPAddressBlockedResponse(BaseModel):
    id: str
    ip_address: str
    blocked_at: datetime
    block_duration: int
    is_active: bool
    username: Optional[str] = None
    failed_attempts: int
    expires_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)

class IPAddressBlockCreate(BaseModel):
    ip_address: constr(min_length=7, max_length=45)  # IPv4 or IPv6
    block_duration: int = Field(gt=0, description="Block duration in milliseconds")
    username: Optional[constr(max_length=50)] = None
    failed_attempts: int = Field(default=1, ge=1)

class IPAddressBlockUpdate(BaseModel):
    is_active: Optional[bool] = None
    block_duration: Optional[int] = Field(None, gt=0, description="Block duration in milliseconds")
    expires_at: Optional[datetime] = None

class E2EESetupRequest(BaseModel):
    password: constr(min_length=8, max_length=30)

class E2EEMasterKeyResponse(BaseModel):
    encrypted_master_key: str
    master_key_salt: str
    message: str

class PasswordCreateE2EE(BaseModel):
    site_name: constr(min_length=1, max_length=100)
    url: Optional[constr(max_length=255)] = None
    login: constr(min_length=1, max_length=100)
    password_encrypted: constr(min_length=1)  # Already encrypted by client
    description: Optional[constr(max_length=500)] = None
    category_id: Optional[str] = None
