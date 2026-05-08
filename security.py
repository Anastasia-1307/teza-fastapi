import secrets
import base64
from typing import Tuple, Optional, Dict, Any
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import hashlib
import jwt
from datetime import datetime, timedelta
import uuid
import string
import re
from fastapi import Depends, HTTPException, Request
from fastapi.responses import Response
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from models import UserLog, IPAddressBlocked
import os
from dotenv import load_dotenv
from models import User
from database import get_db
from zoneinfo import ZoneInfo

# Configure timezone for Moldova
MOLDOVA_TZ = ZoneInfo("Europe/Chisinau")

# încarcă variabilele din fișier
load_dotenv(".env.local")

# Load secrets from environment variables
secret_key = os.getenv("JWT_SECRET_KEY")
if not secret_key:
    raise ValueError("JWT_SECRET_KEY environment variable is required")

AES_KEY = os.getenv("AES_ENCRYPTION_KEY")
if not AES_KEY:
    raise ValueError("AES_ENCRYPTION_KEY environment variable is required")
    
# Convert from hex string to bytes
AES_KEY = bytes.fromhex(AES_KEY)

# Argon2ID configuration for password hashing
ph = PasswordHasher(
    time_cost=3,       # Number of iterations
    memory_cost=65536, # Memory usage in KB
    parallelism=4,     # Number of parallel threads
    hash_len=32,       # Hash length
    salt_len=16        # Salt length
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl= "/auth")

def hash_password(password: str) -> str:
    """
    Hash a password using Argon2ID
    

    """
    return ph.hash(password)

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    user_data = extract_user_from_token(token)
    if not user_data:
        print(f"Token validation failed - token: {token[:20]}...")
        raise HTTPException(status_code=401, detail="Token invalid sau expirat")
    
    print(f"Token validated for user {user_data['user_id']} at {datetime.utcnow()}")
    user = db.query(User).filter(User.id == user_data["user_id"]).first()
    if not user:
        raise HTTPException(status_code=401, detail="Utilizator negăsit")
    
    return user


def require_role(required_role: str):
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role != required_role:
            raise HTTPException(status_code=403, detail="Neautorizat")
        return current_user
    return role_checker




def verify_password(password: str, hashed_password: str) -> bool:
   
    try:
        ph.verify(hashed_password, password)
        return True
    except VerifyMismatchError:
        return False

def encrypt_password(password: str, user_master_key: bytes = None) -> str:
 
    # Use user master key if provided, otherwise use system key
    key = user_master_key if user_master_key else AES_KEY
    
    # Generate a random nonce (12 bytes for GCM)
    nonce = os.urandom(12)
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    # Encrypt the password
    encrypted = encryptor.update(password.encode()) + encryptor.finalize()
    # Get the authentication tag
    tag = encryptor.tag
    # Combine nonce + tag + encrypted data and encode in base64
    combined = nonce + tag + encrypted
    encrypted_b64 = base64.b64encode(combined).decode('utf-8')
    
    return encrypted_b64

def decrypt_password(encrypted_b64: str, user_master_key: bytes = None) -> str:
 
    # Use user master key if provided, otherwise use system key
    key = user_master_key if user_master_key else AES_KEY
    
    # Decode from base64
    combined = base64.b64decode(encrypted_b64.encode('utf-8'))
    
    # Extract nonce, tag, and encrypted data
    nonce = combined[:12]
    tag = combined[12:28]
    encrypted = combined[28:]
    
    # Create cipher
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    # Decrypt the data

    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    
    return decrypted.decode('utf-8')

def generate_master_key() -> str:
    """
    Generate a master key for user to encrypt their passwords
    
    Returns:
        Base64 encoded master key
    """
    return secrets.token_urlsafe(32)

def derive_key_from_master(master_key_b64: str, salt: bytes = None) -> Tuple[bytes, bytes]:
  
    
    if salt is None:
        salt = secrets.token_bytes(16)
    
    master_key = base64.urlsafe_b64decode(master_key_b64.encode())
    
    # Use PBKDF2 with HMAC-SHA256
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        master_key,
        salt,
        100000,  # iterations
        32       # key length
    )
    
    return derived_key, salt

def verify_master_key(master_key_b64: str, stored_hash: str) -> bool:
   
    try:
        master_key_bytes = base64.urlsafe_b64decode(master_key_b64.encode())
        ph.verify(stored_hash, master_key_bytes.decode('utf-8', errors='ignore'))
        return True
    except (VerifyMismatchError, Exception):
        return False

def hash_master_key(master_key_b64: str) -> str:
  
    master_key_bytes = base64.urlsafe_b64decode(master_key_b64.encode())
    return ph.hash(master_key_bytes.decode('utf-8', errors='ignore'))

def generate_password(length: int = 16, include_symbols: bool = True) -> str:
 
    if include_symbols:
        characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    else:
        characters = string.ascii_letters + string.digits
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password

def check_password_strength(password: str) -> dict:
    
    score = 0
    feedback = []
    
    # Length check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long")
    
    # Character variety checks
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Include lowercase letters")
    
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Include uppercase letters")
    
    if re.search(r'\d', password):
        score += 1
    else:
        feedback.append("Include numbers")
    
    if re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password):
        score += 1
    else:
        feedback.append("Include special characters")
    
    # Determine strength level
    if score >= 6:
        strength = "Very Strong"
    elif score >= 5:
        strength = "Strong"
    elif score >= 4:
        strength = "Medium"
    elif score >= 3:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    return {
        "score": score,
        "strength": strength,
        "feedback": feedback,
        "max_score": 6
    }

# JWT Token Configuration
ALGORITHM = os.getenv("ALGORITHM")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS"))

def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    
    print(f"Creating access token for user {data.get('sub', 'unknown')} that expires at {expire}")
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)
    return encoded_jwt

def hash_token(token: str) -> str:
    """
    Hash a token using Argon2ID for secure storage
    """
    return ph.hash(token)

def verify_hashed_token(token: str, token_hash: str) -> bool:
    """
    Verify a token against its hash
    """
    try:
        ph.verify(token_hash, token)
        return True
    except VerifyMismatchError:
        return False

def create_refresh_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
  
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh",
        "jti": str(uuid.uuid4())  # Unique identifier for token
    })
    
    encoded_jwt = jwt.encode(to_encode, secret_key, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
  
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM])
        
        # Check if token type matches
        if payload.get("type") != token_type:
            return None
            
        # Check if token is expired
        if datetime.utcnow() > datetime.fromtimestamp(payload["exp"]):
            return None
        
        # Check if token is blacklisted (only for refresh tokens)
        if token_type == "refresh" and is_token_blacklisted(token):
            return None
            
        return payload
    except jwt.PyJWTError:
        return None

def extract_user_from_token(token: str) -> Optional[Dict[str, Any]]:
 
    payload = verify_token(token, "access")
    
    if payload:
        return {
            "user_id": payload.get("sub"),
            "username": payload.get("username"),
            "role": payload.get("role")
        }
    
    return None

def generate_token_pair(user_data: Dict[str, Any]) -> Dict[str, str]:
   
    access_token = create_access_token(user_data)
    refresh_token = create_refresh_token({
        "sub": user_data["user_id"],
        "username": user_data["username"]
    })
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

def refresh_access_token(refresh_token: str) -> Optional[str]:
 
    payload = verify_token(refresh_token, "refresh")
    
    if payload:
        user_data = {
            "sub": payload.get("sub"),
            "username": payload.get("username"),
            "role": payload.get("role", "user")
        }
        return create_access_token(user_data)
    
    return None

def blacklist_token_db(db: Session, token: str) -> bool:
    
    try:
        import models
        
        # Decode token to get jti and expiration
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM], options={"verify_signature": False})
        jti = payload.get("jti")
        exp = payload.get("exp")
        
        if not jti or not exp:
            return False
        
        # Check if token is already blacklisted
        existing = db.query(models.BlacklistedToken).filter(models.BlacklistedToken.jti == jti).first()
        if existing:
            return True
        
        # Create new blacklisted token record
        blacklisted_token = models.BlacklistedToken(
            jti=jti,
            expires_at=datetime.fromtimestamp(exp),
            created_at=datetime.utcnow()
        )
        
        db.add(blacklisted_token)
        db.commit()
        return True
        
    except jwt.PyJWTError:
        return False

def is_token_blacklisted_db(db: Session, token: str) -> bool:
    
    try:
        import models
        
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM], options={"verify_signature": False})
        jti = payload.get("jti")
        
        if not jti:
            return False
        
        # Clean up expired tokens first
        cleanup_expired_tokens_db(db)
        
        # Check if token is in blacklist
        blacklisted = db.query(models.BlacklistedToken).filter(
            models.BlacklistedToken.jti == jti
        ).first()
        
        return blacklisted is not None
        
    except jwt.PyJWTError:
        return False

def cleanup_expired_tokens_db(db: Session) -> int:
   
    try:
        import models
        
        # Delete expired tokens
        deleted_count = db.query(models.BlacklistedToken).filter(
            models.BlacklistedToken.expires_at < datetime.utcnow()
        ).delete()
        
        db.commit()
        return deleted_count
        
    except Exception:
        db.rollback()
        return 0

def revoke_all_user_tokens(db: Session, user_id: str) -> int:
    try:
        import models
        # Get all refresh tokens for user and blacklist them
        refresh_tokens = db.query(models.RefreshToken).filter(
            models.RefreshToken.user_id == user_id,
            models.RefreshToken.expires_at > datetime.utcnow()).all()
        revoked_count = 0
        for token in refresh_tokens:
            # Use the stored JTI instead of trying to decode hashed token
            jti = token.token_jti
            if jti:
                # Check if already blacklisted
                existing = db.query(models.BlacklistedToken).filter(models.BlacklistedToken.jti == jti).first()
                if not existing:
                    blacklisted_token = models.BlacklistedToken(
                        jti=jti,
                        expires_at=token.expires_at,
                        created_at=datetime.utcnow())
                    db.add(blacklisted_token)
                    revoked_count += 1
        
        # Delete refresh tokens
        db.query(models.RefreshToken).filter(
            models.RefreshToken.user_id == user_id).delete()
        db.commit()
        return revoked_count
        
    except Exception:
        db.rollback()
        return 0

def set_auth_cookies(response: Response, access_token: str, refresh_token: str) -> Response:
    
    # Set access token cookie (short-lived, HTTP-only)
    response.set_cookie(
        key="access_token",
        value=access_token,
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,  # Convert to seconds
        expires=datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        path="/",
        domain=None,
        secure=True,  # HTTPS only
        httponly=True,  # Prevent JavaScript access
        samesite="lax"
    )
    
    # Set refresh token cookie (long-lived, HTTP-only)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        max_age=REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,  # Convert to seconds
        expires=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        path="/",
        domain=None,
        secure=True,  # HTTPS only
        httponly=True,  # Prevent JavaScript access
        samesite="lax"
    )
    
    return response

def clear_auth_cookies(response: Response) -> Response:
    
    response.delete_cookie(
        key="access_token",
        path="/",
        domain=None,
        secure=True,
        httponly=True,
        samesite="lax"
    )
    
    response.delete_cookie(
        key="refresh_token",
        path="/",
        domain=None,
        secure=True,
        httponly=True,
        samesite="lax"
    )
    
    return response

def get_token_from_cookie(request) -> Optional[str]:
    """
    Extract access token from HTTP-only cookie

    """
    return request.cookies.get("access_token")

def get_refresh_token_from_cookie(request) -> Optional[str]:
    """
    Extract refresh token from HTTP-only cookie
 
    """
    return request.cookies.get("refresh_token")


def log_user_action(user_id: str, action: str, request: Request = None, details: str = None, db: Session = None):
    if not db:
        print("ERROR: No database session provided to log_user_action")
        return
    try:
        ip_address = None
        user_agent = None
        
        if request:
            # Get client IP address
            forwarded_for = request.headers.get("X-Forwarded-For")
            if forwarded_for:
                ip_address = forwarded_for.split(",")[0].strip()
            else:
                ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("User-Agent")
        
        utc_time = datetime.utcnow()
        
        user_log = UserLog(
            user_id=user_id,
            action=action,
            ip_address=ip_address,
            user_agent=user_agent,
            details=details,
            created_at=utc_time)
        
        db.add(user_log)
        db.commit()
        print(f"SUCCESS: Logged action '{action}' for user {user_id} at {utc_time}")
        
    except Exception as e:
        print(f"ERROR: Failed to log user action: {str(e)}")
        db.rollback()
        raise

def get_client_ip(request: Request) -> str:
   
    # Check for forwarded headers first (common in production)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    # Check for real IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fall back to direct connection
    return request.client.host if request.client else "unknown"

def check_ip_block(request: Request, db: Session) -> tuple[bool, Optional[IPAddressBlocked]]:
 
    import crud
    
    ip_address = get_client_ip(request)
    
    # Check if IP is blocked
    is_blocked, ip_block = crud.is_ip_blocked(db, ip_address)
    
    if is_blocked:
        print(f"IP BLOCKED: {ip_address} - Block expires at {ip_block.expires_at}")
    
    return is_blocked, ip_block

def block_ip_address(ip_address: str, block_duration: int, username: str = None, failed_attempts: int = 1, db: Session = None):
    
    if not db:
        raise ValueError("Database session is required")
    
    import crud
    
    ip_block = crud.create_ip_block(
        db=db,
        ip_address=ip_address,
        block_duration=block_duration,
        username=username,
        failed_attempts=failed_attempts
    )
    
    print(f"IP BLOCKED: {ip_address} for {block_duration}ms by user {username}")
    return ip_block

def get_delay_for_failed_attempts(attempts: int) -> int:
    
    if attempts <= 5:
        return 0  # No delay for first 5 attempts
    elif attempts <= 10:
        return 10000  # 10 seconds after 5 failed attempts
    elif attempts <= 15:
        return 30000  # 30 seconds after 10 failed attempts
    elif attempts <= 20:
        return 120000  # 2 minutes after 15 failed attempts
    elif attempts <= 25:
        return 300000  # 5 minutes after 20 failed attempts
    elif attempts <= 30:
        return 900000  # 15 minutes after 25 failed attempts
    else:
        return float('inf')  # Permanent block after 30+ attempts

def format_duration_ms(ms: int) -> str:
   
    if ms == float('inf'):
        return 'Permanent'
    
    seconds = ms // 1000
    
    if seconds < 60:
        return f"{seconds} seconds" if seconds != 1 else "1 second"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes} minutes" if minutes != 1 else "1 minute"
    else:
        hours = seconds // 3600
        return f"{hours} hours" if hours != 1 else "1 hour"

def create_persistent_refresh_token(user_id: str) -> tuple[str, str]:
    """
    Create a persistent refresh token that lasts 30 days
    Returns: (token, token_hash)
    """
    token = create_refresh_token({"sub": user_id})
    token_hash = hash_token(token)  # Now uses Argon2ID
    return token, token_hash

def get_or_create_persistent_refresh_token(db: Session, user_id: str) -> tuple[str, str]:
    """
    Get existing valid persistent refresh token or create a new one
    Returns: (token, token_hash)
    """
    try:
        from models import PersistentRefreshToken
        
        # Check if user has an active, non-expired persistent token
        existing_token = db.query(PersistentRefreshToken).filter(
            PersistentRefreshToken.user_id == user_id,
            PersistentRefreshToken.is_active == True,
            PersistentRefreshToken.expires_at > datetime.utcnow()
        ).first()
        
        if existing_token:
            print(f"DEBUG: Reusing existing persistent refresh token for user {user_id}, ID: {existing_token.id}")
            # Update last_used timestamp
            existing_token.last_used = datetime.utcnow()
            db.commit()
            
            # We need to return the actual token, but we only have the hash
            # Since we can't reconstruct the original token from the hash,
            # we'll need to create a new token and update the hash
            print(f"DEBUG: Creating new token to replace expired one (hash-only storage limitation)")
            new_token, new_token_hash = create_persistent_refresh_token(user_id)
            existing_token.token_hash = new_token_hash
            existing_token.last_used = datetime.utcnow()
            existing_token.expires_at = datetime.utcnow() + timedelta(days=30)
            db.commit()
            print(f"DEBUG: Updated persistent refresh token with new hash, ID: {existing_token.id}")
            return new_token, new_token_hash
        else:
            print(f"DEBUG: No valid existing token found, creating new persistent refresh token for user {user_id}")
            new_token, new_token_hash = create_persistent_refresh_token(user_id)
            store_persistent_refresh_token(db, user_id, new_token_hash)
            return new_token, new_token_hash
            
    except Exception as e:
        print(f"ERROR in get_or_create_persistent_refresh_token: {e}")
        db.rollback()
        # Fallback: create new token
        new_token, new_token_hash = create_persistent_refresh_token(user_id)
        return new_token, new_token_hash

def store_persistent_refresh_token(db: Session, user_id: str, token_hash: str, deactivate_existing: bool = False) -> bool:
    """
    Store a persistent refresh token in the database
    If deactivate_existing is True, deactivate all existing tokens for this user
    """
    try:
        from models import PersistentRefreshToken
        
        print(f"DEBUG: Storing persistent refresh token for user {user_id}")
        print(f"DEBUG: Token hash (first 50 chars): {token_hash[:50]}...")
        
        # Deactivate existing tokens for this user/device only if requested
        if deactivate_existing:
            existing_tokens = db.query(PersistentRefreshToken).filter(
                PersistentRefreshToken.user_id == user_id,
                PersistentRefreshToken.is_active == True
            ).all()
            
            for token in existing_tokens:
                token.is_active = False
            print(f"DEBUG: Deactivated {len(existing_tokens)} existing tokens for user {user_id}")
        
        # Create new persistent token
        persistent_token = PersistentRefreshToken(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(days=30)
        )
        
        db.add(persistent_token)
        db.commit()
        print(f"DEBUG: Persistent refresh token stored successfully with ID: {persistent_token.id}")
        return True
        
    except Exception as e:
        print(f"ERROR storing persistent refresh token: {e}")
        db.rollback()
        return False

def verify_persistent_refresh_token(db: Session, token: str) -> tuple[bool, str]:
    """
    Verify a persistent refresh token and return (valid, user_id)
    """
    try:
        from models import PersistentRefreshToken
        
        # Get all active persistent tokens
        persistent_tokens = db.query(PersistentRefreshToken).filter(
            PersistentRefreshToken.is_active == True,
            PersistentRefreshToken.expires_at > datetime.utcnow()
        ).all()
        
        # Find the token with matching hash
        for persistent_token in persistent_tokens:
            if verify_hashed_token(token, persistent_token.token_hash):
                # Update last used timestamp
                persistent_token.last_used = datetime.utcnow()
                db.commit()
                return True, str(persistent_token.user_id)
        
        return False, ""
        
    except Exception as e:
        print(f"Error verifying persistent refresh token: {e}")
        return False, ""

def revoke_persistent_refresh_tokens(db: Session, user_id: str) -> int:
    """
    Revoke all persistent refresh tokens for a user
    Returns: number of tokens revoked
    """
    try:
        from models import PersistentRefreshToken
        
        # Get count before revoking
        count = db.query(PersistentRefreshToken).filter(
            PersistentRefreshToken.user_id == user_id,
            PersistentRefreshToken.is_active == True
        ).count()
        
        if count > 0:
            db.query(PersistentRefreshToken).filter(
                PersistentRefreshToken.user_id == user_id,
                PersistentRefreshToken.is_active == True
            ).update({"is_active": False})
            
            db.commit()
            print(f"DEBUG: Revoked {count} persistent refresh tokens for user {user_id}")
        
        return count
        
    except Exception as e:
        print(f"Error revoking persistent refresh tokens: {e}")
        db.rollback()
        return 0

def cleanup_expired_persistent_tokens(db: Session) -> int:
    """
    Clean up expired persistent tokens
    """
    try:
        from models import PersistentRefreshToken
        
        deleted_count = db.query(PersistentRefreshToken).filter(
            PersistentRefreshToken.expires_at < datetime.utcnow()
        ).delete()
        
        db.commit()
        return deleted_count
        
    except Exception as e:
        print(f"Error cleaning up expired persistent tokens: {e}")
        db.rollback()
        return 0

