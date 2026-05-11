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
from datetime import datetime, timedelta, timezone
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
from models import User, PersistentRefreshToken, RefreshToken
from database import get_db
from zoneinfo import ZoneInfo

# Configure timezone for Moldova
MOLDOVA_TZ = ZoneInfo("Europe/Chisinau")

# încarcă variabilele din fișier
load_dotenv(".env.local")

# Load secrets from environment variables
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
if not JWT_SECRET_KEY:
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
    
    print(f"Token validated for user {user_data['user_id']} at {datetime.now(timezone.utc)}")
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
    master_key = secrets.token_bytes(32)  # 32 bytes = 256 bits
    return base64.urlsafe_b64encode(master_key).decode('utf-8')

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
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": "access"
    })
    
    print(f"Creating access token for user {data.get('sub', 'unknown')} that expires at {expire}")
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, algorithm=ALGORITHM)
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

def create_refresh_token(
    data: Dict[str, Any],
    db: Session,
    user_id: str,
    expires_delta: Optional[timedelta] = None,
    token_type: str = "refresh"
) -> str:

    to_encode = data.copy()

    if expires_delta:
        expire = datetime.now(timezone.utc)+ expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    jti = str(uuid.uuid4())

    to_encode.update({
        "exp": expire,
        "iat": datetime.now(timezone.utc),
        "type": token_type,
        "jti": jti
    })

    encoded_jwt = jwt.encode(
        to_encode,
        JWT_SECRET_KEY,
        algorithm=ALGORITHM
    )

    # HASH refresh token
    token_hash = ph.hash(encoded_jwt)

    refresh_token_record = RefreshToken(
        token_hash=token_hash,
        token_jti=jti,
        user_id=user_id,
        expires_at=expire
    )

    db.add(refresh_token_record)
    db.commit()

    return encoded_jwt

def verify_token(token: str, token_type: str = "access") -> Optional[Dict[str, Any]]:
  
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
        
        # Check if token type matches
        if payload.get("type") != token_type:
            return None
            
        # Check if token is expired
        if datetime.now(timezone.utc) > datetime.fromtimestamp(payload["exp"], tz=timezone.utc):
            return None
        
        # Check if token is blacklisted (only for refresh tokens)
        if token_type == "refresh" and is_token_blacklisted_db(token):
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
    refresh_token = create_refresh_token(
    {
        "sub": user_data["user_id"],
        "username": user_data["username"]
    },
    db=db,
    user_id=user_data["user_id"]
)
    
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
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])
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
            created_at=datetime.now(timezone.utc)
        )
        
        db.add(blacklisted_token)
        db.commit()
        return True
        
    except jwt.PyJWTError:
        return False

def is_token_blacklisted_db(db: Session, token: str) -> bool:
    
    try:
        import models
        
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM], options={"verify_signature": False})
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
            models.BlacklistedToken.expires_at < datetime.now(timezone.utc)
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
            models.RefreshToken.expires_at > datetime.now(timezone.utc)).all()
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
                        created_at=datetime.now(timezone.utc))
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
        expires=datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
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
        expires=datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
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
        
        utc_time = datetime.now(timezone.utc)
        
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

def utc_now():
    return datetime.now(timezone.utc)


def create_persistent_refresh_token(db: Session, user_id: str) -> str | None:
    """Create a persistent refresh token for biometric authentication (30 days)"""
    try:
        # 1. FORȚEAZĂ CONVERTIREA LA STRING
        # Chiar dacă primești string, asigură-te că rămâne string până la capăt
        user_id_str = str(user_id)
        
        print(f"🔍 Creating token for user_id_str: {user_id_str} (Type: {type(user_id_str)})")

        # 2. Convert string to UUID for database operations
        from uuid import UUID
        user_uuid = UUID(user_id_str)
        
        # Invalidate existing tokens using UUID
        db.query(PersistentRefreshToken).filter(
            PersistentRefreshToken.user_id == user_uuid,
            PersistentRefreshToken.is_active.is_(True)
        ).update({"is_active": False})
        
        # 3. Create new token
        # JWT-ul preferă string-uri pentru 'sub'
        persistent_token = create_refresh_token({"sub": user_id_str}, db=db, user_id=user_id_str, token_type="persistent")
        persistent_token_hash = hash_token(persistent_token)
        
        # 4. Save to database
        new_persistent_token = PersistentRefreshToken(
            user_id=user_uuid,  # <--- Folosim UUID object for proper database storage
            token_hash=persistent_token_hash,
            is_active=True,
            expires_at=datetime.now(timezone.utc)+ timedelta(days=30)
        )
        
        db.add(new_persistent_token)
        db.commit()
        db.refresh(new_persistent_token)
        
        print(f"✅ Persistent token created successfully for user {user_id_str}")
        return persistent_token 
        
    except Exception as e:
        # Printăm eroarea detaliată pentru debug
        import traceback
        print(f"❌ Error creating persistent token: {e}")
        traceback.print_exc() # Aceasta va arăta exact linia care crapă
        db.rollback()
        return None
def get_or_create_persistent_token(db: Session, user_id: str) -> str | None:
   
    user_id_str = str(user_id)
    from uuid import UUID
    user_uuid = UUID(user_id)
    
    # 1. Verificăm dacă există un token activ și neexpirat
    existing = db.query(PersistentRefreshToken).filter(
        PersistentRefreshToken.user_id == user_uuid,
        PersistentRefreshToken.is_active.is_(True),
        PersistentRefreshToken.expires_at > datetime.now(timezone.utc)
    ).first()

    if existing:
        print(f"♻️ Valid persistent token already exists for user {user_id_str}. Client should use stored one.")
        return None  # Signal că nu e nevoie de token nou

    # 2. Dacă nu există, creăm unul nou
    print(f"🆕 No valid persistent token found. Creating new one for {user_id_str}")
    return create_persistent_refresh_token(db, user_id_str)


def verify_persistent_refresh_token(db: Session, token: str) -> tuple[bool, str]:
    """Verify a persistent refresh token.
    
    Returns:
        (is_valid, user_id) tuple
    """
    try:
        # Step 1: Decode JWT (validates signature + expiration)
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])

        # Step 2: Check token type
        if payload.get("type") != "persistent":
            logger.warning("Token rejected: wrong type")
            return False, ""

        user_id = payload.get("sub")
        if not user_id:
            logger.warning("Token rejected: missing sub")
            return False, ""

        # Step 3: Check database record exists
        # Convert string user_id to UUID for proper comparison
        from uuid import UUID
        user_uuid = UUID(user_id)
        persistent_token = db.query(PersistentRefreshToken).filter(
            PersistentRefreshToken.user_id == user_uuid,
            PersistentRefreshToken.is_active.is_(True),
            PersistentRefreshToken.expires_at > datetime.now(timezone.utc)
        ).first()

        if not persistent_token:
            logger.warning("Token rejected: no active DB record for user %s", user_id)
            return False, ""

        # Step 4: Verify hash matches (catches cloned tokens)
        if not verify_hashed_token(token, persistent_token.token_hash):
    # ⚠️ Someone has a valid JWT but wrong hash = suspicious
    # Invalidate ALL tokens for this user
            db.query(PersistentRefreshToken).filter( PersistentRefreshToken.user_id == user_id).update({"is_active": False})
            db.commit()
    
            logger.critical("SECURITY: Possible token theft for user %s", user_id)
            return False, ""

        # Step 5: Update last used
        persistent_token.last_used = datetime.now(timezone.utc)
        db.commit()

        return True, user_id

    except jwt.ExpiredSignatureError:
        logger.info("Token rejected: expired")
        return False, ""
    except jwt.InvalidTokenError as e:
        logger.warning("Token rejected: invalid - %s", e)
        return False, ""
    except Exception as e:
        logger.error("Token verification error: %s", e, exc_info=True)
        db.rollback()
        return False, ""

def revoke_persistent_refresh_tokens(
    db: Session,
    user_id: str
) -> int:
    """
    Revoke all persistent tokens for a user.
    """

    try:

        user_uuid = uuid.UUID(user_id)

        revoked_count = db.query(PersistentRefreshToken).filter(
            PersistentRefreshToken.user_id == user_uuid,
            PersistentRefreshToken.is_active.is_(True)
        ).update({
            "is_active": False
        })

        db.commit()

        return revoked_count

    except Exception as e:

        db.rollback()

        print(f"ERROR revoking persistent tokens: {e}")

        return 0


def cleanup_expired_persistent_tokens(
    db: Session
) -> int:
    """
    Deactivate expired tokens.
    """

    try:

        updated_count = db.query(PersistentRefreshToken).filter(
            PersistentRefreshToken.expires_at < utc_now(),
            PersistentRefreshToken.is_active.is_(True)
        ).update({
            "is_active": False
        })

        db.commit()

        return updated_count

    except Exception as e:

        db.rollback()

        print(f"ERROR cleaning expired tokens: {e}")

        return 0

# ==================== END-TO-END ENCRYPTION (E2EE) FUNCTIONS ====================

def derive_encryption_key_from_password(password: str, salt: bytes = None) -> Tuple[bytes, bytes]:
    """
    Derive an encryption key from user's password using PBKDF2.
    This key is used to encrypt/decrypt the user's master key.
    
    Args:
        password: User's password
        salt: Salt for key derivation (generated if not provided)
    
    Returns:
        Tuple of (derived_key, salt)
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    
    # Use PBKDF2 with HMAC-SHA256 to derive key from password
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000,  # iterations
        32       # 32 bytes = 256 bits for AES-256
    )
    
    return derived_key, salt

def encrypt_master_key_with_password(master_key_b64: str, password: str) -> Tuple[str, str]:
    """
    Encrypt the user's master key with their password.
    The encrypted master key is stored in the database.
    
    Args:
        master_key_b64: Base64-encoded master key
        password: User's password
    
    Returns:
        Tuple of (encrypted_master_key_b64, salt_b64)
    """
    # Derive encryption key from password
    encryption_key, salt = derive_encryption_key_from_password(password)
    
    # Encrypt the master key using AES-GCM
    nonce = os.urandom(12)
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(nonce),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    master_key_bytes = base64.urlsafe_b64decode(master_key_b64.encode())
    encrypted = encryptor.update(master_key_bytes) + encryptor.finalize()
    tag = encryptor.tag
    
    # Combine nonce + tag + encrypted data
    combined = nonce + tag + encrypted
    encrypted_b64 = base64.b64encode(combined).decode('utf-8')
    salt_b64 = base64.b64encode(salt).decode('utf-8')
    
    return encrypted_b64, salt_b64

def decrypt_master_key_with_password(encrypted_master_key_b64: str, salt_b64: str, password: str) -> str:
    """
    Decrypt the user's master key using their password.
    
    Args:
        encrypted_master_key_b64: Base64-encoded encrypted master key
        salt_b64: Base64-encoded salt
        password: User's password
    
    Returns:
        Base64-encoded master key
    """
    # Derive encryption key from password
    salt = base64.b64decode(salt_b64.encode())
    encryption_key, _ = derive_encryption_key_from_password(password, salt)
    
    # Decrypt the master key
    combined = base64.b64decode(encrypted_master_key_b64.encode('utf-8'))
    nonce = combined[:12]
    tag = combined[12:28]
    encrypted = combined[28:]
    
    cipher = Cipher(
        algorithms.AES(encryption_key),
        modes.GCM(nonce, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    decrypted = decryptor.update(encrypted) + decryptor.finalize()
    master_key_b64 = base64.urlsafe_b64encode(decrypted).decode('utf-8')
    
    return master_key_b64

def get_user_encryption_key(master_key_b64: str) -> bytes:
    """
    Derive the actual AES encryption key from the user's master key.
    This is the key used to encrypt/decrypt passwords.
    
    Args:
        master_key_b64: Base64-encoded master key
    
    Returns:
        32-byte encryption key for AES-256
    """
    # Use PBKDF2 to derive a consistent key from the master key
    salt = b'user_encryption_key_salt'  # Fixed salt for consistency
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        base64.urlsafe_b64decode(master_key_b64.encode()),
        salt,
        100000,
        32
    )
    
    return derived_key

def encrypt_password_e2e(password: str, master_key_b64: str) -> str:
    """
    Encrypt a password using the user's master key (E2EE mode).
    This uses the same AES-GCM logic as encrypt_password but with user-specific key.
    
    Args:
        password: Password to encrypt
        master_key_b64: Base64-encoded master key
    
    Returns:
        Base64-encoded encrypted password
    """
    # Derive encryption key from master key
    encryption_key = get_user_encryption_key(master_key_b64)
    
    # Use the existing AES-GCM encryption logic
    return encrypt_password(password, encryption_key)

def decrypt_password_e2e(encrypted_b64: str, master_key_b64: str) -> str:
    """
    Decrypt a password using the user's master key (E2EE mode).
    This uses the same AES-GCM logic as decrypt_password but with user-specific key.
    
    Args:
        encrypted_b64: Base64-encoded encrypted password
        master_key_b64: Base64-encoded master key
    
    Returns:
        Decrypted password
    """
    # Derive encryption key from master key
    encryption_key = get_user_encryption_key(master_key_b64)
    
    # Use the existing AES-GCM decryption logic
    return decrypt_password(encrypted_b64, encryption_key)

