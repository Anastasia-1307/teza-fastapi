# FastAPI Authentication Server
import json
import jwt
import os
from pydantic import BaseModel
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from schemas import (
    UserResponse, Register, UserLogResponse, PasswordCreate, PasswordResponse, 
    PasswordDecryptResponse, CategoryCreate, CategoryResponse,
    IPAddressBlockedResponse, IPAddressBlockCreate, IPAddressBlockUpdate,
    E2EESetupRequest, E2EEMasterKeyResponse, PasswordCreateE2EE
)
from crud import (
    create_password, get_user_passwords, get_password_by_id, update_password, delete_password,
    create_ip_block, get_all_ip_blocks, update_ip_block, delete_ip_block, 
    cleanup_expired_ip_blocks, get_ip_block_stats, is_ip_blocked
)
from sqlalchemy.orm import Session
from database import get_db
from models import User, RefreshToken, UserLog, Category, IPAddressBlocked, PersistentRefreshToken
from security import (
    check_ip_block, block_ip_address, get_delay_for_failed_attempts, 
    format_duration_ms, get_client_ip, 
    create_persistent_refresh_token, create_refresh_token, hash_password, 
    verify_password, create_access_token, get_current_user, require_role, 
    log_user_action, revoke_all_user_tokens, revoke_persistent_refresh_tokens, encrypt_password, decrypt_password, 
    verify_persistent_refresh_token, hash_token, verify_hashed_token,
    generate_master_key, encrypt_master_key_with_password, decrypt_master_key_with_password, get_or_create_persistent_token
)
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from fastapi.responses import JSONResponse  

# Configure timezone for Moldova
MOLDOVA_TZ = ZoneInfo("Europe/Chisinau")

# Custom login form to avoid OAuth2PasswordRequestForm issues
class LoginForm(BaseModel):
    username: str
    password: str
    grant_type: str = "password"

# Biometric authentication form
class BiometricAuthForm(BaseModel):
    username: str
    biometric_method: str = "aes_key"  # Pentru viitor extindere
    device_info: dict = {}  # Info despre dispozitiv pentru logging

app = FastAPI(title="FastAPI Auth Server v4 - FIXED")

@app.get("/")
def root():
    return {"message": "FastAPI Auth Server is running", "docs": "/docs", "redoc": "/redoc"}

origins = ["http://localhost:8081", "http://127.0.0.1:8081",  "*"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Add IP blocking middleware
@app.middleware("http")
async def ip_block_middleware(request: Request, call_next):
    """
    Middleware to check IP blocks on all requests
    """
    # Skip IP block checking for certain endpoints (like docs, health checks)
    skip_paths = ["/docs", "/redoc", "/openapi.json", "/", "/test", "/user-logs"]
    
    if request.url.path in skip_paths:
        response = await call_next(request)
        return response
    
    # Get database session
    from database import SessionLocal
    db = SessionLocal()
    
    try:
        # Check if IP is blocked
        is_blocked, ip_block = check_ip_block(request, db)
        
        if is_blocked:
            ip_address = get_client_ip(request)
            from fastapi.responses import JSONResponse
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"Adresa IP {ip_address} este blocată. Încearcă din nou după {ip_block.expires_at.replace(tzinfo=ZoneInfo('UTC')).astimezone(MOLDOVA_TZ).strftime('%d-%m-%Y %H:%M:%S') if ip_block.expires_at else ip_block.expires_at}",
                    "error_code": "IP_BLOCKED",
                    "block_expires_at": ip_block.expires_at.replace(tzinfo=ZoneInfo('UTC')).astimezone(MOLDOVA_TZ).isoformat() if ip_block.expires_at else None
                }
            )
        
        # Continue with the request
        response = await call_next(request)
        return response
        
    finally:
        db.close()

@app.post("/register", response_model=UserResponse)
def register(user: Register, request: Request, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="Utilizator existent")

    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email existent")

    # Generate master key for E2EE
    master_key_b64 = generate_master_key()
    
    # Encrypt master key with user's password
    encrypted_master_key, master_key_salt = encrypt_master_key_with_password(master_key_b64, user.password)

    new_user = User( username = user.username, email = user.email, role = user.role, password_hash = hash_password(user.password),
        encrypted_master_key = encrypted_master_key, master_key_salt = master_key_salt)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log registration action
    log_user_action(user_id=str(new_user.id), action="register", request=request,
        details=f"User {new_user.username} registered successfully", db=db)

    # Convert UUID to string for response
    return {
        "id": str(new_user.id),
        "username": new_user.username,
        "role": new_user.role,
        "created_at": new_user.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if new_user.created_at else new_user.created_at
    }

@app.post("/auth")
def auth(request: Request, form_data: LoginForm, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.password_hash):
        # Get IP address for tracking failed attempts
        ip_address = get_client_ip(request)

        # Check existing failed attempts for this IP
        recent_failed_logs = db.query(UserLog).filter(UserLog.ip_address == ip_address, UserLog.action == "login_failed",
            UserLog.created_at >= datetime.utcnow() - timedelta(hours=1)).count()

        failed_attempts = recent_failed_logs + 1
        delay = get_delay_for_failed_attempts(failed_attempts)

        # Log failed login attempt
        if user:
            log_user_action(user_id=str(user.id), action="login_failed", request=request,
                details=f"Failed login attempt for user {user.username}: wrong password (attempt {failed_attempts})", db=db)
        else:
            log_user_action(user_id=None, action="login_failed", request=request,
                details=f"Failed login attempt: username {form_data.username} not found (attempt {failed_attempts})", db=db)

        # Block IP if threshold reached
        if delay > 0:
            block_ip_address(ip_address=ip_address, block_duration=delay, username=form_data.username, failed_attempts=failed_attempts, db=db)

            if delay == float('inf'):
                raise HTTPException( status_code=429, detail=f"Prea multe încercări eșuate. Adresa IP {ip_address} blocată permanent.") 
            else:
                raise HTTPException( status_code=429,detail=f"Prea multe încercări eșuate. Adresa IP {ip_address} blocată pentru {format_duration_ms(delay).replace('seconds', 'secunde').replace('minutes', 'minute').replace('hours', 'ore')}.")

        raise HTTPException(status_code=401, detail="Credențiale invalide")

    token_access = create_access_token({"sub": str(user.id), "role": user.role, "username": user.username })
    # Create refresh token first
    token_refresh = create_refresh_token(
    data={"sub": str(user.id)},
    db=db,
    user_id=str(user.id)
)

    log_user_action(user_id=str(user.id), action="login", request=request, details=f"User {user.username} logged in successfully with password",
    db=db)
    
    response_data = {
        "access_token": token_access,
        "refresh_token": token_refresh,
        "token_type": "bearer",
        "expires_in": 3600
    }
    
    # Add redirect information based on user role
    if user.role == "admin":
        response_data["redirect_to"] = "/admin"
        response_data["user_role"] = "admin"
    else:
        response_data["redirect_to"] = "/user"
        response_data["user_role"] = "user"
    
    return response_data

@app.post("/auth/biometric")
def biometric_auth(request: Request, form_data: BiometricAuthForm, db: Session = Depends(get_db)):
    """
    Endpoint pentru autentificare biometrică cu chei AES.
    Clientul decriptează parola local cu cheia AES biometrică și o trimite aici.
    """
    # Verifică dacă utilizatorul există
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        # Log failed biometric attempt
        log_user_action(
            user_id=None,
            action="bio_login_failed",
            request=request,
            details=f"Failed biometric login attempt: username {form_data.username} not found",
            db=db
        )
        raise HTTPException(status_code=401, detail="Utilizator negăsit")
    
    # NOTĂ: Autentificarea biometrică reală se face pe client
    # Aici doar verificăm credențialele decriptate de client
    # Securitatea este asigurată de faptul că parola este decriptată doar după auth biometric
    
    # Log biometric authentication attempt
    log_user_action(
        user_id=str(user.id),
        action="login_biometric",
        request=request,
        details=f"Biometric login attempt for user {user.username} using {form_data.biometric_method}",
        db=db
    )
    
    # Returnăm un mesaj de succes - clientul va face login-ul normal cu parola decriptată
    response_data = {
        "message": "Biometric authentication ready",
        "user_id": str(user.id),
        "username": user.username,
        "biometric_method": form_data.biometric_method,
        "next_step": "proceed_with_decrypted_password"
    }
    
    # Add redirect information based on user role for future reference
    if user.role == "admin":
        response_data["redirect_to"] = "/admin"
        response_data["user_role"] = "admin"
    else:
        response_data["redirect_to"] = "/user"
        response_data["user_role"] = "user"
    
    return response_data

@app.post("/auth/biometric/verify")
def biometric_verify(request: Request, form_data: LoginForm, db: Session = Depends(get_db)):
    """
    Endpoint pentru verificarea finală a credențialelor decriptate biometric.
    Acesta este apelat după ce clientul decriptează parola cu cheia AES biometrică."""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        if user:
            log_user_action( user_id=str(user.id), action="bio_login_failed", request=request,
            details=f"Failed biometric verification for user {user.username}: invalid decrypted password", db=db)
        else:
            log_user_action(user_id=None, action="bio_login_failed", request=request,
                details=f"Failed biometric verification: username {form_data.username} not found", db=db)
        raise HTTPException(status_code=401, detail="Verificare biometrică eșuată")
    
    token_access = create_access_token({"sub": str(user.id), "role": user.role, "username": user.username })
    token_refresh = create_refresh_token(
    db=db,
    user_id=str(user.id),
    payload={"sub": str(user.id)})
    
    token_payload = jwt.decode(token_refresh, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
    token_jti = token_payload.get("jti")
    
    # Store hashed token for security
    token_hash = hash_token(token_refresh)
    new_refresh = RefreshToken(
        token_hash = token_hash, 
        token_jti = token_jti,
        user_id = user.id, 
        expires_at = datetime.utcnow() + timedelta(days=7)
    )
    db.add(new_refresh)
    db.commit()
    
    # Generate persistent refresh token for biometric authentication (30 days)
    persistent_token, persistent_token_hash = create_persistent_refresh_token(
        db, str(user.id)
    )
    print(f"DEBUG: Persistent token for biometric user {user.id}: {persistent_token[:20]}...")
    
    # Log successful biometric login
    log_user_action(
        user_id=str(user.id),
        action="bio_login",
        request=request,
        details=f"User {user.username} successfully authenticated with biometric AES keys",
        db=db
    )
    
    response_data = {
        "access_token": token_access,
        "refresh_token": token_refresh,
        "persistent_refresh_token": persistent_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "login_method": "biometric_aes"
    }
    
    # Add redirect information based on user role
    if user.role == "admin":
        response_data["redirect_to"] = "/admin"
        response_data["user_role"] = "admin"
    else:
        response_data["redirect_to"] = "/user"
        response_data["user_role"] = "user"
    
    return response_data

@app.post("/auth/biometric/direct")
def direct_biometric_auth(request: Request, form_data: LoginForm, db: Session = Depends(get_db)):
    """
    Endpoint pentru autentificare directă biometrică.
    Clientul trimite username-ul și parola decriptată biometric.
    Acest endpoint permite autentificarea fără a fi nevoie de login cu parola înainte.
    """
    # DEBUG: Log incoming request details
    print(f"DEBUG /auth/biometric/direct request:")
    print(f"  - Headers: {dict(request.headers)}")
    print(f"  - Username: {form_data.username}")
    print(f"  - Password length: {len(form_data.password)}")
    print(f"  - Password content: '{form_data.password}'")
    print(f"  - Grant type: {form_data.grant_type}")
    print(f"  - Client IP: {get_client_ip(request)}")
    print(f"  - Request body received successfully")
    
    # TEMPORARILY DISABLED IP BLOCKING FOR DEBUGGING
    # Verifică dacă IP este blocat
    # is_blocked, ip_block = check_ip_block(request, db)
    # if is_blocked:
    #     ip_address = get_client_ip(request)
    #     raise HTTPException(
    #         status_code=429,
    #         detail=f"Adresa IP {ip_address} este blocată. Încearcă din nou după {ip_block.expires_at.replace(tzinfo=ZoneInfo('UTC')).astimezone(MOLDOVA_TZ) if ip_block.expires_at else ip_block.expires_at}"
    #     )

    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        log_user_action(
            user_id=None,
            action="bio_login_failed",
            request=request,
            details=f"Failed direct biometric login: username {form_data.username} not found",
            db=db
        )
        raise HTTPException(status_code=401, detail="Utilizator negăsit")

    # Verifică parola decriptată biometric
    if not verify_password(form_data.password, user.password_hash):
        # Get IP address for tracking failed attempts
        ip_address = get_client_ip(request)

        # Check existing failed attempts for this IP
        recent_failed_logs = db.query(UserLog).filter(
            UserLog.ip_address == ip_address,
            UserLog.action == "bio_login_failed",
            UserLog.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).count()

        failed_attempts = recent_failed_logs + 1
        delay = get_delay_for_failed_attempts(failed_attempts)

        # Log failed biometric attempt
        log_user_action(
            user_id=str(user.id),
            action="bio_login_failed",
            request=request,
            details=f"Failed direct biometric login for user {user.username}: invalid decrypted password (attempt {failed_attempts})",
            db=db
        )

        # Block IP if threshold reached
        if delay > 0:
            block_ip_address(
                ip_address=ip_address,
                block_duration=delay,
                username=form_data.username,
                failed_attempts=failed_attempts,
                db=db
            )

            if delay == float('inf'):
                raise HTTPException(
                    status_code=429,
                    detail=f"Prea multe încercări eșuate. Adresa IP {ip_address} blocată permanent."
                )
            else:
                raise HTTPException(
                    status_code=429,
                    detail=f"Prea multe încercări eșuate. Adresa IP {ip_address} blocată pentru {format_duration_ms(delay).replace('seconds', 'secunde').replace('minutes', 'minute').replace('hours', 'ore')}."
                )

        raise HTTPException(status_code=401, detail="Autentificare biometrică eșuată")

    # Generează token-uri
    token_access = create_access_token({"sub": str(user.id), "role": user.role, "username": user.username})
    
    token_refresh = create_refresh_token(
    data={"sub": str(user.id)},
    db=db,
    user_id=str(user.id)
)
    # Obține sau creează persistent refresh token pentru biometric (30 zile)
    # Reutilizează token-ul existent dacă este încă valid
    new_persistent_token = get_or_create_persistent_token(db, str(user.id))
    
    db.commit() # Commit pentru eventualele schimbări de status sau creare

    # Log successful biometric login
    log_user_action(
        user_id=str(user.id),
        action="bio_login",
        request=request,
        details=f"User {user.username} successfully authenticated with direct biometric",
        db=db
    )

    response_data = {
        "access_token": token_access,
        "refresh_token": token_refresh,
        "token_type": "bearer",
        "expires_in": 3600,
        "login_method": "biometric_direct"
    }

    # Add redirect information based on user role
    if user.role == "admin":
        response_data["redirect_to"] = "/admin"
        response_data["user_role"] = "admin"
    else:
        response_data["redirect_to"] = "/user"
        response_data["user_role"] = "user"

    # Trimitem token-ul DOAR dacă am creat unul nou
    if new_persistent_token:
        response_data["persistent_refresh_token"] = new_persistent_token
        print(f"Sending NEW persistent token to client")
    else:
        print(f"Client already has a valid persistent token. Not sending a new one.")

    return response_data

@app.post("/auth/biometric/setup")
def setup_biometric_auth(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    try:
        print(f"🔍 Setup called for user: {current_user.id}")

        if current_user.role == "admin":
            raise HTTPException(
                status_code=403,
                detail="Admin users cannot use biometric authentication"
            )
        
        print(f"🔍 Creating persistent token...")
        
        # Convertește UUID la String
        user_id_str = str(current_user.id)
        
        # Creează token-ul persistent în DB
        persistent_token = create_persistent_refresh_token(db, user_id_str)

        if not persistent_token:
            raise HTTPException(status_code=500, detail="Nu s-a putut crea token-ul persistent")

        print(f"✅ Token saved in DB for user {user_id_str}")
            
        # Logăm acțiunea
        log_user_action(
            user_id=user_id_str,
            action="biometric_setup",
            request=request,
            details=f"User {current_user.username} enabled biometric auth. Relogin required.",
            db=db
        )

        # Răspuns JSON corect
        response = JSONResponse(content={
            "status": "success",
            "message": "Biometrie activată cu succes. Te rugăm să te deloghezi și să te loghezi din nou pentru a o utiliza.",
            "requires_relogin": True
        })
        
        
        response.delete_cookie(key="access_token", path="/")
        response.delete_cookie(key="refresh_token", path="/")
        
        return response

    except Exception as e:
        # ⚠️ ACEASTA ESTE CHEIA: Returnează JSON chiar și la eroare
        print(f"❌ CRITICAL ERROR in setup_biometric_auth: {str(e)}")
        import traceback
        traceback.print_exc() # Printează stack trace în consolă
        
        return JSONResponse(
            status_code=500,
            content={"detail": f"Eroare internă server: {str(e)}"}
        )

# user, admin
@app.post("/user")
def authorize_user(current_user: User = Depends(require_role("user"))):
    return {
        "message": f"Hello {current_user.username}, you are authorized as user!"
    }

@app.post("/admin")
def authorize_admin(current_user: User = Depends(require_role("admin"))):
    return {
        "message": f"Hello {current_user.username}, you are authorized as admin!"
    }

@app.get("/e2ee/master-key")
def get_encrypted_master_key(current_user: User = Depends(get_current_user)):
    """
    Retrieve the encrypted master key for E2EE.
    The client must decrypt this using the user's password locally.
    """
    if not current_user.encrypted_master_key or not current_user.master_key_salt:
        raise HTTPException(status_code=404, detail="E2EE not enabled for this user")
    
    return {
        "encrypted_master_key": current_user.encrypted_master_key,
        "master_key_salt": current_user.master_key_salt,
        "message": "Decrypt this with your password to get your master key"
    }

@app.post("/e2ee/setup-existing-user", response_model=E2EEMasterKeyResponse)
def setup_e2ee_for_existing_user(
    setup_data: E2EESetupRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Enable E2EE for an existing user (created before E2EE was implemented).
    This generates and stores a master key encrypted with the user's password.
    """
    # Verify the password
    if not verify_password(setup_data.password, current_user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid password")
    
    # Check if E2EE is already enabled
    if current_user.encrypted_master_key:
        raise HTTPException(status_code=400, detail="E2EE already enabled for this user")
    
    # Generate master key
    master_key_b64 = generate_master_key()
    
    # Encrypt master key with user's password
    encrypted_master_key, master_key_salt = encrypt_master_key_with_password(master_key_b64, setup_data.password)
    
    # Store in database
    current_user.encrypted_master_key = encrypted_master_key
    current_user.master_key_salt = master_key_salt
    db.commit()
    db.refresh(current_user)
    
    return {
        "encrypted_master_key": encrypted_master_key,
        "master_key_salt": master_key_salt,
        "message": "E2EE enabled successfully"
    }

@app.post("/password", response_model=PasswordResponse)
def add_password(password_data: PasswordCreate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Add a new password for the current user
    """
    try:
        # Validate category if provided
        if password_data.category_id:
            category = db.query(Category).filter(
                Category.id == password_data.category_id,
                Category.user_id == current_user.id
            ).first()
            if not category:
                raise HTTPException(status_code=400, detail="Categoria nu a fost găsită")
        
        # Encrypt password before saving
        encrypted_password = encrypt_password(password_data.password)
        
        # Create password
        new_password = create_password(
            db=db,
            user_id=str(current_user.id),
            site_name=password_data.site_name,
            url=password_data.url or "",
            login=password_data.login,
            password_encrypted=encrypted_password,
            description=password_data.description or "",
            category_id=password_data.category_id
        )
        
        # Log password creation
        log_user_action(
            user_id=str(current_user.id),
            action="password_created",
            request=request,
            details=f"Password created for site: {password_data.site_name}",
            db=db
        )
        
        return {
            "id": str(new_password.id),
            "site_name": new_password.site_name,
            "url": new_password.url,
            "login": new_password.login,
            "password_encrypted": new_password.password_encrypted,
            "description": new_password.description,
            "created_at": new_password.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if new_password.created_at else new_password.created_at,
            "updated_at": new_password.updated_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if new_password.updated_at else new_password.updated_at,
            "user_id": str(new_password.user_id),
            "category_id": str(new_password.category_id) if new_password.category_id else None
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR creating password: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")

@app.get("/passwords", response_model=list[PasswordResponse])
def get_passwords(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get all passwords for the current user
    """
    try:
        passwords = get_user_passwords(db, str(current_user.id))
        return [
            {
                "id": str(password.id),
                "site_name": password.site_name,
                "url": password.url,
                "login": password.login,
                "password_encrypted": password.password_encrypted,
                "description": password.description,
                "created_at": password.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if password.created_at else password.created_at,
                "updated_at": password.updated_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if password.updated_at else password.updated_at,
                "user_id": str(password.user_id),
                "category_id": str(password.category_id) if password.category_id else None,
                "category_name": db.query(Category).filter(Category.id == password.category_id).first().name if password.category_id else None
            }
            for password in passwords
        ]
    except Exception as e:
        print(f"ERROR getting passwords: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")

@app.get("/password/{password_id}", response_model=PasswordDecryptResponse)
def get_password(password_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get a specific password with decrypted password
    """
    try:
        password = get_password_by_id(db, password_id, str(current_user.id))
        if not password:
            raise HTTPException(status_code=404, detail="Parola nu a fost găsită")
        
        # Decrypt the password
        decrypted_password = decrypt_password(password.password_encrypted)
        
        return {
            "id": str(password.id),
            "site_name": password.site_name,
            "url": password.url,
            "login": password.login,
            "password": decrypted_password,
            "description": password.description,
            "created_at": password.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if password.created_at else password.created_at,
            "updated_at": password.updated_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if password.updated_at else password.updated_at,
            "user_id": str(password.user_id),
            "category_id": str(password.category_id) if password.category_id else None
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR getting password: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")



@app.delete("/password/{password_id}")
def delete_password_endpoint(password_id: str, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Delete a specific password
    """
    try:
        deleted_password = delete_password(db, password_id, str(current_user.id))
        if not deleted_password:
            raise HTTPException(status_code=404, detail="Parola nu a fost găsită")
        
        # Log password deletion
        log_user_action(
            user_id=str(current_user.id),
            action="password_deleted",
            request=request,
            details=f"Password deleted for site: {deleted_password.site_name}",
            db=db
        )
        
        return {"message": "Parola a fost ștearsă cu succes"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR deleting password: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")

# ==================== E2EE PASSWORD ENDPOINTS ====================

@app.post("/password/e2ee", response_model=PasswordResponse)
def add_password_e2ee(password_data: PasswordCreateE2EE, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Add a new password for the current user using E2EE.
    The password is already encrypted by the client using the user's master key.
    """
    try:
        # Validate category if provided
        if password_data.category_id:
            category = db.query(Category).filter(
                Category.id == password_data.category_id,
                Category.user_id == current_user.id
            ).first()
            if not category:
                raise HTTPException(status_code=400, detail="Categoria nu a fost găsită")
        
        # Create password with already-encrypted data
        new_password = create_password(
            db=db,
            user_id=str(current_user.id),
            site_name=password_data.site_name,
            url=password_data.url or "",
            login=password_data.login,
            password_encrypted=password_data.password_encrypted,  # Already encrypted by client
            description=password_data.description or "",
            category_id=password_data.category_id
        )
        
        # Log password creation
        log_user_action(
            user_id=str(current_user.id),
            action="password_created_e2ee",
            request=request,
            details=f"E2EE Password created for site: {password_data.site_name}",
            db=db
        )
        
        return {
            "id": str(new_password.id),
            "site_name": new_password.site_name,
            "url": new_password.url,
            "login": new_password.login,
            "password_encrypted": new_password.password_encrypted,
            "description": new_password.description,
            "created_at": new_password.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if new_password.created_at else new_password.created_at,
            "updated_at": new_password.updated_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if new_password.updated_at else new_password.updated_at,
            "user_id": str(new_password.user_id),
            "category_id": str(new_password.category_id) if new_password.category_id else None
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR creating E2EE password: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")

@app.put("/password/e2ee/{password_id}", response_model=PasswordResponse)
def update_password_e2ee(password_id: str, password_data: PasswordCreateE2EE, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Update a password using E2EE.
    The password is already encrypted by the client using the user's master key.
    """
    try:
        # Validate category if provided
        if password_data.category_id:
            category = db.query(Category).filter(
                Category.id == password_data.category_id,
                Category.user_id == current_user.id
            ).first()
            if not category:
                raise HTTPException(status_code=400, detail="Categoria nu a fost găsită")
        
        # Update password with already-encrypted data
        updated_password = update_password(
            db=db,
            password_id=password_id,
            user_id=str(current_user.id),
            site_name=password_data.site_name,
            url=password_data.url,
            login=password_data.login,
            password_encrypted=password_data.password_encrypted,  # Already encrypted by client
            description=password_data.description,
            category_id=password_data.category_id
        )
        
        if not updated_password:
            raise HTTPException(status_code=404, detail="Parola nu a fost găsită")
        
        # Log password update
        log_user_action(
            user_id=str(current_user.id),
            action="password_updated_e2ee",
            request=request,
            details=f"E2EE Password updated for site: {updated_password.site_name}",
            db=db
        )
        
        return {
            "id": str(updated_password.id),
            "site_name": updated_password.site_name,
            "url": updated_password.url,
            "login": updated_password.login,
            "password_encrypted": updated_password.password_encrypted,
            "description": updated_password.description,
            "created_at": updated_password.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if updated_password.created_at else updated_password.created_at,
            "updated_at": updated_password.updated_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if updated_password.updated_at else updated_password.updated_at,
            "user_id": str(updated_password.user_id),
            "category_id": str(updated_password.category_id) if updated_password.category_id else None
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR updating E2EE password: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")

@app.post("/category", response_model=CategoryResponse)
def create_category(category_data: CategoryCreate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Create a new category for the current user
    """
    try:
        # Check if category name already exists for this user
        existing_category = db.query(Category).filter(
            Category.name == category_data.name,
            Category.user_id == current_user.id
        ).first()
        if existing_category:
            raise HTTPException(status_code=400, detail="Numele categoriei există deja")
        
        # Create category
        new_category = Category(
            name=category_data.name,
            user_id=current_user.id
        )
        db.add(new_category)
        db.commit()
        db.refresh(new_category)
        
        # Log category creation
        log_user_action(
            user_id=str(current_user.id),
            action="category_created",
            request=request,
            details=f"Category created: {category_data.name}",
            db=db
        )
        
        return {
            "id": str(new_category.id),
            "name": new_category.name,
            "user_id": str(new_category.user_id)
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR creating category: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")

@app.get("/categories", response_model=list[CategoryResponse])
def get_categories(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Get all categories for the current user
    """
    try:
        categories = db.query(Category).filter(Category.user_id == current_user.id).all()
        return [
            {
                "id": str(category.id),
                "name": category.name,
                "user_id": str(category.user_id)
            }
            for category in categories
        ]
    except Exception as e:
        print(f"ERROR getting categories: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")

@app.delete("/category/{category_id}")
def delete_category(category_id: str, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Delete a specific category for the current user
    """
    try:
        # Find the category and verify it belongs to the current user
        category = db.query(Category).filter(
            Category.id == category_id,
            Category.user_id == current_user.id
        ).first()
        
        if not category:
            raise HTTPException(status_code=404, detail="Categoria nu a fost găsită")
        
        # Check if there are any passwords using this category
        from models import Password
        passwords_with_category = db.query(Password).filter(
            Password.category_id == category_id,
            Password.user_id == current_user.id
        ).count()
        
        if passwords_with_category > 0:
            raise HTTPException(
                status_code=400, 
                detail=f"Nu se poate șterge categoria. Este folosită de {passwords_with_category} parole. Vă rugăm să ștergeți sau să reatribuiți parolele mai întâi."
            )
        
        # Delete the category
        db.delete(category)
        db.commit()
        
        # Log category deletion
        log_user_action(
            user_id=str(current_user.id),
            action="category_deleted",
            request=request,
            details=f"Category deleted: {category.name}",
            db=db
        )
        
        return {"message": "Categoria a fost ștearsă cu succes"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR deleting category: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")


@app.post("/bioauth")
def bio_auth(request: Request, form_data: LoginForm, db: Session = Depends(get_db)):
    """
    Legacy biometric authentication endpoint.
    Uses password-based authentication with biometric verification.
    """
    try:
        if not form_data.password:
            raise HTTPException(status_code=400, detail="Parola este obligatorie")
        return handle_legacy_bio_auth(request, form_data, db)

    except Exception as e:
        print(f"ERROR during biometric authentication: {str(e)}")
        raise HTTPException(status_code=500, detail="Autentificarea a eșuat")

def handle_legacy_bio_auth(request: Request, form_data: LoginForm, db: Session):
    """Handle legacy password-based authentication"""
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        # Log failed attempt
        log_user_action(
            user_id=str(user.id) if user else None,
            action="login_password_failed",
            request=request,
            details=f"Failed login attempt for user {form_data.username}",
            db=db
        )
        raise HTTPException(status_code=401, detail="Credențiale invalide")

    # Generate tokens
    token_access = create_access_token({"sub": str(user.id), "role": user.role, "username": user.username})
    token_refresh = create_refresh_token(
    db=db,
    user_id=str(user.id),
    payload={"sub": str(user.id)}
)
    
    # Extract JTI from token for tracking
    token_payload = jwt.decode(token_refresh, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
    token_jti = token_payload.get("jti")
    
    # Store hashed token for security
    token_hash = hash_token(token_refresh)
    db.add(RefreshToken(
        token_hash = token_hash, 
        token_jti = token_jti,
        user_id = user.id, 
        expires_at = datetime.utcnow() + timedelta(days=7)
    ))
    db.commit()

    log_user_action(
        user_id=str(user.id),
        action="login_password",
        request=request,
        details=f"User {user.username} logged in via password",
        db=db
    )

    return {"access_token": token_access, "refresh_token": token_refresh, "token_type": "bearer"}

@app.get("/test")
def test_endpoint():
    """
    Simple test endpoint to check connectivity
    """
    return {"message": "Backend is reachable", "timestamp": datetime.utcnow().isoformat()}

@app.get("/auth/biometric/status/{username}")
def check_biometric_status(username: str, db: Session = Depends(get_db)):
    """
    Check if biometric authentication is available for a user
    Verifies both local data availability and persistent token status
    Only available for regular users (not admins)
    """
    try:
        # Check if user exists
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return {"biometric_available": False, "reason": "user_not_found"}
        
        # Check if user is admin - biometric auth only for regular users
        if user.role == "admin":
            return {"biometric_available": False, "reason": "admin_user_not_allowed"}
        
        # Check if user has active persistent refresh token
        from models import PersistentRefreshToken
        from sqlalchemy import and_
        persistent_token = db.query(PersistentRefreshToken).filter(and_(PersistentRefreshToken.user_id == user.id, PersistentRefreshToken.is_active.is_(True), PersistentRefreshToken.expires_at > datetime.utcnow())).first()
        # 🔥 DEBUG AICI
        print("TOKEN DEBUG:", {
        "exists": persistent_token is not None,
        "is_active": persistent_token.is_active if persistent_token else None,
        "expires_at": persistent_token.expires_at if persistent_token else None,
        "now": datetime.utcnow()
            })
        if not persistent_token:
            return {"biometric_available": False, "reason": "no_active_persistent_token"}
        
        return {
        "biometric_available": persistent_token is not None,
        "has_persistent_token": persistent_token is not None,
        "token_expires_at": persistent_token.expires_at.isoformat() if persistent_token else None
        }
    except Exception as e:
        print(f"Error checking biometric status: {e}")
        return {"biometric_available": False, "reason": "server_error"}

@app.post("/auth/refresh")
def refresh_token(request: Request, refresh_token: str = None, persistent_refresh_token: str = None, db: Session = Depends(get_db)):
    """
    Refresh access token using either regular refresh token or persistent refresh token
    """
    try:
        user_id = None
        
        # Try persistent refresh token first (for biometric login)
        if persistent_refresh_token:
            is_valid, user_id = verify_persistent_refresh_token(db, persistent_refresh_token)
            if is_valid:
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    # Generate new access token
                    token_access = create_access_token({
                        "sub": str(user.id), 
                        "role": user.role, 
                        "username": user.username
                    })
                    
                    log_user_action(
                        user_id=str(user.id),
                        action="token_refreshed_persistent",
                        request=request,
                        details="Access token refreshed using persistent refresh token",
                        db=db
                    )
                    
                    return {
                        "access_token": token_access,
                        "token_type": "bearer",
                        "expires_in": 3600,
                        "refresh_method": "persistent"
                    }
        
        # Fall back to regular refresh token
        if refresh_token:
            # Get all refresh tokens for this user and verify hash
            all_tokens = db.query(RefreshToken).filter(
                RefreshToken.expires_at > datetime.utcnow()
            ).all()
            
            # Find the token with matching hash
            token_record = None
            for token in all_tokens:
                if verify_hashed_token(refresh_token, token.token_hash):
                    token_record = token
                    break
            
            if token_record:
                user = db.query(User).filter(User.id == token_record.user_id).first()
                if user:
                    # Generate new access token
                    token_access = create_access_token({
                        "sub": str(user.id), 
                        "role": user.role, 
                        "username": user.username
                    })
                    
                    log_user_action(
                        user_id=str(user.id),
                        action="token_refreshed",
                        request=request,
                        details="Access token refreshed using regular refresh token",
                        db=db
                    )
                    
                    return {
                        "access_token": token_access,
                        "token_type": "bearer",
                        "expires_in": 3600,
                        "refresh_method": "regular"
                    }
        
        raise HTTPException(status_code=401, detail="Refresh token invalid sau expirat")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error refreshing token: {e}")
        raise HTTPException(status_code=500, detail="Eroare internă la refresh token")

@app.post("/logout")
def logout(request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    try:
        print(f"Logout attempt for user: {current_user.username} (ID: {current_user.id})")
        
        # Revoke all regular refresh tokens (not persistent ones)
        revoked_count = revoke_all_user_tokens(db, str(current_user.id))
        print(f"Revoked {revoked_count} regular refresh tokens for user {current_user.username}")
        
        # NOTE: Persistent refresh tokens are NOT revoked on logout
        # They remain valid for 30 days for biometric authentication
        # They are only revoked when biometric auth is disabled
        
        # Log logout action
        log_user_action(
            user_id=str(current_user.id),
            action="logout",
            request=request,
            details=f"User {current_user.username} logged out successfully. Revoked {revoked_count} regular tokens. Persistent tokens remain active for biometric auth.",
            db=db)
        return {"message": "Logout successful", "revoked_tokens": revoked_count}
    except Exception as e:
        print(f"ERROR during logout: {str(e)}")
        try:
            log_user_action(
                user_id=str(current_user.id),
                action="logout",
                request=request,
                details=f"User {current_user.username} logged out with error: {str(e)}",
                db=db)
        except Exception as log_error:
            print(f"ERROR logging logout action: {str(log_error)}")
        
        return {"message": "Logout completed with warnings", "error": str(e)}

@app.post("/user-logs")
def log_user_event(request: Request, log_data: dict, db: Session = Depends(get_db)):
    """
    Log user events from client (login, login_bio, IP_BLOCKED, etc.)
    """
    try:
        print(f"Received user log request: {log_data}")
        
        # Extract data from client request
        username = log_data.get("username")
        event_type = log_data.get("event_type")
        details = log_data.get("details", {})
        
        print(f"Extracted data: username={username}, event_type={event_type}, details={details}")
        
        # Handle different event types
        if event_type == "IP_BLOCKED":
            # Handle IP block events
            log_user_action(
                user_id=None,  # Always None for IP blocks - we log the attempt, not the user
                action="ip_blocked",
                request=request,
                details=f"IP {details.get('ip_address', 'unknown')} blocked for {details.get('block_duration_readable', 'unknown')} after {details.get('failed_attempts', 0)} failed attempts (username: {username})",
                db=db
            )
            print(f"IP block logged successfully for username {username}")
            return {"message": "IP block logged successfully", "status": "success"}
        
        elif event_type in ["login", "login_bio"]:
            # Handle login events
            # Find the user by username
            user = db.query(User).filter(User.username == username).first()
            if not user:
                raise HTTPException(status_code=404, detail=f"User {username} not found")
            
            # Map event types to database actions
            action = "login" if event_type == "login" else "bio_login"
            login_method = details.get("login_method", "unknown")
            
            log_user_action(
                user_id=user.id,
                action=action,
                request=request,
                details=f"User logged in via {login_method}",
                db=db
            )
            print(f"{event_type} logged successfully for username {username}")
            return {"message": f"{event_type} logged successfully", "status": "success"}
        
        elif event_type in ["set_bio_auth", "disable_bio_auth", "confirm_bio_auth"]:
            # Handle biometric authentication setup events
            # Find the user by username
            user = db.query(User).filter(User.username == username).first()
            if not user:
                raise HTTPException(status_code=404, detail=f"User {username} not found")
            
            # Map event types to database actions
            if event_type == "set_bio_auth":
                action = "set_bio_auth"
            elif event_type == "confirm_bio_auth":
                action = "confirm_bio_auth"
            else:
                action = "disable_bio_auth"
            bio_method = details.get("bio_method", "aes_key")
            
            if event_type == "set_bio_auth":
                details_message = f"User {username} enabled biometric authentication using {bio_method}"
            elif event_type == "confirm_bio_auth":
                details_message = f"User {username} confirmed biometric authentication using {bio_method}"
            else:
                details_message = f"User {username} disabled biometric authentication"
                # Revoke persistent refresh tokens when biometric auth is disabled
                revoked = revoke_persistent_refresh_tokens(db, str(user.id))
                print(f"Revoked {revoked} persistent refresh tokens for user {username} (biometric auth disabled)")
            
            log_user_action(
                user_id=user.id,
                action=action,
                request=request,
                details=details_message,
                db=db
            )
            print(f"{event_type} logged successfully for username {username}")
            return {"message": f"{event_type} logged successfully", "status": "success"}
        
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported event type: {event_type}")
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR logging user event: {str(e)}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Înregistrarea evenimentului a eșuat")

@app.get("/users", response_model=list[UserResponse])
def get_all_users(current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """
    Get all users (admin only)
    """
    users = db.query(User).order_by(User.created_at.desc()).all()
    return [
        {
            "id": str(user.id),
            "username": user.username,
            "role": user.role,
            "created_at": user.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if user.created_at else user.created_at
        }
        for user in users
    ]

@app.put("/users/{user_id}/role")
def update_user_role(user_id: str, role_data: dict, request: Request, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """
    Update user role (admin only)
    """
    try:
        # Prevent admin from changing their own role
        if str(current_user.id) == user_id:
            raise HTTPException(status_code=403, detail="Nu poți modifica propriul rol")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Utilizatorul nu a fost găsit")
        
        new_role = role_data.get("role")
        if new_role not in ["user", "admin"]:
            raise HTTPException(status_code=400, detail="Rol invalid")
        
        # Prevent changing the last admin to user
        if user.role == "admin" and new_role == "user":
            admin_count = db.query(User).filter(User.role == "admin").count()
            if admin_count <= 1:
                raise HTTPException(status_code=403, detail="Nu poți schimba rolul ultimului admin")
        
        old_role = user.role
        user.role = new_role
        db.commit()
        
        # Revoke all user tokens to force re-login with new role
        revoked_count = revoke_all_user_tokens(db, str(user.id))
        print(f"Revoked {revoked_count} tokens for user {user.username} after role change")
        
        # Log role change action
        log_user_action(
            user_id=str(current_user.id),
            action="role_changed",
            request=request,
            details=f"Admin {current_user.username} changed role of user {user.username} from {old_role} to {new_role}",
            db=db
        )
        
        return {"message": f"Rolul utilizatorului {user.username} a fost actualizat la {new_role}. Utilizatorul trebuie să se autentifice din nou."}
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR updating user role: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă")

@app.delete("/users/{user_id}")
def delete_user(user_id: str, request: Request, current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """
    Delete user (admin only)
    """
    try:
        # Prevent admin from deleting themselves
        if str(current_user.id) == user_id:
            raise HTTPException(status_code=403, detail="Nu poți șterge propriul cont")
        
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=404, detail="Utilizatorul nu a fost găsit")
        
        # Prevent deleting the last admin
        if user.role == "admin":
            admin_count = db.query(User).filter(User.role == "admin").count()
            if admin_count <= 1:
                raise HTTPException(status_code=403, detail="Nu poți șterge ultimul admin")
        
        username = user.username
        
        # Delete all user's passwords
        from models import Password, Category, RefreshToken, PersistentRefreshToken
        db.query(Password).filter(Password.user_id == user.id).delete()
        
        # Delete all user's categories
        db.query(Category).filter(Category.user_id == user.id).delete()
        
        # Delete all user's refresh tokens
        db.query(RefreshToken).filter(RefreshToken.user_id == user.id).delete()
        
        # Delete all user's persistent refresh tokens
        db.query(PersistentRefreshToken).filter(PersistentRefreshToken.user_id == user.id).delete()
        
        # Revoke all user tokens before deletion
        revoked_count = revoke_all_user_tokens(db, str(user.id))
        print(f"Revoked {revoked_count} tokens for user {username} before deletion")
        
        db.delete(user)
        db.commit()
        
        # Log user deletion action
        log_user_action(
            user_id=str(current_user.id),
            action="user_deleted",
            request=request,
            details=f"Admin {current_user.username} deleted user {username} (role: {user.role})",
            db=db
        )
        
        return {"message": f"Utilizatorul {username} a fost șters cu succes"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR deleting user: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă")

@app.get("/user-logs", response_model=list[UserLogResponse])
def get_user_logs(current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """
    Get last 100 user logs (admin only)
    """
    logs = db.query(UserLog).order_by(UserLog.created_at.desc()).limit(100).all()
    return [
        {
            "id": str(log.id),
            "user_id": str(log.user_id),
            "action": log.action,
            "ip_address": log.ip_address,
            "user_agent": log.user_agent,
            "details": log.details,
            "created_at": log.created_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if log.created_at else log.created_at
        }
        for log in logs
    ]

# IP Address Blocking Management Endpoints

@app.get("/admin/ip-blocks", response_model=list[IPAddressBlockedResponse])
def get_ip_blocks(
    active_only: bool = False,
    limit: int = 100,
    current_user: User = Depends(require_role("admin")), 
    db: Session = Depends(get_db)
):
    """
    Get all IP blocks (admin only)
    """
    ip_blocks = get_all_ip_blocks(db, active_only=active_only, limit=limit)
    return [
        {
            "id": str(block.id),
            "ip_address": block.ip_address,
            "blocked_at": block.blocked_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if block.blocked_at else block.blocked_at,
            "block_duration": block.block_duration,
            "is_active": block.is_active,
            "username": block.username,
            "failed_attempts": block.failed_attempts,
            "expires_at": block.expires_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if block.expires_at else block.expires_at
        }
        for block in ip_blocks
    ]

@app.get("/admin/ip-blocks/stats")
def get_ip_block_stats_endpoint(current_user: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    """
    Get IP blocking statistics (admin only)
    """
    stats = get_ip_block_stats(db)
    return stats

@app.post("/admin/ip-blocks", response_model=IPAddressBlockedResponse)
def create_ip_block_admin(
    block_data: IPAddressBlockCreate,
    request: Request,
    current_user: User = Depends(require_role("admin")), 
    db: Session = Depends(get_db)
):
    """
    Create a new IP block (admin only)
    """
    try:
        ip_block = create_ip_block(
            db=db,
            ip_address=block_data.ip_address,
            block_duration=block_data.block_duration,
            username=block_data.username,
            failed_attempts=block_data.failed_attempts
        )
        
        # Log admin action
        log_user_action(
            user_id=str(current_user.id),
            action="ip_block_created",
            request=request,
            details=f"Admin {current_user.username} blocked IP {block_data.ip_address} for {format_duration_ms(block_data.block_duration)}",
            db=db
        )
        
        return {
            "id": str(ip_block.id),
            "ip_address": ip_block.ip_address,
            "blocked_at": ip_block.blocked_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if ip_block.blocked_at else ip_block.blocked_at,
            "block_duration": ip_block.block_duration,
            "is_active": ip_block.is_active,
            "username": ip_block.username,
            "failed_attempts": ip_block.failed_attempts,
            "expires_at": ip_block.expires_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if ip_block.expires_at else ip_block.expires_at,
            "user_id": str(ip_block.user_id) if ip_block.user_id else None
        }
    
    except Exception as e:
        print(f"ERROR creating IP block: {str(e)}")
        raise HTTPException(status_code=500, detail="Crearea blocului IP a eșuat")

@app.put("/admin/ip-blocks/{block_id}", response_model=IPAddressBlockedResponse)
def update_ip_block_admin(
    block_id: str,
    update_data: IPAddressBlockUpdate,
    request: Request,
    current_user: User = Depends(require_role("admin")), 
    db: Session = Depends(get_db)
):
    """
    Update an IP block (admin only)
    """
    try:
        update_dict = update_data.dict(exclude_unset=True)
        ip_block = update_ip_block(db, block_id, update_dict)
        
        if not ip_block:
            raise HTTPException(status_code=404, detail="Blocul IP nu a fost găsit")
        
        # Log admin action
        log_user_action(
            user_id=str(current_user.id),
            action="ip_block_updated",
            request=request,
            details=f"Admin {current_user.username} updated IP block for {ip_block.ip_address}",
            db=db
        )
        
        return {
            "id": str(ip_block.id),
            "ip_address": ip_block.ip_address,
            "blocked_at": ip_block.blocked_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if ip_block.blocked_at else ip_block.blocked_at,
            "block_duration": ip_block.block_duration,
            "is_active": ip_block.is_active,
            "username": ip_block.username,
            "failed_attempts": ip_block.failed_attempts,
            "expires_at": ip_block.expires_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if ip_block.expires_at else ip_block.expires_at,
            "user_id": str(ip_block.user_id) if ip_block.user_id else None
        }
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR updating IP block: {str(e)}")
        raise HTTPException(status_code=500, detail="Actualizarea blocului IP a eșuat")

@app.delete("/admin/ip-blocks/{block_id}")
def delete_ip_block_admin(
    block_id: str,
    request: Request,
    current_user: User = Depends(require_role("admin")), 
    db: Session = Depends(get_db)
):
    """
    Delete an IP block (admin only)
    """
    try:
        ip_block = delete_ip_block(db, block_id)
        
        if not ip_block:
            raise HTTPException(status_code=404, detail="Blocul IP nu a fost găsit")
        
        # Log admin action
        log_user_action(
            user_id=str(current_user.id),
            action="ip_block_deleted",
            request=request,
            details=f"Admin {current_user.username} deleted IP block for {ip_block.ip_address}",
            db=db
        )
        
        return {"message": f"Blocul IP pentru {ip_block.ip_address} a fost șters cu succes"}
    
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR deleting IP block: {str(e)}")
        raise HTTPException(status_code=500, detail="Ștergerea blocului IP a eșuat")

@app.post("/admin/ip-blocks/cleanup")
def cleanup_expired_blocks(
    request: Request,
    current_user: User = Depends(require_role("admin")), 
    db: Session = Depends(get_db)
):
    """
    Clean up expired IP blocks (admin only)
    """
    try:
        cleaned_count = cleanup_expired_ip_blocks(db)
        
        # Log admin action
        log_user_action(
            user_id=str(current_user.id),
            action="ip_blocks_cleanup",
            request=request,
            details=f"Admin {current_user.username} cleaned up {cleaned_count} expired IP blocks",
            db=db
        )
        
        return {"message": f"Au fost șterse {cleaned_count} bolcuri de IP expirate"}
    
    except Exception as e:
        print(f"ERROR cleaning up IP blocks: {str(e)}")
        raise HTTPException(status_code=500, detail="Curățarea blocului a eșuat")

@app.get("/admin/ip-blocks/check/{ip_address}")
def check_ip_address(
    ip_address: str,
    current_user: User = Depends(require_role("admin")), 
    db: Session = Depends(get_db)
):
    """
    Check if an IP address is blocked (admin only)
    """
    try:
        is_blocked, ip_block = is_ip_blocked(db, ip_address)
        
        if is_blocked and ip_block:
            return {
                "ip_address": ip_address,
                "is_blocked": True,
                "block_details": {
                    "id": str(ip_block.id),
                    "blocked_at": ip_block.blocked_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if ip_block.blocked_at else ip_block.blocked_at,
                    "block_duration": ip_block.block_duration,
                    "expires_at": ip_block.expires_at.replace(tzinfo=ZoneInfo("UTC")).astimezone(MOLDOVA_TZ) if ip_block.expires_at else ip_block.expires_at,
                    "username": ip_block.username,
                    "failed_attempts": ip_block.failed_attempts
                }
            }
        else:
            return {
                "ip_address": ip_address,
                "is_blocked": False,
                "block_details": None
            }
    
    except Exception as e:
        print(f"ERROR checking IP address: {str(e)}")
        raise HTTPException(status_code=500, detail="Verificarea adresei IP a eșuat")

# Temporary endpoint for testing - clear IP blocks
@app.post("/admin/clear-ip-blocks")
def clear_ip_blocks(db: Session = Depends(get_db)):
    """
    Clear all IP blocks (for testing purposes only)
    """
    try:
        # Delete all IP blocks
        deleted_count = db.query(IPAddressBlocked).count()
        db.query(IPAddressBlocked).delete()
        db.commit()
        return {"message": f"Cleared {deleted_count} IP blocks successfully"}
    except Exception as e:
        print(f"ERROR clearing IP blocks: {str(e)}")
        raise HTTPException(status_code=500, detail="Clearing IP blocks failed")

# Temporary endpoint for testing - check IP blocks
@app.get("/admin/check-ip-blocks")
def check_ip_blocks(db: Session = Depends(get_db)):
    """
    Check all IP blocks (for testing purposes only)
    """
    try:
        blocks = db.query(IPAddressBlocked).all()
        return {
            "total_blocks": len(blocks),
            "blocks": [
                {
                    "id": str(block.id),
                    "ip_address": block.ip_address,
                    "is_active": block.is_active,
                    "blocked_at": block.blocked_at,
                    "expires_at": block.expires_at,
                    "username": block.username,
                    "failed_attempts": block.failed_attempts
                }
                for block in blocks
            ]
        }
    except Exception as e:
        print(f"ERROR checking IP blocks: {str(e)}")
        raise HTTPException(status_code=500, detail="Checking IP blocks failed")

# Temporary endpoint for testing - check user existence
@app.get("/admin/check-user/{username}")
def check_user(username: str, db: Session = Depends(get_db)):
    """
    Check if user exists and show basic info (for testing purposes only)
    """
    try:
        user = db.query(User).filter(User.username == username).first()
        if not user:
            return {"exists": False, "username": username}
        
        return {
            "exists": True,
            "username": user.username,
            "id": str(user.id),
            "role": user.role,
            "created_at": user.created_at,
            "has_password_hash": bool(user.password_hash)
        }
    except Exception as e:
        print(f"ERROR checking user: {str(e)}")
        raise HTTPException(status_code=500, detail="Checking user failed")

# Simple connectivity test endpoint
@app.get("/test-connectivity")
def test_connectivity():
    """
    Simple endpoint to test connectivity
    """
    return {"status": "connected", "timestamp": datetime.utcnow().isoformat()}

# Debug endpoint to test password verification
@app.post("/debug-auth")
def debug_auth(request: Request, form_data: LoginForm, db: Session = Depends(get_db)):
    """
    Debug endpoint to test password verification step by step
    """
    print(f"DEBUG /debug-auth request:")
    print(f"  - Username: {form_data.username}")
    print(f"  - Password: {form_data.password}")
    print(f"  - Grant type: {form_data.grant_type}")
    
    user = db.query(User).filter(User.username == form_data.username).first()
    
    if not user:
        print(f"  - User not found in database")
        return {"exists": False, "reason": "User not found"}
    
    print(f"  - User found: {user.username}")
    print(f"  - User has password hash: {bool(user.password_hash)}")
    
    try:
        is_valid = verify_password(form_data.password, user.password_hash)
        print(f"  - Password verification result: {is_valid}")
        return {
            "exists": True,
            "username": user.username,
            "password_valid": is_valid,
            "has_password_hash": bool(user.password_hash)
        }
    except Exception as e:
        print(f"  - Password verification error: {str(e)}")
        return {
            "exists": True,
            "username": user.username,
            "password_valid": False,
            "error": str(e)
        }

