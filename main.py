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
    PasswordUpdate, PasswordDecryptResponse, CategoryCreate, CategoryResponse,
    IPAddressBlockedResponse, IPAddressBlockCreate, IPAddressBlockUpdate
)
from crud import (
    create_password, get_user_passwords, get_password_by_id, update_password, delete_password,
    create_ip_block, get_all_ip_blocks, update_ip_block, delete_ip_block, 
    cleanup_expired_ip_blocks, get_ip_block_stats, is_ip_blocked
)
from sqlalchemy.orm import Session
from database import get_db
from models import User, RefreshToken, UserLog, Category, IPAddressBlocked
from security import (
    check_ip_block, block_ip_address, get_delay_for_failed_attempts, 
    format_duration_ms, get_client_ip, get_or_create_persistent_refresh_token,
    create_persistent_refresh_token, store_persistent_refresh_token, create_refresh_token, hash_password, 
    verify_password, create_access_token, get_current_user, require_role, 
    log_user_action, revoke_all_user_tokens, revoke_persistent_refresh_tokens, decrypt_password, 
    verify_persistent_refresh_token, hash_token, verify_hashed_token
)
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

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
    allow_origins=origins,
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
                    "detail": f"Adresa IP {ip_address} este blocată. Încearcă din nou peste {ip_block.expires_at}",
                    "error_code": "IP_BLOCKED",
                    "block_expires_at": ip_block.expires_at.isoformat() if ip_block.expires_at else None
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

    new_user = User(username = user.username, email = user.email, role = user.role, password_hash = hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Log registration action
    log_user_action(
        user_id=str(new_user.id),
        action="register",
        request=request,
        details=f"User {new_user.username} registered successfully",
        db=db
    )

    # Convert UUID to string for response
    return {
        "id": str(new_user.id),
        "username": new_user.username,
        "role": new_user.role,
        "created_at": new_user.created_at
    }

@app.post("/auth")
def auth(request: Request, form_data: LoginForm, db: Session = Depends(get_db)):
    # Check if IP is blocked first
    is_blocked, ip_block = check_ip_block(request, db)
    if is_blocked:
        ip_address = get_client_ip(request)
        raise HTTPException(
            status_code=429,
            detail=f"Adresa IP {ip_address} este blocată. Încearcă din nou după {ip_block.expires_at}"
        )

    user = db.query(User).filter(User.username == form_data.username).first()

    if not user or not verify_password(form_data.password, user.password_hash):
        # Get IP address for tracking failed attempts
        ip_address = get_client_ip(request)

        # Check existing failed attempts for this IP
        recent_failed_logs = db.query(UserLog).filter(
            UserLog.ip_address == ip_address,
            UserLog.action == "login_failed",
            UserLog.created_at >= datetime.utcnow() - timedelta(hours=1)
        ).count()

        failed_attempts = recent_failed_logs + 1
        delay = get_delay_for_failed_attempts(failed_attempts)

        # Log failed login attempt
        if user:
            log_user_action(
                user_id=str(user.id),
                action="login_failed",
                request=request,
                details=f"Failed login attempt for user {user.username}: wrong password (attempt {failed_attempts})",
                db=db
            )
        else:
            log_user_action(
                user_id=None,
                action="login_failed",
                request=request,
                details=f"Failed login attempt: username {form_data.username} not found (attempt {failed_attempts})",
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
                raise HTTPException( status_code=429, detail=f"Prea multe încercări eșuate. Adresa IP {ip_address} blocată permanent.")
            else:
                raise HTTPException( status_code=429,detail=f"Prea multe încercări eșuate. Adresa IP {ip_address} blocată pentru {format_duration_ms(delay).replace('seconds', 'secunde').replace('minutes', 'minute').replace('hours', 'ore')}.")

        raise HTTPException(status_code=401, detail="Credențiale invalide")

    token_access = create_access_token({"sub": str(user.id), "role": user.role, "username": user.username })
    token_refresh = create_refresh_token({"sub": str(user.id)})

    # Extract JTI from token for tracking
    token_payload = jwt.decode(token_refresh, os.getenv("JWT_SECRET_KEY"), algorithms=["HS256"])
    token_jti = token_payload.get("jti")

    # Store hashed token for security
    token_hash = hash_token(token_refresh)
    new_refresh = RefreshToken( token_hash = token_hash, token_jti = token_jti, user_id = user.id, expires_at = datetime.utcnow() + timedelta(days=7))
    db.add(new_refresh)
    db.commit()

    # Log successful login
    log_user_action(
        user_id=str(user.id),
        action="login",
        request=request,
        details=f"User {user.username} logged in successfully with password",
        db=db
    )
    return {
        "access_token": token_access,
        "refresh_token": token_refresh,
        "token_type": "bearer",
        "expires_in": 3600
    }

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
    return {
        "message": "Biometric authentication ready",
        "user_id": str(user.id),
        "username": user.username,
        "biometric_method": form_data.biometric_method,
        "next_step": "proceed_with_decrypted_password"
    }

@app.post("/auth/biometric/verify")
def biometric_verify(request: Request, form_data: LoginForm, db: Session = Depends(get_db)):
    """
    Endpoint pentru verificarea finală a credențialelor decriptate biometric.
    Acesta este apelat după ce clientul decriptează parola cu cheia AES biometrică.
    """
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
    token_refresh = create_refresh_token({"sub": str(user.id)})
    
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
    
    # Log successful biometric login
    log_user_action(
        user_id=str(user.id),
        action="bio_login",
        request=request,
        details=f"User {user.username} successfully authenticated with biometric AES keys",
        db=db
    )
    
    return {
        "access_token": token_access,
        "refresh_token": token_refresh,
        "token_type": "bearer",
        "expires_in": 3600,
        "login_method": "biometric_aes"
    }

@app.post("/auth/biometric/direct")
def direct_biometric_auth(request: Request, form_data: LoginForm, db: Session = Depends(get_db)):
    """
    Endpoint pentru autentificare directă biometrică.
    Clientul trimite username-ul și parola decriptată biometric.
    Acest endpoint permite autentificarea fără a fi nevoie de login cu parola înainte.
    """
    # Verifică dacă IP este blocat
    is_blocked, ip_block = check_ip_block(request, db)
    if is_blocked:
        ip_address = get_client_ip(request)
        raise HTTPException(
            status_code=429,
            detail=f"Adresa IP {ip_address} este blocată. Încearcă din nou după {ip_block.expires_at}"
        )

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

    # Obține sau creează persistent refresh token pentru biometric (30 zile)
    # Reutilizează token-ul existent dacă este încă valid
    persistent_token, persistent_token_hash = get_or_create_persistent_refresh_token(
        db, str(user.id)
    )
    print(f"DEBUG: Persistent token for user {user.id}: {persistent_token[:20]}...")

    # Creează și refresh token standard (7 zile)
    token_refresh = create_refresh_token({"sub": str(user.id)})

    # Extract JTI from token for tracking
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

    # Log successful biometric login
    log_user_action(
        user_id=str(user.id),
        action="bio_login",
        request=request,
        details=f"User {user.username} successfully authenticated with direct biometric",
        db=db
    )

    return {
        "access_token": token_access,
        "refresh_token": token_refresh,
        "persistent_refresh_token": persistent_token,
        "token_type": "bearer",
        "expires_in": 3600,
        "login_method": "biometric_direct"
    }


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
        
        # Create password
        new_password = create_password(
            db=db,
            user_id=str(current_user.id),
            site_name=password_data.site_name,
            url=password_data.url or "",
            login=password_data.login,
            password=password_data.password,
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
            "created_at": new_password.created_at,
            "updated_at": new_password.updated_at,
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
                "created_at": password.created_at,
                "updated_at": password.updated_at,
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
            "created_at": password.created_at,
            "updated_at": password.updated_at,
            "user_id": str(password.user_id),
            "category_id": str(password.category_id) if password.category_id else None
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR getting password: {str(e)}")
        raise HTTPException(status_code=500, detail="Eroare internă de server")

@app.put("/password/{password_id}", response_model=PasswordResponse)
def update_password_endpoint(password_id: str, password_data: PasswordUpdate, request: Request, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """
    Update a specific password
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
        
        # Update password
        updated_password = update_password(
            db=db,
            password_id=password_id,
            user_id=str(current_user.id),
            site_name=password_data.site_name,
            url=password_data.url,
            login=password_data.login,
            password=password_data.password,
            description=password_data.description,
            category_id=password_data.category_id
        )
        
        if not updated_password:
            raise HTTPException(status_code=404, detail="Parola nu a fost găsită")
        
        # Log password update
        log_user_action(
            user_id=str(current_user.id),
            action="password_updated",
            request=request,
            details=f"Password updated for site: {updated_password.site_name}",
            db=db
        )
        
        return {
            "id": str(updated_password.id),
            "site_name": updated_password.site_name,
            "url": updated_password.url,
            "login": updated_password.login,
            "password_encrypted": updated_password.password_encrypted,
            "description": updated_password.description,
            "created_at": updated_password.created_at,
            "updated_at": updated_password.updated_at,
            "user_id": str(updated_password.user_id),
            "category_id": str(updated_password.category_id) if updated_password.category_id else None
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR updating password: {str(e)}")
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
    token_refresh = create_refresh_token({"sub": str(user.id)})
    
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
        
        elif event_type in ["set_bio_auth", "disable_bio_auth"]:
            # Handle biometric authentication setup events
            # Find the user by username
            user = db.query(User).filter(User.username == username).first()
            if not user:
                raise HTTPException(status_code=404, detail=f"User {username} not found")
            
            # Map event types to database actions
            action = "set_bio_auth" if event_type == "set_bio_auth" else "disable_bio_auth"
            bio_method = details.get("bio_method", "aes_key")
            
            if event_type == "set_bio_auth":
                details_message = f"User {username} enabled biometric authentication using {bio_method}"
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
            "created_at": user.created_at
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
        
        # Log role change action
        log_user_action(
            user_id=str(current_user.id),
            action="role_changed",
            request=request,
            details=f"Admin {current_user.username} changed role of user {user.username} from {old_role} to {new_role}",
            db=db
        )
        
        return {"message": f"Rolul utilizatorului {user.username} a fost actualizat la {new_role}"}
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
            "created_at": log.created_at
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
            "blocked_at": block.blocked_at,
            "block_duration": block.block_duration,
            "is_active": block.is_active,
            "username": block.username,
            "failed_attempts": block.failed_attempts,
            "expires_at": block.expires_at,
            "user_id": str(block.user_id) if block.user_id else None
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
            "blocked_at": ip_block.blocked_at,
            "block_duration": ip_block.block_duration,
            "is_active": ip_block.is_active,
            "username": ip_block.username,
            "failed_attempts": ip_block.failed_attempts,
            "expires_at": ip_block.expires_at,
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
            "blocked_at": ip_block.blocked_at,
            "block_duration": ip_block.block_duration,
            "is_active": ip_block.is_active,
            "username": ip_block.username,
            "failed_attempts": ip_block.failed_attempts,
            "expires_at": ip_block.expires_at,
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
                    "blocked_at": ip_block.blocked_at,
                    "block_duration": ip_block.block_duration,
                    "expires_at": ip_block.expires_at,
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

