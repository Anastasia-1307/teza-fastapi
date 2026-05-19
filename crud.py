from schemas import Register
from sqlalchemy.orm import Session
import models, schemas, security
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

# Configure timezone for Moldova
MOLDOVA_TZ = ZoneInfo("Europe/Chisinau")


def _utc_now_naive() -> datetime:
    """Return current UTC time as naive datetime to match stored DB values."""
    return datetime.utcnow()


def _is_block_expired(block: models.IPAddressBlocked, reference_time: datetime | None = None) -> bool:
    """Check whether a block has expired using UTC naive datetimes."""
    if not block.expires_at:
        return False

    current_time = reference_time or _utc_now_naive()
    return block.expires_at <= current_time


def _sync_expired_ip_blocks(db: Session) -> None:
    """Mark expired active IP blocks as inactive before reads/statistics."""
    current_time = _utc_now_naive()
    expired_blocks = db.query(models.IPAddressBlocked).filter(
        models.IPAddressBlocked.is_active == True,
        models.IPAddressBlocked.expires_at.isnot(None),
        models.IPAddressBlocked.expires_at <= current_time
    ).all()

    if not expired_blocks:
        return

    for block in expired_blocks:
        block.is_active = False

    db.commit()

def get_user_by_name(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, user: schemas.Register):
    hashed_pass = security.hash_password(user.password)
    db_user = models.User(username=user.username, password_hash=hashed_pass, role=user.role)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def get_all_users(db: Session):
    return db.query(models.User).all()

def update_user_role(db: Session, user_id: int, new_role: str):
    user = db.query(models.User).filter(models.User.id == user_id).first()
    if user:
        user.role = new_role
        db.commit()
        db.refresh(user)
    return user

def create_password(db: Session, user_id: str, site_name: str, url: str, login: str, password_encrypted: str, description: str, category_id: str = None):
    db_password = models.Password(
        user_id=user_id,
        site_name=site_name,
        url=url,
        login=login,
        password_encrypted=password_encrypted,
        description=description,
        category_id=category_id
    )
    db.add(db_password)
    db.commit()
    db.refresh(db_password)
    return db_password

def get_user_passwords(db: Session, user_id: str):
    return db.query(models.Password).filter(models.Password.user_id == user_id).all()

def get_password_by_id(db: Session, password_id: str, user_id: str):
    return db.query(models.Password).filter(
        models.Password.id == password_id,
        models.Password.user_id == user_id
    ).first()

def update_password(db: Session, password_id: str, user_id: str, site_name: str = None, url: str = None, login: str = None, password_encrypted: str = None, description: str = None, category_id: str = None):
    db_password = get_password_by_id(db, password_id, user_id)
    if db_password:
        if site_name:
            db_password.site_name = site_name
        if url:
            db_password.url = url
        if login:
            db_password.login = login
        if password_encrypted:
            db_password.password_encrypted = password_encrypted
        if description:
            db_password.description = description
        if category_id:
            db_password.category_id = category_id
        db.commit()
        db.refresh(db_password)
    return db_password

def delete_password(db: Session, password_id: str, user_id: str):
    db_password = get_password_by_id(db, password_id, user_id)
    if db_password:
        db.delete(db_password)
        db.commit()
    return db_password

def verify_user_password(db: Session, username: str, password: str) -> bool:
    user = get_user_by_name(db, username)
    if user:
        return security.verify_password(password, user.password_hash)
    return False

# IP Address Blocking CRUD operations
def create_ip_block(db: Session, ip_address: str, block_duration: int, username: str = None, failed_attempts: int = 1):
    """Create a new IP address block"""
    _sync_expired_ip_blocks(db)

    # Calculate expiration time
    expires_at = None
    if block_duration != float('inf'):  # Permanent block
        duration_seconds = block_duration / 1000
        expires_at = _utc_now_naive() + timedelta(seconds=duration_seconds)
    
    # Deactivate existing blocks for this IP
    existing_blocks = db.query(models.IPAddressBlocked).filter(
        models.IPAddressBlocked.ip_address == ip_address,
        models.IPAddressBlocked.is_active == True
    ).all()
    
    for block in existing_blocks:
        block.is_active = False
    
    ip_block = models.IPAddressBlocked(
        ip_address=ip_address,
        block_duration=block_duration,
        is_active=True,
        username=username,
        failed_attempts=failed_attempts,
        expires_at=expires_at
    )
    
    db.add(ip_block)
    db.commit()
    db.refresh(ip_block)
    return ip_block

def get_ip_block_by_address(db: Session, ip_address: str, active_only: bool = True):
    """Get IP block by address"""
    _sync_expired_ip_blocks(db)
    query = db.query(models.IPAddressBlocked).filter(models.IPAddressBlocked.ip_address == ip_address)
    
    if active_only:
        query = query.filter(models.IPAddressBlocked.is_active == True)
    
    return query.first()

def is_ip_blocked(db: Session, ip_address: str):
    """Check if IP address is currently blocked"""
    ip_block = get_ip_block_by_address(db, ip_address, active_only=True)
    
    if not ip_block:
        return False, None

    if _is_block_expired(ip_block):
        ip_block.is_active = False
        db.commit()
        return False, None

    return True, ip_block

def get_all_ip_blocks(db: Session, active_only: bool = False, limit: int = 100):
    """Get all IP blocks"""
    _sync_expired_ip_blocks(db)
    query = db.query(models.IPAddressBlocked)
    
    if active_only:
        query = query.filter(models.IPAddressBlocked.is_active == True)
    
    return query.order_by(models.IPAddressBlocked.blocked_at.desc()).limit(limit).all()

def update_ip_block(db: Session, block_id: str, update_data: dict):
    """Update IP block"""
    ip_block = db.query(models.IPAddressBlocked).filter(models.IPAddressBlocked.id == block_id).first()
    
    if not ip_block:
        return None
    
    for key, value in update_data.items():
        if hasattr(ip_block, key):
            setattr(ip_block, key, value)
    
    db.commit()
    db.refresh(ip_block)
    return ip_block

def delete_ip_block(db: Session, block_id: str):
    """Delete IP block"""
    ip_block = db.query(models.IPAddressBlocked).filter(models.IPAddressBlocked.id == block_id).first()
    
    if ip_block:
        db.delete(ip_block)
        db.commit()
    return ip_block

def cleanup_expired_ip_blocks(db: Session) -> int:
    """Clean up expired IP blocks"""
    current_time = _utc_now_naive()
    expired_blocks = db.query(models.IPAddressBlocked).filter(
        models.IPAddressBlocked.expires_at.isnot(None),
        models.IPAddressBlocked.expires_at <= current_time
    ).all()
    
    count = 0
    for block in expired_blocks:
        db.delete(block)
        count += 1
    
    db.commit()
    return count

def get_ip_block_stats(db: Session):
    """Get IP blocking statistics"""
    _sync_expired_ip_blocks(db)

    total_active = db.query(models.IPAddressBlocked).filter(models.IPAddressBlocked.is_active == True).count()
    total_blocks = db.query(models.IPAddressBlocked).count()
    
    # Blocks in last 24 hours
    current_time = _utc_now_naive()
    yesterday = current_time - timedelta(days=1)
    recent_blocks = db.query(models.IPAddressBlocked).filter(
        models.IPAddressBlocked.blocked_at >= yesterday
    ).count()
    
    # Expiring soon (next hour)
    next_hour = current_time + timedelta(hours=1)
    expiring_soon = db.query(models.IPAddressBlocked).filter(
        models.IPAddressBlocked.is_active == True,
        models.IPAddressBlocked.expires_at <= next_hour,
        models.IPAddressBlocked.expires_at > current_time
    ).count()
    
    return {
        "total_active": total_active,
        "total_blocks": total_blocks,
        "recent_blocks_24h": recent_blocks,
        "expiring_soon_1h": expiring_soon
    }
