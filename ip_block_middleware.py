"""
IP Address Blocking Middleware

This middleware automatically checks if incoming requests are from blocked IP addresses.
"""
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from security import check_ip_block, get_client_ip
from database import get_db
import crud

async def ip_block_middleware(request: Request, call_next):
    """
    Middleware to check IP blocks on all requests
    
    This middleware runs before the main application and checks if the client IP is blocked.
    If blocked, it returns a 429 response immediately.
    """
    # Skip IP block checking for certain endpoints (like docs, health checks)
    skip_paths = ["/docs", "/redoc", "/openapi.json", "/", "/test"]
    
    if request.url.path in skip_paths:
        response = await call_next(request)
        return response
    
    # Get database session
    db_gen = get_db()
    db = next(db_gen)
    
    try:
        # Check if IP is blocked
        is_blocked, ip_block = check_ip_block(request, db)
        
        if is_blocked:
            ip_address = get_client_ip(request)
            return JSONResponse(
                status_code=429,
                content={
                    "detail": f"IP address {ip_address} is blocked. Try again after {ip_block.expires_at}",
                    "error_code": "IP_BLOCKED",
                    "block_expires_at": ip_block.expires_at.isoformat() if ip_block.expires_at else None
                }
            )
        
        # Continue with the request
        response = await call_next(request)
        return response
        
    finally:
        db.close()
        # Don't try to close the generator, just let it be cleaned up by garbage collection
