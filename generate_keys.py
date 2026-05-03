#!/usr/bin/env python3
"""
Script to generate and save encryption keys for the password manager.
Run this once to generate the keys and add them to your .env.local file.
"""

import secrets
import os

def generate_keys():
    """Generate secure keys for JWT and AES encryption"""
    
    # Generate JWT secret key (64 bytes for token_urlsafe)
    jwt_secret = secrets.token_urlsafe(64)
    
    # Generate AES-256 key (32 bytes) and convert to hex for storage
    aes_key = secrets.token_bytes(32)
    aes_key_hex = aes_key.hex()
    
    print("Generated keys:")
    print(f"JWT_SECRET_KEY={jwt_secret}")
    print(f"AES_ENCRYPTION_KEY={aes_key_hex}")
    print()
    print("Add these to your .env.local file:")
    print(f"JWT_SECRET_KEY={jwt_secret}")
    print(f"AES_ENCRYPTION_KEY={aes_key_hex}")
    print()
    print("IMPORTANT: Save these keys securely! If you lose them, all encrypted data will be permanently lost.")
    print("Never commit these keys to version control.")

if __name__ == "__main__":
    generate_keys()
