"""
Authentication Configuration Module

This module handles user authentication, password hashing, and security settings.
Credentials are loaded from environment variables or a config file.

To set credentials via environment variables:
    export ADMIN_USERNAME="admin"
    export ADMIN_PASSWORD_HASH="<hash_from_hash_password.py>"
    export USER_USERNAME="user"
    export USER_PASSWORD_HASH="<hash_from_hash_password.py>"

Or create a .env file with:
    ADMIN_USERNAME=admin
    ADMIN_PASSWORD_HASH=<hash>
    USER_USERNAME=user
    USER_PASSWORD_HASH=<hash>
"""

import os
import hashlib
import secrets
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta

# Security settings
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 5
PASSWORD_SALT_LENGTH = 32

# In-memory storage for failed attempts (per username)
_failed_attempts: Dict[str, Dict] = {}


def hash_password(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """
    Hash a password using PBKDF2 with SHA-256.
    
    Args:
        password: Plain text password
        salt: Optional salt bytes (generated if not provided)
    
    Returns:
        Tuple of (hashed_password_hex, salt_hex)
    """
    if salt is None:
        salt = secrets.token_bytes(PASSWORD_SALT_LENGTH)
    
    # Use PBKDF2 with 100,000 iterations
    key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return key.hex(), salt.hex()


def verify_password(password: str, password_hash: str, salt_hex: str) -> bool:
    """
    Verify a password against a stored hash.
    
    Args:
        password: Plain text password to verify
        password_hash: Stored password hash (hex)
        salt_hex: Stored salt (hex)
    
    Returns:
        True if password matches, False otherwise
    """
    try:
        salt = bytes.fromhex(salt_hex)
        stored_hash = password_hash
        computed_hash, _ = hash_password(password, salt)
        return secrets.compare_digest(computed_hash, stored_hash)
    except Exception:
        return False


def load_users_from_env() -> Dict[str, Dict]:
    """
    Load user credentials from environment variables.
    
    Expected format:
    - ADMIN_USERNAME, ADMIN_PASSWORD_HASH, ADMIN_PASSWORD_SALT
    - USER_USERNAME, USER_PASSWORD_HASH, USER_PASSWORD_SALT
    
    Returns:
        Dictionary mapping username -> {password_hash, salt, role}
    """
    users = {}
    
    # Admin user
    admin_username = os.getenv('ADMIN_USERNAME', 'admin')
    admin_hash = os.getenv('ADMIN_PASSWORD_HASH')
    admin_salt = os.getenv('ADMIN_PASSWORD_SALT')
    
    if admin_hash and admin_salt:
        users[admin_username.lower()] = {
            'password_hash': admin_hash,
            'salt': admin_salt,
            'role': 'admin'
        }
    
    # Regular user
    user_username = os.getenv('USER_USERNAME', 'user')
    user_hash = os.getenv('USER_PASSWORD_HASH')
    user_salt = os.getenv('USER_PASSWORD_SALT')
    
    if user_hash and user_salt:
        users[user_username.lower()] = {
            'password_hash': user_hash,
            'salt': user_salt,
            'role': 'user'
        }
    
    # Fallback: if no env vars set, use default (for development only)
    if not users:
        # Default admin: password is "worldtech" (CHANGE IN PRODUCTION!)
        # Using pre-generated hash for consistency
        users['admin'] = {
            'password_hash': '5d816fad376d074d4020e5f1d6e4df6166a06538d388b3374c0b4ca981586972',
            'salt': '9208fa1baae7b5cec949ad844a85a37cf32e5dfaa85569976e2d48feb861d24f',
            'role': 'admin'
        }
        print("⚠️ WARNING: Using default credentials. Set environment variables for production!")
    
    return users


# Load users at module import
USERS = load_users_from_env()


def authenticate_user(username: str, password: str) -> Optional[Dict]:
    """
    Authenticate a user with username and password.
    
    Args:
        username: Username to authenticate
        password: Plain text password
    
    Returns:
        User dict with role if authenticated, None otherwise
    """
    username_lower = username.lower().strip()
    
    # Check if account is locked
    if is_account_locked(username_lower):
        return None
    
    # Get user
    user = USERS.get(username_lower)
    if not user:
        record_failed_attempt(username_lower)
        return None
    
    # Verify password
    if verify_password(password, user['password_hash'], user['salt']):
        # Success - clear failed attempts
        clear_failed_attempts(username_lower)
        return {
            'username': username_lower,
            'role': user['role']
        }
    else:
        # Failed - record attempt
        record_failed_attempt(username_lower)
        return None


def record_failed_attempt(username: str):
    """Record a failed login attempt for a username."""
    username_lower = username.lower().strip()
    
    if username_lower not in _failed_attempts:
        _failed_attempts[username_lower] = {
            'count': 0,
            'lockout_until': None
        }
    
    _failed_attempts[username_lower]['count'] += 1
    
    # Lock account if max attempts reached
    if _failed_attempts[username_lower]['count'] >= MAX_FAILED_ATTEMPTS:
        lockout_until = datetime.now() + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
        _failed_attempts[username_lower]['lockout_until'] = lockout_until


def clear_failed_attempts(username: str):
    """Clear failed attempts for a username (on successful login)."""
    username_lower = username.lower().strip()
    if username_lower in _failed_attempts:
        del _failed_attempts[username_lower]


def is_account_locked(username: str) -> bool:
    """
    Check if an account is currently locked.
    
    Returns:
        True if locked, False otherwise
    """
    username_lower = username.lower().strip()
    
    if username_lower not in _failed_attempts:
        return False
    
    lockout_until = _failed_attempts[username_lower].get('lockout_until')
    if lockout_until is None:
        return False
    
    # Check if lockout has expired
    if datetime.now() >= lockout_until:
        # Lockout expired - clear it
        _failed_attempts[username_lower]['lockout_until'] = None
        _failed_attempts[username_lower]['count'] = 0
        return False
    
    return True


def get_lockout_time_remaining(username: str) -> Optional[int]:
    """
    Get remaining lockout time in seconds.
    
    Returns:
        Seconds remaining, or None if not locked
    """
    username_lower = username.lower().strip()
    
    if username_lower not in _failed_attempts:
        return None
    
    lockout_until = _failed_attempts[username_lower].get('lockout_until')
    if lockout_until is None:
        return None
    
    remaining = (lockout_until - datetime.now()).total_seconds()
    return max(0, int(remaining))


def get_failed_attempts_count(username: str) -> int:
    """Get the number of failed attempts for a username."""
    username_lower = username.lower().strip()
    if username_lower not in _failed_attempts:
        return 0
    return _failed_attempts[username_lower].get('count', 0)


def get_all_failed_attempts() -> Dict[str, Dict]:
    """Get all failed attempts (admin only)."""
    return _failed_attempts.copy()


def is_authorized(user_role: str, required_role: str) -> bool:
    """
    Check if a user role is authorized for an action.
    
    Args:
        user_role: User's role ('admin' or 'user')
        required_role: Required role ('admin' or 'user')
    
    Returns:
        True if authorized, False otherwise
    """
    if required_role == 'admin':
        return user_role == 'admin'
    elif required_role == 'user':
        return user_role in ['admin', 'user']
    return False

