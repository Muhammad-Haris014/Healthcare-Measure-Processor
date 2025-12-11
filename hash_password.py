"""
Password Hashing Utility

Run this script to generate password hashes for your users.

Usage:
    python hash_password.py

This will prompt you for a password and output the hash and salt
to use in your environment variables or config file.
"""

from auth_config import hash_password

if __name__ == "__main__":
    print("=" * 60)
    print("Password Hash Generator")
    print("=" * 60)
    print()
    
    password = input("Enter password to hash: ")
    if not password:
        print("❌ Password cannot be empty!")
        exit(1)
    
    password_hash, salt = hash_password(password)
    
    print()
    print("=" * 60)
    print("Generated Credentials (add to environment variables):")
    print("=" * 60)
    print()
    print(f"PASSWORD_HASH={password_hash}")
    print(f"PASSWORD_SALT={salt}")
    print()
    print("=" * 60)
    print("Example .env file entry:")
    print("=" * 60)
    print(f"ADMIN_PASSWORD_HASH={password_hash}")
    print(f"ADMIN_PASSWORD_SALT={salt}")
    print()
    print("⚠️  Keep these values secure and never commit them to version control!")
    print()

