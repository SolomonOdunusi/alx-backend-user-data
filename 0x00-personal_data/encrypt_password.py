#!/usr/bin/env python3
"""Bycrypt encryption Module"""
import bcrypt
import hashlib
import base64


def hash_password(password: str) -> bytes:
    """Encrypts a password using bcrypt and sha256"""
    hashed = bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt())
    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """Checks the validity of a password"""
    return bcrypt.checkpw(hashlib.sha256(
        password.encode()).digest(), hashed_password)
