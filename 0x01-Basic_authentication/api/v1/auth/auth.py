#!/usr/bin/env python3
""" Module of Auth class"""

from flask import request
from typing import List, TypeVar
import re


class Auth:
    """Auth class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require auth"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        path = path.rstrip('/') + '/'
        for p in excluded_paths:
            p = p.rstrip('/') + '/'
            rp = re.escape(p).replace('\\*', '.*')
            if re.match(rp, path):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Authorization header"""
        if request is None or 'Authorization' not in request.headers:
            return None
        return request.headers['Authorization']

    def current_user(self, request=None) -> TypeVar('User'):
        """Current user"""
        return None
