#!/usr/bin/env python3
"""This module contains the Auth class"""


from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
from uuid import uuid4
from typing import Union
import bcrypt


def _hash_password(password: str) -> str:
    """This method should take a string and return a salted, hashed password"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def _generate_uuid() -> str:
    """It generates a new UUID and returns it as a string"""
    return str(uuid4())


class Auth:
    """Autheniction class to handle all the auth tasks
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Register mandatory email and password and
        return a User object
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f'User {email} already exists')
        except NoResultFound:
            user = self._db.add_user(email, _hash_password(password))
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """The method should take self, email and password
            arguments, and return a boolean.
        """
        try:
            user = self._db.find_user_by(email=email)
            return bcrypt.checkpw(password.encode(
                    'utf-8'), user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """Create a new session for the user and
        return the session ID
        """
        try:
            user = self._db.find_user_by(email=email)
            sessionID = _generate_uuid()
            self._db.update_user(user.id, session_id=sessionID)
            return sessionID
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
        """ Method to find user by session ID and return
        User or None if the session ID is None or not user is found
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
            return user
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """Destroys the session by updating
        the user's session ID to None"""
        if user_id is None:
            return None
        try:
            user = self._db.find_user_by(id=user_id)
            self._db.update_user(user.id, session_id=None)
        except NoResultFound:
            return None

    def get_reset_password_token(self, email: str) -> str:
        """Method to get the reset password token and return it
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            raise ValueError
        token_ = _generate_uuid()
        self._db.update_user(user.id, reset_token=token_)
        return token_

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates the password using the reset token
        """
        if reset_token is None or password is None:
            return None
        try:
            user_session = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError
        hashed_password = _hash_password(password)
        self._db.update_user(user_session.id,
                             hashed_password=hashed_password,
                             reset_token=None)
