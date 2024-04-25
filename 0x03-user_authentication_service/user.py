#!/usr/bin/env python3
"""This module contains the User class"""
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, Column, String

Base = declarative_base()


class User(Base):
    """Create a User class that inherits from Base
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250))
    reset_token = Column(String(250))


print(User.__tablename__)

for column in User.__table__.columns:
    print("{}: {}".format(column, column.type))
