# encoding=utf-8
__author__ = 'Zephyr369'

from app.models.base import Base, db
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
from datetime import datetime, timedelta


class OAuthToken(Base):
    __tablename__ = 'oauth_token'

    id = Column(Integer, primary_key=True)
    client_id = Column(String(64), ForeignKey('oauth_client.client_id'))
    user_id = Column(Integer, ForeignKey('bank_user.UserId'))
    access_token = Column(String(256), unique=True, nullable=False)
    refresh_token = Column(String(256), unique=True, nullable=True)
    expires = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(hours=1))
    scopes = Column(String(256), nullable=True)
    revoked = Column(Boolean, default=False)

    def __init__(self, client_id, user_id, access_token, expires=None, scopes=None):
        self.client_id = client_id
        self.user_id = user_id
        self.access_token = access_token
        self.expires = expires if expires else datetime.utcnow() + timedelta(hours=1)
        self.scopes = scopes
