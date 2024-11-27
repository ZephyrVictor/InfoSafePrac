# encoding=utf-8
__author__ = 'Zephyr369'
from app.models.base import Base, db
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime
from datetime import datetime, timedelta

class OAuthGrant(Base):
    __tablename__ = 'oauth_grant'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('bank_user.UserId'))
    client_id = Column(String(64), ForeignKey('oauth_client.client_id'))
    code = Column(String(256), index=True, nullable=False)
    redirect_uri = Column(String(256), nullable=False)
    expires = Column(DateTime, default=lambda: datetime.utcnow() + timedelta(minutes=10))
    scopes = Column(String(256), nullable=True)

    def __init__(self, user_id, client_id, code, redirect_uri, scopes, expires=None):
        self.user_id = user_id
        self.client_id = client_id
        self.code = code
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.expires = expires if expires else datetime.utcnow()