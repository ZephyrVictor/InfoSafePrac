# encoding=utf-8
__author__ = 'Zephyr369'

from app.models.base import Base, db
from sqlalchemy import Column, Integer, String, Boolean


class OAuthClient(Base):
    __tablename__ = 'oauth_client'

    client_id = Column(String(64), primary_key=True)
    client_secret = Column(String(64), nullable=False)
    redirect_uris = Column(String(256), nullable=False)  # 逗号分隔的 URI 列表
    is_confidential = Column(Boolean, default=True)  # 是否为机密客户端
    client_name = Column(String(255), nullable=False) # 客户端名称

    def check_redirect_uri(self, redirect_uri):
        return redirect_uri in self.redirect_uris.split(',')

    def __init__(self, client_id, client_secret, client_name, redirect_uris):
        self.client_id = client_id
        self.client_secret = client_secret
        self.client_name = client_name
        self.redirect_uris = ','.join(redirect_uris)
