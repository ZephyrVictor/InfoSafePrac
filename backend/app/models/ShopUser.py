# app/models/ShopUser.py

# encoding=utf-8
__author__ = 'Zephyr369'

import datetime
import random
from datetime import timedelta

import jwt
from flask import current_app
from flask_jwt_extended import create_access_token, decode_token
from flask_login import UserMixin
from sqlalchemy import Column, Integer, String, Boolean
from werkzeug.security import generate_password_hash, check_password_hash

from app import login_manager, logger
from app.models.base import Base, db


class ShopUser(UserMixin, Base):
    __tablename__ = 'shop_user'

    UserId = Column(Integer, primary_key=True)  # 用户ID
    nickname = Column(String(24), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    _password = Column('password', String(255), nullable=False)
    isAdmin = Column(Boolean, default=False)  # 是否为管理员
    captcha = Column(String(6), nullable=True)  # 验证码
    bank_user_id = Column(Integer, nullable=True)  # 关联的银行用户ID

    stores = db.relationship('Store', backref='owner', lazy='dynamic')

    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, raw):
        self._password = generate_password_hash(raw)

    def verify_password(self, raw):
        return check_password_hash(self._password, raw)

    def set_captcha(self):
        """生成验证码"""
        self.captcha = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        db.session.commit()

    def verify_captcha(self, input_captcha):
        """验证验证码"""
        if self.captcha == input_captcha:
            self.captcha = None
            db.session.commit()
            return True
        return False

    @staticmethod
    def reset_password(user_id, new_password):
        try:
            user = ShopUser.query.get(user_id)
            user.password = new_password
            db.session.commit()
            return True
        except Exception as e:
            logger.error(f"重置密码失败: {e}")
            return False

    @staticmethod
    def generate_jwt(user, remember=False):
        expires = timedelta(days=7) if remember else timedelta(days=1)
        return create_access_token(
            identity=user.UserId,
            expires_delta=expires,
            additional_claims={'user_type': 'shop'} # 在jwt中存一个用户类型
        )

    def generate_token(self, expiration=600):
        secret_key = current_app.config['SECRET_KEY']
        payload = {
            'UserId': self.UserId,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expiration)
        }
        token = jwt.encode(payload, secret_key, algorithm='HS256')
        return token

    @staticmethod
    def get_user_from_jwt(token):
        try:
            decoded_token = decode_token(token)
            user_id = decoded_token['identity']
            return ShopUser.query.get(user_id)
        except Exception as e:
            logger.error(f'JWT解析失败: {e}')
            return None


@login_manager.user_loader
def load_user(user_id):
    return ShopUser.query.get(int(user_id))
