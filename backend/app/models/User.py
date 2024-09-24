# encoding=utf-8
__author__ = 'Zephyr369'

import datetime
from datetime import timedelta

import jwt
from flask import current_app
from flask_jwt_extended import create_access_token, decode_token
from flask_login import UserMixin
from itsdangerous import Serializer
from sqlalchemy import Column, Integer, String, Boolean, Float
from werkzeug.security import generate_password_hash, check_password_hash

from app import login_manager, logger
from app.models.base import Base, db


class User(UserMixin, Base):
    UserId = Column(Integer, primary_key=True)  # 用户id
    nickname = Column(String(24), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    _password = Column(String(255), nullable=False)  # hashed_password
    isExamined = Column(Boolean, default=False)  # 只有经过审核的人才可以申请银行卡
    _payPassword = Column(String(255), nullable=False)  # 用户支付密码
    isAdmin = Column(Boolean, default=False)
    IdCardNumber = Column(String(18), nullable=True)  # 用户的身份证号，用来模拟实名认证，用户只有在提交了身份证号之后管理员才能够审核。
    # 用户登录密码
    @property
    def password(self):
        return self._password

    @password.setter
    def password(self, raw):
        self._password = generate_password_hash(raw)

    @property
    def payPassword(self):
        return self._payPassword

    @payPassword.setter
    def payPassword(self, raw):
        self._payPassword = generate_password_hash(raw)

    # 验证支付密码
    def verify_payPassword(self, raw):
        return check_password_hash(self._payPassword, raw)

    # 验证登录密码
    def verify_password(self, raw):
        return check_password_hash(self._password, raw)

    # 这个装饰器修饰的方法可以直接类名.方法调用 不用实例化
    @staticmethod
    def reset_password(user_id, new_password):
        try:
            user = User.query.get(user_id)  # 获取用户对象
            # 直接修改密码
            user.password = new_password
            db.session.commit()  # 提交更改
            return True
        except Exception as e:
            logger.error(f"重置密码失败: {e}")
            return False

    @staticmethod
    def generate_jwt(user, remember=False):
        # 过期时间
        expires = timedelta(days=7) if remember else timedelta(days=1)
        return create_access_token(identity=user.UserId, expires_delta=expires)

    # 用于重置邮件
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
            return User.query.get(user_id)
        except:
            logger.error('JWT解析失败')


# 请在app/models/User.py中补充完整代码
@login_manager.user_loader
def get_user(uid):
    return User.query.get(int(uid))
