# encoding=utf-8
__author__ = 'Zephyr369'

import datetime
from datetime import timedelta
import random

import jwt
from flask import current_app
from flask_jwt_extended import create_access_token, decode_token
from flask_login import UserMixin
from itsdangerous import Serializer
from sqlalchemy import Column, Integer, String, Boolean, Float, UniqueConstraint
from werkzeug.security import generate_password_hash, check_password_hash

from app import login_manager, logger
from app.models.base import Base, db


class User(UserMixin, Base):
    UserId = Column(Integer, primary_key=True)  # 用户id
    nickname = Column(String(24), nullable=False)
    email = Column(String(50), nullable=False)
    _password = Column(String(255), nullable=False)  # hashed_password
    isExamined = Column(Boolean, default=False)  # 只有经过审核的人才可以申请银行卡
    _payPassword = Column(String(255), nullable=False)  # 用户支付密码
    isAdmin = Column(Boolean, default=False)
    IdCardNumber = Column(String(18), nullable=True)  # 用户的身份证号，用来模拟实名认证，用户只有在提交了身份证号之后管理员才能够审核。
    captcha = Column(String(6), nullable=True)  # 用户的验证码

    # 用户的银行卡和用户的商店
    user_type = Column(String(20), nullable = False, default='bank')  # 用户类型：'bank'（银行用户）、'shop'（外卖平台用户）、'both'（两者都是）
    bank_user_id = Column(Integer, nullable=True)  # 关联的银行用户ID
    # 联合索引的约束 保证了email和user_type的组合是唯一的
    __table_args__ = (
        UniqueConstraint('email', 'user_type', name='_email_user_type_uc'),
    )

    # 关联关系
    bank_cards = db.relationship('BankCard', backref='user', lazy='dynamic')
    stores = db.relationship('Store', backref='owner', lazy='dynamic')

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
        except Exception as e:
            logger.error(f'JWT解析失败: {e}')
            return None

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

    def is_bank_user(self):
        return self.user_type in ['bank', 'both']

    def is_shop_user(self):
        return self.user_type in ['shop', 'both']


# 请在app/models/User.py中补充完整代码
@login_manager.user_loader
def get_user(uid):
    return User.query.get(int(uid))
