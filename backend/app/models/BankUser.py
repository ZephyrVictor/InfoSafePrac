# app/models/BankUser.py

# encoding=utf-8
__author__ = 'Zephyr369'

# import datetime
import random
from datetime import datetime, timedelta
import jwt
from flask import current_app
from flask_jwt_extended import create_access_token, decode_token
from sqlalchemy import Column, Integer, String, Boolean, DateTime
from werkzeug.security import generate_password_hash, check_password_hash

from app import logger, login_manager
from app.models.base import Base, db


# TODO: 将BankUser继承于AbstractUser
class BankUser(Base):
    __tablename__ = 'bank_user'

    UserId = Column(Integer, primary_key=True)  # 用户ID
    nickname = Column(String(24), nullable=False)
    email = Column(String(50), unique=True, nullable=False)
    _password = Column('password', String(255), nullable=False)
    isExamined = Column(Boolean, default=False)  # 是否经过审核
    _payPassword = Column('pay_password', String(255), nullable=False)  # 支付密码
    isAdmin = Column(Boolean, default=False)  # 是否为管理员
    IdCardNumber = Column(String(18), nullable=True)  # 身份证号
    _captcha = Column("captcha", String(255), nullable=True)  # 验证码
    captcha_expiry = Column(DateTime, nullable=True)  # 验证码过期时间
    bank_cards = db.relationship('BankCard', back_populates='user', lazy='dynamic')

    @property
    def captcha(self):
        return self._captcha

    @captcha.setter
    def captcha(self, raw):
        if raw:
            self._captcha = generate_password_hash(raw)
        else:
            self._captcha = None

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

    def verify_payPassword(self, raw):
        return check_password_hash(self._payPassword, raw)

    def verify_password(self, raw):
        return check_password_hash(self._password, raw)

    def set_captcha(self):
        """生成验证码"""
        self.captcha = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        db.session.commit()

    def verify_captcha(self, input_captcha):
        """验证用户输入的验证码"""
        if self._captcha and check_password_hash(self._captcha, input_captcha):
            if datetime.utcnow() <= self.captcha_expiry:
                self.captcha = None
                self.captcha_expiry = None
                db.session.commit()
                return True
        return False

    def generate_captcha(self, captcha_value, expiry_seconds=60):
        """生成哈希化验证码并设置过期时间"""
        self.captcha = captcha_value  # 触发setter进行哈希化
        self.captcha_expiry = datetime.utcnow() + timedelta(seconds=expiry_seconds)
        db.session.commit()

    @staticmethod
    def reset_password(user_id, new_password):
        try:
            user = BankUser.query.get(user_id)
            user.password = new_password
            db.session.commit()
            return True
        except Exception as e:
            logger.error(f"重置密码失败: {e}")
            return False

    @staticmethod
    def generate_jwt(user, remember=False):
        expires = timedelta(days=7) if remember else timedelta(days=1)
        print(f"Generating JWT for user_id: {user.UserId}")  # 打印user_id
        return create_access_token(
            identity=user.UserId,
            expires_delta=expires,
            additional_claims={'user_type': 'bank'}  # 银行用户
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
            return BankUser.query.get(user_id)
        except Exception as e:
            logger.error(f'JWT解析失败: {e}')
            return None

    def get_id(self):
        return str(self.UserId)

    def get_name(self):
        return self.nickname

    @login_manager.user_loader
    def load_user(user_id):
        """
        Flask-Login 使用的用户加载回调函数。
        根据用户 ID 从数据库加载用户。
        """
        return BankUser.query.get(int(user_id))
