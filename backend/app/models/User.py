# encoding=utf-8
__author__ = 'Zephyr369'

from flask import current_app
from flask_login import UserMixin
from itsdangerous import Serializer
from sqlalchemy import Column, Integer, String, Boolean, Float
from werkzeug.security import generate_password_hash, check_password_hash

from app import login_manager
from app.models.base import Base, db


class User(UserMixin,Base):
    UserId = Column(Integer, primary_key=True) # 用户id
    nickname = Column(String(24),nullable=False)
    email = Column(String(50),unique = True, nullable = False)
    _password = Column(String(255),nullable=False) # hashed_password
    is_examined = Column(Boolean, default=False) # 只有经过审核的人才可以申请银行卡
    _payPassword = Column(String(255),nullable=False) # 用户支付密码
    # 用户登录密码
    @property
    def password(self):
        return self._password

    @password.setter
    def password(self,raw):
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
    def reset_password(token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token.encode('utf8'))
        except:
            return False
        uid = data.get('UserId')
        with db.auto_commit():
            user = User.query.get(uid)
            user.password = new_password
        return True

@login_manager.user_loader
def get_user(uid):
    return User.query.get(int(uid))


class Admin(UserMixin,Base):
    adminID = Column(Integer, primary_key=True)
    _adminPassword = Column(String(255),nullable= False)
    adminNickName = Column(String(255),nullable=False)


    @property
    def adminPassword(self):
        return self._adminPassword

    @adminPassword.setter
    def adminPassword(self,raw):
        self._adminPassword = generate_password_hash(raw)

    def verify_adminPassword(self,raw):
        return check_password_hash(self._adminPasswordm,raw)

