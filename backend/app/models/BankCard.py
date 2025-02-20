# app/models/BankCard.py

from sqlalchemy import Column, Integer, String, ForeignKey, Float, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import random

from werkzeug.security import generate_password_hash, check_password_hash

from app.models.base import Base, db
from app.models.BankUser import BankUser


class BankCard(Base):
    __tablename__ = 'bank_card'

    CardId = Column(Integer, primary_key=True)
    card_number = Column(String(19), unique=True, nullable=False)
    # user_id = Column(Integer, ForeignKey('bank_user.UserId'), nullable=False)
    balance = Column(Float, default=0.0)
    is_active = Column(Boolean, default=False)
    _captcha = Column("captcha",String(255), nullable=True)  # 验证码

# TODO: 为 BankCard 添加一个 captcha_expiry 字段，用于保存验证码的过期时间
    user_id = Column(Integer, ForeignKey('bank_user.UserId'), nullable=False)
    user = relationship('BankUser', back_populates='bank_cards')

    def __init__(self, user_id, **kwargs):
        super(BankCard, self).__init__(**kwargs)
        self.user_id = user_id  # 设置 user_id
        if not self.card_number:
            self.card_number = self.generate_card_number()

    @property
    def captcha(self):
        return self._captcha

    @captcha.setter
    def captcha(self, value):
        self._captcha = generate_password_hash(value)

    @staticmethod
    def generate_card_number():
        return ''.join([str(random.randint(0, 9)) for _ in range(19)])

    def set_captcha(self):
        """生成验证码"""
        self.captcha = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        db.session.commit()

    def verify_captcha(self, input_captcha):
        """验证用户输入的验证码"""
        if self._captcha and check_password_hash(self._captcha, input_captcha):
            if datetime.utcnow() <= self.captcha_expiry:
                self.captcha = None
                # self.captcha_expiry = None
                db.session.commit()
                return True
        return False

    def generate_captcha(self, captcha_value, expiry_seconds=60):
        """生成哈希化验证码并设置过期时间"""
        self.captcha = captcha_value  # 触发setter进行哈希化
        self.captcha_expiry = datetime.utcnow() + timedelta(seconds=expiry_seconds)
        db.session.commit()

    def deposit(self, amount):
        if amount > 0:
            self.balance += amount
            db.session.commit()
            return True
        return False

    def withdraw(self, amount):
        if amount > 0 and self.balance >= amount:
            self.balance -= amount
            db.session.commit()
            return True
        return False

    @property
    def masked_card_number(self):
        # 仅显示前4位和后4位，中间使用 * 号替代
        if self.card_number:
            return f"{self.card_number[:4]} **** **** {self.card_number[-4:]}"
        return "未知卡号"

    @property
    def masked_balance(self):
        # 隐藏具体余额，只显示大概范围
        if self.balance is not None:
            return f"¥ {int(self.balance) // 100 * 100} +"
        return "未知余额"
