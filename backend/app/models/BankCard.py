# encoding=utf-8
__author__ = 'Zephyr369'

import random
from datetime import datetime, timedelta

from sqlalchemy import Column, Integer, ForeignKey, String, Float, Boolean, DateTime
from sqlalchemy.orm import relationship

from app.models.base import Base, db


class BankCard(Base):
    __tablename__ = 'bank_card'

    CardId = Column(Integer, primary_key=True)
    card_number = Column(String(19), unique=True, nullable=False) # 中国的银行卡号都是19位
    user_id = Column(Integer, ForeignKey('user.UserId'), nullable=False)
    balance = Column(Float, default=0.0)
    is_active = Column(Boolean, default=False)
    captcha = Column(String(6), nullable=True)
    captcha_expiry = Column(DateTime, nullable=True)

    user = relationship('User', backref='bank_cards')

    def __init__(self, **kwargs):
        super(BankCard, self).__init__(**kwargs)
        if not self.card_number:
            self.card_number = self.generate_card_number()

    # 生成银行卡号
    @staticmethod
    def generate_card_number():
        return ''.join([str(random.randint(0, 9)) for _ in range(19)])

    def set_captcha(self):
        self.captcha = ''.join([str(random.randint(0, 9)) for _ in range(6)])
        self.captcha_expiry = datetime.utcnow() + timedelta(minutes=10)
        db.session.commit()

    def verify_captcha(self, input_captcha):
        if self.captcha == input_captcha and datetime.utcnow() <= self.captcha_expiry:
            self.captcha = None
            self.captcha_expiry = None
            db.session.commit()
            return True
        return False

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