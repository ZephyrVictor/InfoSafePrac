# app/models/BankCard.py

from sqlalchemy import Column, Integer, String, ForeignKey, Float, Boolean, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
import random

from werkzeug.security import generate_password_hash

from app.models.base import Base, db
from app.models.BankUser import BankUser


class BankCard(Base):
    __tablename__ = 'bank_card'

    CardId = Column(Integer, primary_key=True)
    card_number = Column(String(19), unique=True, nullable=False)
    # user_id = Column(Integer, ForeignKey('bank_user.UserId'), nullable=False)
    balance = Column(Float, default=0.0)
    is_active = Column(Boolean, default=False)
    _captcha = Column("captcha",String(255), nullable=True)


    user_id = Column(Integer, ForeignKey('bank_user.UserId'), nullable=False)
    user = relationship('BankUser', back_populates='bank_cards')

    def __init__(self, **kwargs):
        super(BankCard, self).__init__(**kwargs)
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
