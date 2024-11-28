# encoding=utf-8
__author__ = 'Zephyr369'

from datetime import datetime

from sqlalchemy import Integer, Column, ForeignKey, String, Float, DateTime
from sqlalchemy.orm import relationship

from app.models.base import Base


# 转账记录
class Transaction(Base):
    __tablename__ = 'transactions'

    id = Column(Integer, primary_key=True)
    sender_id = Column(Integer, ForeignKey('bank_user.UserId'))
    recipient_id = Column(Integer, ForeignKey('bank_user.UserId'))
    amount = Column(Float, nullable=False)
    transaction_type = Column(String(50), nullable=False)  # 'TRANSFER' 或 'PAYMENT'
    status = Column(String(50), nullable=False)  # 'SUCCESS' 或 'FAILED'
    timestamp = Column(DateTime, default=datetime.utcnow)

    sender = relationship('BankUser', foreign_keys=[sender_id], backref='sent_transactions')
    recipient = relationship('BankUser', foreign_keys=[recipient_id], backref='received_transactions')

    def __init__(self, sender_id, recipient_id, amount, transaction_type='TRANSFER', status='SUCCESS'):
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.amount = amount
        self.transaction_type = transaction_type
        self.status = status
