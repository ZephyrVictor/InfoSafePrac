# encoding=utf-8
__author__ = 'Zephyr369'

from sqlalchemy import Column, String, Integer, Text, Float, DateTime

from app.models.base import Base


class PaymentCache(Base):
    __tablename__ = 'payment_cache'

    payment_id = Column(String(255), primary_key=True)
    buyer_bank_user_id = Column(Integer, nullable=False)
    seller_payments = Column(Text, nullable=False)  # 存储为 JSON
    total_amount = Column(Float, nullable=False)
    order_ids = Column(Text, nullable=False)  # 存储为 JSON
    expires_at = Column(DateTime, nullable=False)

    def __init__(self, payment_id, buyer_bank_user_id, seller_payments, total_amount, order_ids, expires_at):
        self.payment_id = payment_id
        self.buyer_bank_user_id = buyer_bank_user_id
        self.seller_payments = seller_payments
        self.total_amount = total_amount
        self.order_ids = order_ids
        self.expires_at = expires_at

    def to_dict(self):
        return {
            "payment_id": self.payment_id,
            "buyer_bank_user_id": self.buyer_bank_user_id,
            "seller_payments": self.seller_payments,
            "total_amount": self.total_amount,
            "order_ids": self.order_ids,
            "expires_at": self.expires_at
        }