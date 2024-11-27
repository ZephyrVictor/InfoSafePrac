# app/models/Order.py

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Float
from sqlalchemy.orm import relationship
from datetime import datetime

from app.models.base import Base
from app.models.ShopUser import ShopUser
import random
import string
from datetime import datetime

class Order(Base):
    __tablename__ = 'order'

    OrderId = Column(Integer, primary_key=True)
    order_number = Column(String(50), unique=True, nullable=False)
    buyer_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    seller_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    store_id = Column(Integer, ForeignKey('item.ItemId'), nullable=False)
    amount = Column(Float, nullable=False)
    order_time = Column(DateTime, default=datetime.utcnow)
    details = Column(String(255), nullable=False)

    buyer = relationship('ShopUser', foreign_keys=[buyer_id], backref='purchases')
    seller = relationship('ShopUser', foreign_keys=[seller_id], backref='sales')

    def __init__(self, order_number, buyer_id, amount, details, order_time, seller_id=None, store_id=None):
        self.order_number = order_number
        self.buyer_id = buyer_id
        self.amount = amount
        self.details = details
        self.seller_id = seller_id
        self.store_id = store_id
        self.order_time = order_time


