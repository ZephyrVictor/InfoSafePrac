# encoding=utf-8
__author__ = 'Zephyr369'

from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Float
from sqlalchemy.orm import relationship
from datetime import datetime

from app.models.base import Base


class Order(Base):

    __tablename__ = 'order'

    OrderId = Column(Integer, primary_key=True)
    order_number = Column(String(50), unique=True, nullable=False)
    buyer_id = Column(Integer, ForeignKey('user.UserId'), nullable=False) # 买家
    seller_id = Column(Integer, ForeignKey('user.UserId'), nullable=False) # 卖家
    store_id = Column(Integer, ForeignKey('store.StoreId'), nullable=False) # 商品
    amount = Column(Float, nullable=False)
    order_time = Column(DateTime, default=datetime.utcnow)
    details = Column(String(255), nullable=False)

    buyer = relationship('User', foreign_keys=[buyer_id], backref='purchases')
    seller = relationship('User', foreign_keys=[seller_id], backref='sales')