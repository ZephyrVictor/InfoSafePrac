# app/models/Store.py

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.models.ShopUser import ShopUser


class Store(Base):
    __tablename__ = 'store'

    StoreId = Column(Integer, primary_key=True)
    store_name = Column(String(50), nullable=False)
    store_type = Column(String(50), nullable=False)
    owner_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    is_approved = Column(Boolean, default=False)
    is_open = Column(Boolean, default=False)

    owner = relationship('ShopUser', backref='stores')
    orders = relationship('Order', backref='store', lazy='dynamic')
