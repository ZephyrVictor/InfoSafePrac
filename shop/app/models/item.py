# app/models/shop.py

from sqlalchemy import Column, Integer, String, ForeignKey, Boolean, Float
from sqlalchemy.orm import relationship

from app.models.base import Base
from app.models.ShopUser import ShopUser


class Item(Base):
    __tablename__ = 'item'

    ItemId = Column(Integer, primary_key=True)
    Item_name = Column(String(50), nullable=False)
    Item_type = Column(String(50), nullable=False)
    is_approved = Column(Boolean, default=False)
    is_open = Column(Boolean, default=False)
    description = Column(String(256), nullable=False)
    image_path = Column(String(256), nullable=False)
    price = Column(Float, nullable=False)  # 新增价格字段

    owner_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)  # 关联到 ShopUser
    owner = relationship('ShopUser', back_populates='items')  # 修正为对应 `ShopUser` 的 `items`
    orders = relationship('Order', backref='store', lazy='dynamic')
