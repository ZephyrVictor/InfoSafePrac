# encoding=utf-8
__author__ = 'Zephyr369'
from sqlalchemy import Column, Integer, ForeignKey
from app.models.base import Base
class CartItem(Base):
    __tablename__ = 'cart_item'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    item_id = Column(Integer, ForeignKey('item.ItemId'), nullable=False)
    quantity = Column(Integer, default=1)