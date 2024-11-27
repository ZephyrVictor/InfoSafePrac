# encoding=utf-8
__author__ = 'Zephyr369'
from sqlalchemy import Column, Integer, ForeignKey
from sqlalchemy.orm import relationship

from app.models.base import Base
class CartItem(Base):
    __tablename__ = 'cart_item'

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey('shop_user.UserId'), nullable=False)
    item_id = Column(Integer, ForeignKey('item.ItemId'), nullable=False)
    quantity = Column(Integer, default=1)

    item = relationship('Item', backref='cart_items')

    def __init__(self, user_id, item_id, quantity=1):
        self.user_id = user_id
        self.item_id = item_id
        self.quantity = quantity
