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

    def generate_order_number():
        """生成唯一的订单号"""
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')  # 时间戳部分
        random_suffix = ''.join(random.choices(string.digits, k=6))  # 随机6位数字
        return f"{timestamp}{random_suffix}"

    def calculate_total(cart_items):
        """
        计算购物车中所有商品的总金额

        参数:
        - cart_items: List[Dict] - 每个字典包含商品和数量，例如 [{'item': item, 'quantity': 2}]

        返回:
        - float - 总金额
        """
        total = sum(item['item'].price * item['quantity'] for item in cart_items)
        return total
