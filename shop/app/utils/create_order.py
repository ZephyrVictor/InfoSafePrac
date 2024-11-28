# encoding=utf-8
__author__ = 'Zephyr369'

from datetime import datetime
import random
import string

from flask_login import current_user

from app.models.Order import Order
from app.models.base import db


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




def create_order(cart_items):
    """
    创建订单并保存到数据库

    参数:
    - cart_items: List[Dict] - 每个字典包含商品和数量，例如 [{'item': item, 'quantity': 2}]

    返回:
    - Order - 创建的订单对象
    """
    # 确定卖家 (假设每件商品有唯一的卖家)
    if not cart_items:
        raise ValueError("购物车不能为空")

    # 默认取第一个商品的卖家 ID，假设购物车商品来自同一卖家
    seller_id = cart_items[0]['item'].owner_id

    # 计算订单总金额
    total_amount = calculate_total(cart_items)

    # 创建订单
    order = Order(
        order_number=generate_order_number(),
        buyer_id=current_user.UserId,
        seller_id=seller_id,
        store_id=cart_items[0]['item'].ItemId,  # 默认使用第一个商品的ID
        amount=total_amount,
        order_time=datetime.utcnow(),
        details='购买商品'  # 可以扩展为更多详细信息
    )

    # 保存到数据库
    db.session.add(order)
    db.session.commit()

    return order
