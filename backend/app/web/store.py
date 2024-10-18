# encoding=utf-8
__author__ = 'Zephyr369'

from flask import request, jsonify, Blueprint
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt

from app.models.Store import Store
from ..models.Order import Order
from ..models.base import db

store_bp = Blueprint('store', __name__)

def shop_user_required(fn):
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        if claims.get('user_type') != 'shop':
            return jsonify({'msg': '需要外卖平台用户身份'}), 403
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@store_bp.route('/apply_store', methods=['POST'])
@jwt_required()
@shop_user_required
def apply_store():
    """
    申请开店
    ---
    tags:
      - Store
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - store_name
            - store_type
          properties:
            store_name:
              type: string
              description: 店铺名称
              example: 我的餐馆
            store_type:
              type: string
              description: 店铺类型
              example: 中餐
    responses:
      200:
        description: 店铺申请已提交，等待管理员审核
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 店铺申请已提交，等待管理员审核
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    store_name = data.get('store_name')
    store_type = data.get('store_type')

    new_store = Store(store_name=store_name, store_type=store_type, owner_id=user_id)
    db.session.add(new_store)
    db.session.commit()
    return jsonify({'msg': '店铺申请已提交，等待管理员审核'}), 200


@store_bp.route('/view_earnings', methods=['GET'])
@jwt_required()
@shop_user_required
def view_earnings():
    """
    商家查看收益
    ---
    tags:
      - Store
    security:
      - Bearer: []
    responses:
      200:
        description: 成功返回收益信息
        schema:
          type: object
          properties:
            total_earnings:
              type: number
              format: float
              example: 1000.50
            orders:
              type: array
              items:
                type: object
                properties:
                  order_number:
                    type: string
                    example: ORD123456
                  amount:
                    type: number
                    format: float
                    example: 100.25
                  order_time:
                    type: string
                    example: "2023-10-18 12:34:56"
                  buyer_id:
                    type: integer
                    example: 2
                  details:
                    type: string
                    example: "购买了2份炒饭"
      404:
        description: 没有已开业的店铺
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 您没有已开业的店铺
    """
    user_id = get_jwt_identity()

    stores = Store.query.filter_by(owner_id=user_id, is_open=True).all()
    if not stores:
        return jsonify({'msg': '您没有已开业的店铺'}), 404

    total_earnings = 0.0
    orders_list = []
    for store in stores:
        orders = Order.query.filter_by(store_id=store.StoreId).all()
        for order in orders:
            total_earnings += order.amount
            orders_list.append({
                'order_number': order.order_number,
                'amount': order.amount,
                'order_time': order.order_time.strftime('%Y-%m-%d %H:%M:%S'),
                'buyer_id': order.buyer_id,
                'details': order.details
            })

    return jsonify({'total_earnings': total_earnings, 'orders': orders_list}), 200
