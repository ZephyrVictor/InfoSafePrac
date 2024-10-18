# encoding=utf-8
__author__ = 'Zephyr369'

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from . import web
from app.models.Store import Store
from ..models.Order import Order
from ..models.base import db


@web.route('/apply_store', methods=['POST'])
@jwt_required()
def apply_store():
    """
    申请开店
    """
    '''return '申请开店成功', 200'''
    user_id = get_jwt_identity()
    data = request.get_json()
    store_name = data.get('store_name')
    store_type = data.get('store_type')

    new_store = Store(store_name, store_type, user_id)
    db.session.add(new_store)
    db.session.commit()
    return jsonify({'msg': '店铺申请已提交，等待管理员审核'}), 200


@web.route('/view_earnings', methods=['GET'])
@jwt_required()
def view_earnings():
    """
    商家查看收益
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
