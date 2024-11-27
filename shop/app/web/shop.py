# encoding=utf-8
__author__ = 'Zephyr369'

import datetime
import glob
import os

from flask import request, jsonify, Blueprint, render_template, current_app, url_for, session, flash
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
from flask_login import login_required, current_user
from requests_oauthlib import OAuth2Session
from sqlalchemy.orm import joinedload
from werkzeug.exceptions import abort
from werkzeug.utils import redirect

from app.models.item import Item
from ..models.CarItem import CartItem
from ..models.Order import Order
from ..models.base import db
from ..utils.create_order import generate_order_number, calculate_total
from ..utils.save_images import save_image

shop_bp = Blueprint('shop', __name__)


@shop_bp.route('/')
def index():
    # 查询数据库中的所有商品
    items = Item.query.all()

    # 渲染主界面，无论是否登录，数据来源一致
    return render_template('shop_index.html', items=items)


@shop_bp.route('/item/<int:item_id>', endpoint='view_item')
def view_item(item_id):
    cart_items = CartItem.query.options(joinedload(CartItem.item)).filter_by(user_id=current_user.UserId).all()
    return render_template('shop/view_cart.html', cart_items=cart_items)


@shop_bp.route('/upload_item', methods=['GET', 'POST'])
@login_required
def upload_item():
    if request.method == 'POST':
        item_name = request.form.get('item_name')
        item_type = request.form.get('item_type')
        price = request.form.get('price')
        description = request.form.get('description')
        image = request.files.get('image')

        if not all([item_name, item_type, price, description, image]):
            flash('所有字段都是必需的', 'error')
            return redirect(url_for('web.shop.upload_item'))

        # 保存图片并获取存储路径
        image_path = save_image(image, current_user.UserId)

        # 创建商品记录
        item = Item(
            Item_name=item_name,
            Item_type=item_type,
            price=float(price),
            description=description,
            image_path=image_path,
            owner_id=current_user.UserId
        )
        db.session.add(item)
        db.session.commit()

        flash('商品上传成功', 'success')
        return redirect(url_for('web.shop.index'))

    return render_template('shop/upload_item.html')


@shop_bp.route('/cart')
@login_required
def cart():
    cart_items = CartItem.query.filter_by(user_id=current_user.UserId).all()
    return render_template('shop/cart.html', cart_items=cart_items)


@shop_bp.route('/add_to_cart/<int:item_id>', methods=['POST'])
@login_required
def add_to_cart(item_id):
    cart_item = CartItem.query.filter_by(user_id=current_user.UserId, item_id=item_id).first()
    if cart_item:
        cart_item.quantity += 1
    else:
        cart_item = CartItem(user_id=current_user.UserId, item_id=item_id, quantity=1)
        db.session.add(cart_item)
    db.session.commit()
    flash('已加入购物车', 'success')
    return redirect(url_for('web.shop.cart'))


@shop_bp.route('/checkout', methods=['POST'])
@login_required
def checkout():
    cart_items = CartItem.query.filter_by(user_id=current_user.UserId).all()
    if not cart_items:
        flash('购物车为空', 'error')
        return redirect(url_for('web.shop.cart'))

    # 创建订单
    order = Order(
        order_number=generate_order_number(),
        buyer_id=current_user.UserId,
        amount=calculate_total(cart_items),
        order_time=datetime.utcnow(),
        details='购买商品'
    )
    db.session.add(order)
    db.session.commit()

    # 清空购物车
    for item in cart_items:
        db.session.delete(item)
    db.session.commit()

    # 跳转到支付页面
    return redirect(url_for('web.shop.pay_order', order_id=order.OrderId))


@shop_bp.route('/order/<int:order_id>/pay')
@login_required
def pay_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.buyer_id != current_user.UserId:
        abort(403)

    # 跳转到银行支付页面
    return redirect(url_for('web.bank.pay', order_id=order.OrderId))


@shop_bp.route('/upload_item_image', methods=['POST'])
@login_required
def upload_item_image():
    image = request.files.get('image')
    if not image:
        return jsonify({'error': 'No image uploaded'}), 400

    try:
        image_path = save_image(image, current_user.UserId)
        return jsonify({'message': 'Image uploaded successfully', 'image_path': image_path}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to upload image: {e}'}), 500


@shop_bp.route('/profile')
@login_required
def profile():
    """
    用户个人信息页面，展示用户基本信息和银行账户绑定状态。
    """
    bank_user_id = current_user.bank_user_id
    bank_user_info = None
    # TODO: 完善二者的对接关系
    if bank_user_id:
        # 用户已绑定银行账户，可以通过银行API获取更多信息
        # 这里假设有一个函数 get_bank_user_info 用于获取银行用户信息
        # bank_user_info = get_bank_user_info(bank_user_id)
        bank_user_info = {'user_id': bank_user_id}  # 示例数据
    else:
        # 用户未绑定银行账户
        bank_user_info = None

    return render_template(
        'shop/profile.html',
        user=current_user,
        bank_user_info=bank_user_info
    )
