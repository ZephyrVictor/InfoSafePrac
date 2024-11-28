# encoding=utf-8
__author__ = 'Zephyr369'

import datetime
import glob
import os
from uuid import uuid4

import requests
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
from ..models.ShopUser import ShopUser
from ..models.base import db
from ..utils.create_order import generate_order_number, calculate_total
from ..utils.save_images import save_image

shop_bp = Blueprint('shop', __name__)


@shop_bp.route('/')
def index():
    items = Item.query.all()
    return render_template('shop_index.html', items=items)


@shop_bp.route('/item/<int:item_id>', endpoint='view_item')
def view_item(item_id):
    item = Item.query.filter_by(ItemId=item_id).first()

    if not item:
        flash('商品不存在', 'error')
        return redirect(url_for('shop.index'))

    cart_items = CartItem.query.options(joinedload(CartItem.item)).filter_by(user_id=current_user.UserId).all()

    return render_template('shop/view_item.html', item=item)


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

    # 获取卖家银行用户ID
    seller_id = cart_items[0].item.owner_id
    seller = ShopUser.query.get(seller_id)
    bank_user_id = seller.bank_user_id  # 获取卖家的 bank_user_id

    if not bank_user_id:
        flash('商家没有绑定银行账户', 'error')
        return redirect(url_for('web.shop.cart'))

    # 跳转到银行支付页面
    return redirect(url_for('web.bank.pay', order_id=order.OrderId, bank_user_id=bank_user_id))


# 支付订单
@shop_bp.route('/order/<int:order_id>/pay', methods=['GET', 'POST'])
@login_required
def pay_order(order_id):
    order = Order.query.get_or_404(order_id)
    if order.buyer_id != current_user.UserId:
        abort(403)

    if request.method == 'POST':
        buyer_id = order.buyer_id
        seller_id = order.seller_id
        amount = order.amount
        order_id = order.OrderId

        bank_url = 'http://127.0.0.1:5000/web/bank/pay'
        data = {
            'order_id': order_id,
            'buyer_id': buyer_id,
            'seller_id': seller_id,
            'amount': amount
        }

        response = requests.post(bank_url, data=data)

        if response.status_code == 200:
            flash('支付成功', 'success')
            return redirect(url_for('web.shop.order_detail', order_id=order.OrderId))
        else:
            flash('支付失败', 'error')
            return redirect(url_for('web.shop.cart'))

    return render_template('shop/pay_order.html', order=order)


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


@shop_bp.route('/select_bank_card', methods=['GET', 'POST'])
def select_bank_card():
    bank_cards = session.get('bank_cards', [])
    bank_user_id = session.get('bank_user_id')

    if not bank_cards:
        flash("未找到可用的银行卡", 'error')
        return redirect(url_for('web.shop.profile'))

    if request.method == 'POST':
        selected_card_id = request.form.get('card_id')
        if not selected_card_id:
            flash("请选择一张银行卡", 'error')
            return redirect(url_for('web.shop.select_bank_card'))

        selected_card = next(
            (card for card in bank_cards if str(card['card_id']) == selected_card_id), None
        )
        if not selected_card:
            flash("无效的银行卡选择", 'error')
            return redirect(url_for('web.shop.select_bank_card'))

        # 绑定银行卡
        current_user.bank_user_id = bank_user_id
        current_user.bank_card_number = selected_card['card_number']
        db.session.commit()

        flash("银行卡绑定成功", 'success')
        return redirect(url_for('web.shop.profile'))

    return render_template('shop/select_bank_card.html', bank_cards=bank_cards)
