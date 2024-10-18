# encoding=utf-8
__author__ = 'Zephyr369'

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt

from . import web
from ..libs.email import send_mail
from ..models.BankUser import BankUser
from ..models.ShopUser import ShopUser
from ..models.User import User
from ..models.base import db


@web.route('/bind_bank_user', methods=['POST'])
@jwt_required()
def bind_bank_user():
    verify_jwt_in_request()
    claims = get_jwt()
    if claims.get('user_type') != 'shop':
        return jsonify({'msg': '需要外卖平台用户身份'}), 403

    user_id = get_jwt_identity()
    data = request.get_json()
    bank_user_email = data.get('bank_user_email')

    shop_user = ShopUser.query.get(user_id)

    # 查找银行用户
    bank_user = BankUser.query.filter_by(email=bank_user_email).first()
    if not bank_user:
        return jsonify({'msg': '银行用户不存在'}), 404

    # 发送验证码到银行用户邮箱
    bank_user.set_captcha()
    send_mail(bank_user.email, '绑定验证码', 'email/bind_bank_user.html', user=bank_user, captcha=bank_user.captcha)

    # 保存待绑定信息
    shop_user.bank_user_id = bank_user.UserId
    db.session.commit()

    return jsonify({'msg': '验证码已发送到银行用户邮箱，请查收'}), 200


@web.route('/confirm_bind_bank_user', methods=['POST'])
@jwt_required()
def confirm_bind_bank_user():
    verify_jwt_in_request()
    claims = get_jwt()
    if claims.get('user_type') != 'shop':
        return jsonify({'msg': '需要外卖平台用户身份'}), 403

    user_id = get_jwt_identity()
    data = request.get_json()
    captcha = data.get('captcha')

    shop_user = ShopUser.query.get(user_id)
    bank_user = BankUser.query.get(shop_user.bank_user_id)
    if not bank_user:
        return jsonify({'msg': '银行用户不存在'}), 404

    if bank_user.verify_captcha(captcha):
        # 绑定成功
        db.session.commit()
        return jsonify({'msg': '绑定成功'}), 200
    else:
        return jsonify({'msg': '验证码错误或已过期'}), 400
