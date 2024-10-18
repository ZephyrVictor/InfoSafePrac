# encoding=utf-8
__author__ = 'Zephyr369'

from flask import request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from . import web
from ..libs.email import send_mail
from ..models.User import User


@web.route('/bind_bank_user', methods=['POST'])
@jwt_required()
def bind_bank_user():
    """
    用户绑定银行卡
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    bank_user_email = data.get('bank_user_email')

    # 验证银行用户是否存在
    bank_user = User.query.filter_by(email=bank_user_email).first()
    if not bank_user:
        return jsonify({'msg': '银行用户不存在'}), 404

    # send capcha
    bank_user.set_captcha()
    send_mail(bank_user.email, '绑定银行卡验证码', 'email/bind_bank_card.html', user=bank_user, captcha=bank_user.captcha)
    return jsonify({'msg': '验证码已发送到银行用户邮箱，请查收'}), 200

@web.route('/confirm_bind_bank_user', methods=['POST'])
@jwt_required()
def confirm_bind_bank_user():
    """
    确认绑定银行用户
    :return:
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    bank_user_email = data.get('bank_user_email')
    captcha = data.get('captcha')

    bank_user = User.query.filter_by(email=bank_user_email).first()
    if not bank_user:
        return jsonify({'msg': '银行用户不存在'}), 404






