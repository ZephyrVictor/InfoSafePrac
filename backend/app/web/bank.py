# encoding=utf-8
__author__ = 'Zephyr369'

# app/web/bank.py

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.models.User import User
from app.models.BankCard import BankCard
from app.libs.email import send_mail
from app import db
from . import web


# bank = Blueprint('bank', __name__)


@web.route('/apply_bank_card', methods=['POST'])
@jwt_required()
def apply_bank_card():
    """
    用户申请绑定银行卡
    """
    user_id = get_jwt_identity()
    # 得是银行用户
    user = User.query.get(user_id).filter_by(user_type="bank").first()

    if not user:
        return jsonify({'msg': '当前用户不存在'}), 403

    if not user.isExamined:
        return jsonify({'msg': '用户未经过审核，无法绑定银行卡'}), 403

    new_card = BankCard(user_id=user.UserId)
    new_card.set_captcha()

    send_mail(user.email, '绑定银行卡验证码', 'email/bind_bank_card.html', user=user, captcha=new_card.captcha)

    db.session.add(new_card)
    db.session.commit()

    return jsonify({'msg': '验证码已发送到您的邮箱，请查收', 'card_id': new_card.CardId}), 200


@web.route('/confirm_bank_card', methods=['POST'])
@jwt_required()
def confirm_bank_card():
    """
    用户确认绑定银行卡
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    card_id = data.get('card_id')
    captcha = data.get('captcha')

    bank_card = BankCard.query.filter_by(CardId=card_id, user_id=user_id).first()
    if not bank_card:
        return jsonify({'msg': '银行卡不存在'}), 404

    if bank_card.verify_captcha(captcha):
        bank_card.is_active = True
        db.session.commit()
        return jsonify({'msg': '银行卡绑定成功'}), 200
    else:
        return jsonify({'msg': '验证码错误或已过期'}), 400


@web.route('/deposit', methods=['POST'])
@jwt_required()
def deposit():
    """
    用户充值
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    card_id = data.get('card_id')
    amount = data.get('amount')
    captcha = data.get('captcha')

    bank_card = BankCard.query.filter_by(CardId=card_id, user_id=user_id, is_active=True).first()
    if not bank_card:
        return jsonify({'msg': '银行卡不存在或未激活'}), 400

    if not bank_card.verify_captcha(captcha):
        return jsonify({'msg': '验证码错误或已过期'}), 400

    if bank_card.deposit(amount):
        return jsonify({'msg': '充值成功', 'balance': bank_card.balance}), 200
    else:
        return jsonify({'msg': '充值失败'}), 400


@web.route('/withdraw', methods=['POST'])
@jwt_required()
def withdraw():
    """
    用户取钱
    """
    user_id = get_jwt_identity()
    data = request.get_json()
    card_id = data.get('card_id')
    amount = data.get('amount')
    captcha = data.get('captcha')

    bank_card = BankCard.query.filter_by(CardId=card_id, user_id=user_id, is_active=True).first()
    if not bank_card:
        return jsonify({'msg': '银行卡不存在或未激活'}), 404

    if not bank_card.verify_captcha(captcha):
        return jsonify({'msg': '验证码错误或已过期'}), 400

    if bank_card.withdraw(amount):
        return jsonify({'msg': '取款成功', 'balance': bank_card.balance}), 200
    else:
        return jsonify({'msg': '取款失败，余额不足'}), 400
