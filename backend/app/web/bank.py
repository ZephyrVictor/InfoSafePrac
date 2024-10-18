# encoding=utf-8
__author__ = 'Zephyr369'

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt

from app.models.BankCard import BankCard
from app.libs.email import send_mail
from app import db
from ..models.BankUser import BankUser

bank_bp = Blueprint('bank', __name__)

def bank_user_required(fn):
    def wrapper(*args, **kwargs):
        verify_jwt_in_request()
        claims = get_jwt()
        if claims.get('user_type') != 'bank':
            return jsonify({'msg': '需要银行用户身份'}), 403
        return fn(*args, **kwargs)
    wrapper.__name__ = fn.__name__
    return wrapper


@bank_bp.route('/apply_bank_card', methods=['POST'])
@jwt_required()
@bank_user_required
def apply_bank_card():
    """
    用户申请绑定银行卡
    ---
    tags:
      - Bank
    security:
      - Bearer: []
    responses:
      200:
        description: 验证码已发送到您的邮箱，请查收
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 验证码已发送到您的邮箱，请查收
            card_id:
              type: integer
              example: 1
      403:
        description: 用户未经过审核，无法绑定银行卡
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 用户未经过审核，无法绑定银行卡
    """
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    if not user.isExamined:
        return jsonify({'msg': '用户未经过审核，无法绑定银行卡'}), 403

    new_card = BankCard(user_id=user.UserId)
    new_card.set_captcha()

    send_mail(user.email, '绑定银行卡验证码', 'email/bind_bank_card.html', user=user, captcha=new_card.captcha)

    db.session.add(new_card)
    db.session.commit()

    return jsonify({'msg': '验证码已发送到您的邮箱，请查收', 'card_id': new_card.CardId}), 200


@bank_bp.route('/confirm_bank_card', methods=['POST'])
@jwt_required()
@bank_user_required
def confirm_bank_card():
    """
    用户确认绑定银行卡
    ---
    tags:
      - Bank
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - card_id
            - captcha
          properties:
            card_id:
              type: integer
              description: 银行卡ID
              example: 1
            captcha:
              type: string
              description: 验证码
              example: 123456
    responses:
      200:
        description: 银行卡绑定成功
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 银行卡绑定成功
      400:
        description: 验证码错误或已过期
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 验证码错误或已过期
      404:
        description: 银行卡不存在
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 银行卡不存在
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


@bank_bp.route('/deposit', methods=['POST'])
@jwt_required()
@bank_user_required
def deposit():
    """
    用户充值
    ---
    tags:
      - Bank
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - card_id
            - amount
            - captcha
          properties:
            card_id:
              type: integer
              description: 银行卡ID
              example: 1
            amount:
              type: number
              format: float
              description: 充值金额
              example: 100.50
            captcha:
              type: string
              description: 验证码
              example: 123456
    responses:
      200:
        description: 充值成功
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 充值成功
            balance:
              type: number
              format: float
              example: 200.75
      400:
        description: 充值失败或验证码错误
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 充值失败 或 验证码错误或已过期
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


@bank_bp.route('/withdraw', methods=['POST'])
@jwt_required()
@bank_user_required
def withdraw():
    """
    用户取钱
    ---
    tags:
      - Bank
    security:
      - Bearer: []
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - card_id
            - amount
            - captcha
          properties:
            card_id:
              type: integer
              description: 银行卡ID
              example: 1
            amount:
              type: number
              format: float
              description: 取款金额
              example: 50.25
            captcha:
              type: string
              description: 验证码
              example: 123456
    responses:
      200:
        description: 取款成功
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 取款成功
            balance:
              type: number
              format: float
              example: 150.50
      400:
        description: 取款失败或验证码错误
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 取款失败，余额不足 或 验证码错误或已过期
      404:
        description: 银行卡不存在或未激活
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 银行卡不存在或未激活
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
