# encoding=utf-8
__author__ = 'Zephyr369'

from flasgger import swag_from
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt

from app.models.BankCard import BankCard
from app.libs.email import send_mail
from app import db
from ..libs.captcha import CaptchaManager
from ..models.BankUser import BankUser
from ..utils import Logger

bank_bp = Blueprint('bank', __name__)


# 逻辑：
# 用户注册后，要经过管理员审核才有资格开卡
# 开卡的时候，会先生成一个银行卡，然后交到数据库里
# 用户经过验证码验证后银行卡才会激活 否则就是废卡

# 申请一张银行卡
@bank_bp.route('/apply_bank_card', methods=['POST'])
@jwt_required()
@swag_from('../docs/apply_bank_card.yml')
def apply_bank_card():
    user_id = get_jwt_identity()
    user = BankUser.query.get(user_id)

    if not user.isExamined:
        return jsonify({'msg': '用户未经过审核，无法申请'}), 403

    new_card = BankCard(user_id=user.UserId)
    db.session.add(new_card)
    db.session.commit()

    captcha_manager = CaptchaManager(user)
    captcha_manager.generate_captcha()
    captcha_manager.send_captcha_email('绑定银行卡验证码', 'email/bind_bank_card.html')

    return jsonify({'msg': '验证码已发送到您的邮箱，请查收', 'card_number': new_card.card_number}), 200


@bank_bp.route('/confirm_bank_card', methods=['POST'])
@jwt_required()
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
    card_number = data.get('card_number')
    captcha = data.get('captcha')

    user = BankUser.query.get(user_id)
    captcha_manager = CaptchaManager(user)
    # 先拿到银行卡
    # 应当用card_number来索引
    bank_card = BankCard.query.filter_by(card_number=card_number, user_id=user_id).first()
    if not bank_card:
        return jsonify({'msg': '银行卡不存在'}), 404

    if not captcha_manager.verify_captcha(captcha):
        # 如果银行卡存在， 而且验证码过期了 那就应该删除
        if bank_card:
            db.session.delete(bank_card)
            db.session.commit()  # 提交更改
        return jsonify({'msg': '验证码错误或已过期'}), 400
    bank_card.is_active = True
    db.session.commit()
    return jsonify({'msg': '银行卡激活成功'}), 200


@bank_bp.route('/deposit', methods=['POST'])
@jwt_required()
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

