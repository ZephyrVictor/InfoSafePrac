# encoding=utf-8
__author__ = 'Zephyr369'
# app/web/api.py

from flask import Blueprint, jsonify
from flask import request
from flask_jwt_extended import jwt_required, get_jwt_identity

from app.models.BankUser import BankUser
from app.utils.oauth2 import oauth_required

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/user_info', methods=['GET'])
@oauth_required
def get_user_info():
    user = request.user

    # 只筛选出已激活的银行卡
    bank_cards = [
        {'card_id': card.CardId, 'card_number': card.card_number}
        for card in user.bank_cards.filter_by(is_active=True).all()
    ]

    return jsonify({
        'user_id': user.UserId,
        'nickname': user.nickname,
        'email': user.email,
        'bank_cards': bank_cards
    }), 200
