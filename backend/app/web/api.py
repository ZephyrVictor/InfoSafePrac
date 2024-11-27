# encoding=utf-8
__author__ = 'Zephyr369'
# app/web/api.py

from flask import Blueprint, jsonify
from flask import request
from app.utils.oauth2 import oauth_required

api_bp = Blueprint('api', __name__)

@api_bp.route('/api/user_info', methods=['GET'])
@oauth_required
def get_user_info():
    user = request.user
    return jsonify({
        'user_id': user.UserId,
        'nickname': user.nickname,
        'email': user.email,
        'bank_card_number': user.bank_card_number  # 假设有此字段
    }), 200
