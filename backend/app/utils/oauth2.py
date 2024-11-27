# encoding=utf-8
__author__ = 'Zephyr369'

# app/utils/oauth2.py

from functools import wraps
from flask import request, jsonify
from app.models.OAuthToken import OAuthToken
from app.models.BankUser import BankUser
from datetime import datetime


def oauth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 从请求头中提取 Bearer Token
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'missing_token'}), 401

        access_token = auth_header[7:]  # 去掉 'Bearer ' 前缀
        token = OAuthToken.query.filter_by(access_token=access_token, revoked=False).first()
        if not token:
            return jsonify({'error': 'invalid_token'}), 401

        if datetime.utcnow() > token.expires:
            return jsonify({'error': 'expired_token'}), 401

        # 使用访问令牌找到对应的用户
        user = BankUser.query.get(token.user_id)
        if not user:
            return jsonify({'error': 'user_not_found'}), 404

        # 将用户注入到请求对象中
        request.user = user

        return f(*args, **kwargs)

    return decorated_function
