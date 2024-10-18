# encoding=utf-8
__author__ = 'Zephyr369'

import jwt
from flask import request, jsonify, current_app, Blueprint
from flask_login import logout_user
from flask_jwt_extended import jwt_required

from .. import logger
from ..forms.auth import EmailForm
from ..libs.email import send_mail
from ..models.BankUser import BankUser
from ..models.ShopUser import ShopUser
# from ..models.User import User
from ..models.base import db

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/bank/register", methods=['POST'])
def bank_register():
    """
    银行用户注册接口
    ---
    tags:
      - Bank Auth
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - nickname
            - email
            - password
            - payPassword
          properties:
            nickname:
              type: string
              example: 用户昵称
            email:
              type: string
              example: user@example.com
            password:
              type: string
              example: userpassword
            payPassword:
              type: string
              example: paypassword
    responses:
      201:
        description: 注册成功
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 银行用户注册成功
      400:
        description: 输入错误或邮箱已被注册
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 所有字段都是必需的 或 该邮箱已被注册
    """
    data = request.get_json()
    nickname = data.get('nickname')
    email = data.get('email')
    password = data.get('password')
    payPassword = data.get('payPassword')

    if not all([nickname, email, password, payPassword]):
        return jsonify({'msg': '所有字段都是必需的'}), 400

    existing_user = BankUser.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'msg': '该邮箱已被注册'}), 400

    user = BankUser()
    user.set_attrs(data)
    db.session.add(user)
    db.session.commit()

    return jsonify({'msg': '银行用户注册成功'}), 201


@auth_bp.route('/bank/login', methods=['POST'])
def bank_login():
    """
    银行用户登录接口
    ---
    tags:
      - Bank Auth
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              example: user@example.com
            password:
              type: string
              example: userpassword
            remember:
              type: boolean
              example: false
    responses:
      200:
        description: 登录成功
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 登录成功
            access_token:
              type: string
              example: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
      400:
        description: 输入错误
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 邮箱和密码是必需的
      401:
        description: 密码错误
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 密码不正确
      404:
        description: 用户不存在
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 用户不存在
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    remember = data.get('remember', False)

    if not email or not password:
        return jsonify({"msg": "邮箱和密码是必需的"}), 400

    user = BankUser.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"msg": "用户不存在"}), 404

    if not user.verify_password(password):
        logger.info(f"银行用户{user.nickname}密码输入错误")
        return jsonify({"msg": "密码不正确"}), 401

    access_token = user.generate_jwt(user, remember)
    logger.info(f"银行用户{user.nickname}登录成功")
    response = jsonify({"msg": "登录成功", "access_token": access_token})
    response.set_cookie(
        'access_token',
        access_token,
        httponly=True,
        secure=True,
        samesite='Lax',
        max_age=60 * 60 * 24 * 7 if remember else 60 * 60 * 24
    )
    return response, 200

# TODO: 修改一下修改密码的逻辑
# @auth_bp.route("/reset/password", methods=['POST'])
# def forget_password_request():
#     """
#     发送重置密码请求
#     ---
#     tags:
#       - Auth
#     parameters:
#       - name: body
#         in: body
#         required: true
#         schema:
#           type: object
#           required:
#             - email
#           properties:
#             email:
#               type: string
#               description: 用户的邮箱地址
#               example: user@example.com
#     responses:
#       200:
#         description: 重置密码邮件已发送，请查收
#         schema:
#           type: object
#           properties:
#             msg:
#               type: string
#               example: 重置密码邮件已发送，请查收
#       400:
#         description: 输入错误或用户不存在
#         schema:
#           type: object
#           properties:
#             msg:
#               type: string
#               example: 请输入有效的邮箱地址 或 用户不存在
#     """
#     data = request.get_json()
#     email = data.get('email')
#
#     if not email:
#         return jsonify({"msg": "请输入有效的邮箱地址"}), 400
#
#     user = User.query.filter_by(email=email).first()
#     if user:
#         token = user.generate_token()
#         send_mail(email, "重置您的密码", 'email/reset_password.html', user=user, token=token)
#         return jsonify({"msg": "重置密码邮件已发送，请查收"}), 200
#     return jsonify({"msg": "用户不存在"}), 400
#
#
# @auth_bp.route("/reset/password/<token>", methods=['POST'])
# def forget_password(token):
#     """
#     重置密码接口
#     ---
#     tags:
#       - Auth
#     parameters:
#       - name: token
#         in: path
#         type: string
#         required: true
#         description: 重置密码的令牌
#       - name: body
#         in: body
#         required: true
#         schema:
#           type: object
#           required:
#             - first_password
#             - second_password
#           properties:
#             first_password:
#               type: string
#               description: 新密码
#               example: newpassword123
#             second_password:
#               type: string
#               description: 确认新密码
#               example: newpassword123
#     responses:
#       201:
#         description: 密码重置成功
#         schema:
#           type: object
#           properties:
#             msg:
#               type: string
#               example: 密码重置成功
#       400:
#         description: 密码重置失败或输入错误
#         schema:
#           type: object
#           properties:
#             msg:
#               type: string
#               example: 密码重置失败 或 输入错误信息
#       405:
#         description: 无效的请求方法
#         schema:
#           type: object
#           properties:
#             msg:
#               type: string
#               example: 无效的请求方法
#     """
#     if request.method == 'POST':
#         data = request.json
#         first_password = data.get('first_password')
#         second_password = data.get('second_password')
#
#         if not (6 <= len(first_password) <= 32):
#             return jsonify({"errors": {"first_password": ["密码长度至少需要6到32个字符之间"]}}), 400
#
#         if first_password != second_password:
#             return jsonify({"errors": {"second_password": ["两次输入的密码不同"]}}), 400
#
#         try:
#             payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
#             user = User.query.get(payload['UserId'])
#             if user:
#                 if user.verify_password(first_password):
#                     return jsonify({"errors": {"first_password": ["新密码不能与原密码相同"]}}), 400
#
#                 if User.reset_password(user.UserId, first_password):
#                     return jsonify({"msg": "密码重置成功"}), 201
#                 else:
#                     return jsonify({"msg": "密码重置失败"}), 400
#             else:
#                 return jsonify({"msg": "无效的用户"}), 400
#         except jwt.ExpiredSignatureError:
#             return jsonify({"msg": "令牌已过期"}), 400
#         except jwt.InvalidTokenError:
#             return jsonify({"msg": "无效的令牌"}), 400
#
#     return jsonify({"msg": "无效的请求方法"}), 405


@auth_bp.route('/logout')
@jwt_required()
def logout():
    """
    退出登录接口
    ---
    tags:
      - Auth
    security:
      - Bearer: []
    responses:
      201:
        description: 退出登录成功
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 退出登录成功
    """
    logout_user()
    return jsonify({"msg": "退出登录成功"}), 201


@auth_bp.route("/register", methods=['POST'])
def register():
    """
    外卖平台用户注册接口
    ---
    tags:
      - Shop Auth
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - nickname
            - email
            - password
          properties:
            nickname:
              type: string
              example: 用户昵称
            email:
              type: string
              example: user@example.com
            password:
              type: string
              example: userpassword
    responses:
      201:
        description: 注册成功
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 注册成功
      400:
        description: 输入错误或邮箱已被注册
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 所有字段都是必需的 或 该邮箱已被注册
    """
    data = request.get_json()
    nickname = data.get('nickname')
    email = data.get('email')
    password = data.get('password')

    if not all([nickname, email, password]):
        return jsonify({'msg': '所有字段都是必需的'}), 400

    existing_user = ShopUser.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'msg': '该邮箱已被注册'}), 400

    shop_user = ShopUser()
    shop_user.set_attrs(data)
    db.session.add(shop_user)
    db.session.commit()

    return jsonify({'msg': '注册成功'}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """
    外卖平台用户登录接口
    ---
    tags:
      - Shop Auth
    parameters:
      - name: body
        in: body
        required: true
        schema:
          type: object
          required:
            - email
            - password
          properties:
            email:
              type: string
              example: user@example.com
            password:
              type: string
              example: userpassword
            remember:
              type: boolean
              example: false
    responses:
      200:
        description: 登录成功
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 登录成功
            access_token:
              type: string
              example: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...
      400:
        description: 输入错误
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 邮箱和密码是必需的
      401:
        description: 密码错误
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 密码不正确
      404:
        description: 用户不存在
        schema:
          type: object
          properties:
            msg:
              type: string
              example: 用户不存在
    """
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    remember = data.get('remember', False)

    if not email or not password:
        return jsonify({"msg": "邮箱和密码是必需的"}), 400

    user = ShopUser.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"msg": "用户不存在"}), 404

    if not user.verify_password(password):
        logger.info(f"用户{user.nickname}密码输入错误")
        return jsonify({"msg": "密码不正确"}), 401

    access_token = user.generate_jwt(user, remember)
    logger.info(f"用户{user.nickname}登录成功")
    response = jsonify({"msg": "登录成功", "access_token": access_token})
    response.set_cookie(
        'access_token',
        access_token,
        httponly=True,
        secure=True,
        samesite='Lax',
        max_age=60 * 60 * 24 * 7 if remember else 60 * 60 * 24
    )
    return response, 200
