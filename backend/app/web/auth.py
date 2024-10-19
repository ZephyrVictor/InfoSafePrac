# encoding=utf-8
__author__ = 'Zephyr369'

import jwt
from flask import request, jsonify, current_app, Blueprint
from flask_login import logout_user
from flask_jwt_extended import jwt_required

from .. import logger
from ..forms.auth import EmailForm
from ..libs.captcha import CaptchaManager
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


# TODO: 这段代码写的重用不咋地 应当封装一下最好
@auth_bp.route("/bank/reset/password", methods=['POST'])
def bank_reset_password_request():
    """
    银行用户发送重置密码验证码请求
    """
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"msg": "请输入有效的邮箱地址"}), 400

    user = BankUser.query.filter_by(email=email).first()
    if user:
        captcha_manager = CaptchaManager(user)
        captcha_manager.generate_captcha()
        captcha_manager.send_captcha_email("重置您的密码验证码", 'email/reset_password.html')
        return jsonify({"msg": "重置密码验证码已发送，请查收"}), 200
    return jsonify({"msg": "用户不存在"}), 400


@auth_bp.route("/bank/reset/password", methods=['PUT'])
def bank_reset_password():
    """
    银行用户重置密码接口
    """
    data = request.get_json()
    email = data.get('email')
    captcha = data.get('captcha')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not all([email, captcha, new_password, confirm_password]):
        return jsonify({"msg": "所有字段都是必需的"}), 400

    if new_password != confirm_password:
        return jsonify({"msg": "两次输入的密码不一致"}), 400

    user = BankUser.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "用户不存在"}), 400

    captcha_manager = CaptchaManager(user)
    if captcha_manager.verify_captcha(captcha):
        if user.verify_password(new_password):
            return jsonify({"msg": "新密码不能与原密码相同"}), 400
        user.password = new_password
        db.session.commit()
        return jsonify({"msg": "密码重置成功"}), 200
    else:
        return jsonify({"msg": "验证码错误或已过期"}), 400


@auth_bp.route("/shop/reset/password", methods=['POST'])
def shop_reset_password_request():
    """
    外卖平台用户发送重置密码验证码请求
    """
    data = request.get_json()
    email = data.get('email')

    if not email:
        return jsonify({"msg": "请输入有效的邮箱地址"}), 400

    user = ShopUser.query.filter_by(email=email).first()
    if user:
        captcha_manager = CaptchaManager(user)
        captcha_manager.generate_captcha()
        captcha_manager.send_captcha_email("重置您的密码验证码", 'email/reset_password.html')
        return jsonify({"msg": "重置密码验证码已发送，请查收"}), 200
    return jsonify({"msg": "用户不存在"}), 400


@auth_bp.route("/shop/reset/password", methods=['PUT'])
def shop_reset_password():
    """
    外卖平台用户重置密码接口
    """
    data = request.get_json()
    email = data.get('email')
    captcha = data.get('captcha')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if not all([email, captcha, new_password, confirm_password]):
        return jsonify({"msg": "所有字段都是必需的"}), 400

    if new_password != confirm_password:
        return jsonify({"msg": "两次输入的密码不一致"}), 400

    user = ShopUser.query.filter_by(email=email).first()
    if not user:
        return jsonify({"msg": "用户不存在"}), 400

    captcha_manager = CaptchaManager(user)
    if captcha_manager.verify_captcha(captcha):
        if user.verify_password(new_password):
            return jsonify({"msg": "新密码不能与原密码相同"}), 400
        user.password = new_password
        db.session.commit()
        return jsonify({"msg": "密码重置成功"}), 200
    else:
        return jsonify({"msg": "验证码错误或已过期"}), 400


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
def shop_register():
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
def shop_login():
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
