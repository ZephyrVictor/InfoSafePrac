# encoding=utf-8
__author__ = 'Zephyr369'

import jwt
from flask import request, jsonify, current_app
from flask_login import logout_user

from . import web
from .. import logger
from ..forms.auth import EmailForm
from ..libs.email import send_mail
from ..models.User import User
from ..viewmodels.auth import do_register_form


@web.route("/register", methods=['POST'])
def register():
    """
        用户注册接口
        ---
        parameters:
          - name: data
            in: body
            required: true
            schema:
              type: object
              properties:
                nickname:
                  type: string
                  example: "用户昵称"
                email:
                  type: string
                  example: "user@example.com"
                password:
                  type: string
                  example: "userpassword"
                payPassword:
                  type: string
                  example: "paypassword"
                remember:
                  type: boolean
                  example: false
        responses:
          201:
            description: 注册成功
          400:
            description: 输入错误
          404:
            description: 用户已存在
        """
    data = request.get_json()
    result = do_register_form(data)
    return result


@web.route('/login', methods=['POST'])
def login():
    """
        用户登录接口
        ---
        parameters:
          - name: data
            in: body
            required: true
            schema:
              type: object
              properties:
                email:
                  type: string
                  example: "user@example.com"
                password:
                  type: string
                  example: "userpassword"
                remember:
                  type: boolean
                  example: false
        responses:
          200:
            description: 登录成功
          400:
            description: 输入错误
          404:
            description: 用户不存在
          401:
            description: 密码错误
        """
    # 获取请求数据
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    remember = data.get('remember', False)

    if not email or not password:
        return jsonify({"msg": "邮箱和密码是必需的"}), 400

    # 查找用户
    user = User.query.filter_by(email=email).first()
    if user is None:
        return jsonify({"msg": "用户不存在"}), 404

    # 验证密码
    if not user.verify_password(password):
        logger.info(f"用户{user.nickname}密码输入错误")
        return jsonify({"msg": "密码不正确"}), 401

    # 生成 JWT
    access_token = user.generate_jwt(user, remember)
    logger.info(f"用户{user.nickname}登录成功")
    # 设置 Cookie
    response = jsonify({"msg": "登录成功", "access_token": access_token})
    response.set_cookie('access_token', access_token, httponly=True,
                        max_age=60 * 60 * 24 * 7 if remember else 60 * 60 * 24)

    return response, 200


# 发送重置密码请求
@web.route("/reset/password", methods=['POST', 'GET'])
def forget_password_request():
    """
        发送重置密码请求
        ---
        parameters:
          - name: email
            in: formData
            type: string
            required: true
            description: 用户的邮箱地址
        responses:
          200:
            description: 重置密码邮件已发送，请查收
          400:
            description: 请输入有效的邮箱地址
        """
    form = EmailForm(request.form)
    if request.method == 'POST' and form.validate():
        account_email = form.email.data
        user = User.query.filter_by(email=account_email).first()
        if user:
            token = user.generate_token()  # 使用新的 token 生成方法
            send_mail(form.email.data, "重置您的密码", 'email/reset_password.html', user=user, token=token)
            return jsonify({"msg": "重置密码邮件已发送，请查收"}), 200
        return jsonify({"msg": "用户不存在"}), 400
    else:
        return jsonify({"msg": "请输入有效的邮箱地址"}), 400


@web.route("/reset/password/<token>", methods=['POST', 'GET'])
def forget_password(token):
    """
            重置密码接口
            ---
            parameters:
              - name: token
                in: path
                type: string
                required: true
                description: 重置密码的令牌
              - name: first_password
                in: formData
                type: string
                required: true
                description: 新密码
            responses:
              200:
                description: 密码重置成功
              400:
                description: 密码重置失败或输入错误
        """
    # 妈的急了 直接硬性校验了
    if request.method == 'POST':
        # 获取新密码
        data = request.json
        first_password = data.get('first_password')
        second_password = data.get('second_password')

        # 校验密码长度
        if not (6 <= len(first_password) <= 32):
            return jsonify({"errors": {"first_password": ["密码长度至少需要6到32个字符之间"]}}), 400

        # 校验两次密码是否一致
        if first_password != second_password:
            return jsonify({"errors": {"second_password": ["两次输入的密码不同"]}}), 400

        try:
            payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
            user = User.query.get(payload['UserId'])
            if user:
                # 确保新密码与原密码不同
                if user.verify_password(first_password):
                    return jsonify({"errors": {"first_password": ["新密码不能与原密码相同"]}}), 400

                # 重置密码
                if User.reset_password(user.UserId, first_password):
                    return jsonify({"msg": "密码重置成功"}), 200
                else:
                    return jsonify({"msg": "密码重置失败"}), 400
            else:
                return jsonify({"msg": "无效的用户"}), 400
        except jwt.ExpiredSignatureError:
            return jsonify({"msg": "令牌已过期"}), 400
        except jwt.InvalidTokenError:
            return jsonify({"msg": "无效的令牌"}), 400

    return jsonify({"msg": "无效的请求方法"}), 405


@web.route('/logout')
def logout():
    """
        退出登录接口
        ---
        responses:
          201:
            description: 退出登录成功
        """
    logout_user()
    return jsonify({"msg": "退出登录成功"}), 201
